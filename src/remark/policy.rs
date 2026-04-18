//! REMARK admission-policy enforcement.
//!
//! Traces to: [SPEC §16.1](../../docs/resources/SPEC.md).
//!
//! # Role
//!
//! The consensus layer hands us:
//!
//!   - a `SpendBundle` whose individual `CoinSpend`s may carry
//!     evidence payloads inside REMARK conditions,
//!   - a map `coin_id → REMARK-payload-bytes…` produced by running
//!     each spend's puzzle against its solution.
//!
//! This module enforces the rule that ties the two together:
//! every parsed evidence's DSL-103 puzzle hash MUST equal the
//! spending coin's `puzzle_hash`. That equality is what forces
//! the reporter to commit to the EXACT evidence bytes at coin
//! creation time — without it an attacker could laundered a
//! different evidence through a coin that never committed to it.
//!
//! Foreign REMARK payloads (not evidence) are silently ignored by
//! the DSL-102 parser, so unrelated app REMARKs sharing the block
//! never trip this check.
//!
//! # Scope (incremental)
//!
//! First commit lands DSL-104 (matching-coin admission). DSL-105
//! extends the mismatch path with the `AdmissionPuzzleHashMismatch`
//! error. DSL-106..109 add mempool policy on top.

use std::collections::{HashMap, HashSet};

use chia_protocol::SpendBundle;
use dig_protocol::Bytes32;

use dig_epoch::SLASH_LOOKBACK_EPOCHS;

use crate::appeal::envelope::{SlashAppeal, SlashAppealPayload};
use crate::error::SlashingError;
use crate::evidence::{SlashingEvidence, SlashingEvidencePayload};
use crate::pending::PendingSlashStatus;
use crate::remark::appeal_wire::{
    parse_slash_appeals_from_conditions, slash_appeal_remark_puzzle_hash_v1,
};
use crate::remark::evidence_wire::{
    parse_slashing_evidence_from_conditions, slashing_evidence_remark_puzzle_hash_v1,
};
use crate::{
    MAX_APPEAL_PAYLOAD_BYTES, MAX_APPEALS_PER_BLOCK, MAX_SLASH_PROPOSAL_PAYLOAD_BYTES,
    MAX_SLASH_PROPOSALS_PER_BLOCK, SLASH_APPEAL_WINDOW_EPOCHS,
};

/// Enforce the DSL-104 admission predicate over every evidence
/// parsed from a spend bundle's REMARK conditions.
///
/// # Semantics
///
/// For each `CoinSpend` in `bundle.coin_spends`:
///
///   1. Look up the coin's REMARK payload list in `conditions`.
///      A spend absent from the map contributes zero payloads
///      (the consensus layer only populates entries for spends
///      that emitted conditions).
///   2. Run DSL-102's parser over the payload list — foreign /
///      malformed payloads drop silently and do not participate
///      in the check.
///   3. For every parsed evidence, derive the DSL-103 puzzle hash
///      and compare with `spend.coin.puzzle_hash`. Mismatch →
///      `AdmissionPuzzleHashMismatch`.
///
/// A bundle with zero evidences across all spends returns
/// `Ok(())` — admission is per-evidence, not per-spend, so
/// vacuously-true cases MUST admit.
///
/// # Errors
///
/// - [`SlashingError::AdmissionPuzzleHashMismatch`] — one of the
///   parsed evidences derived a puzzle hash that does not equal
///   the spent coin's `puzzle_hash`.
/// - [`SlashingError::InvalidSlashingEvidence`] — the DSL-103
///   hash derivation itself failed (extremely rare — serde /
///   CLVM allocator issue).
pub fn enforce_slashing_evidence_remark_admission(
    bundle: &SpendBundle,
    conditions: &HashMap<Bytes32, Vec<Vec<u8>>>,
) -> Result<(), SlashingError> {
    for spend in bundle.coin_spends.iter() {
        let coin_id = spend.coin.coin_id();
        // unwrap_or(&empty) — a spend with no REMARK entry is a
        // "no evidences" case, not a rejection. Matches the spec
        // pseudocode's `.unwrap_or_default()`.
        let empty = Vec::new();
        let payloads = conditions.get(&coin_id).unwrap_or(&empty);

        for ev in parse_slashing_evidence_from_conditions(payloads) {
            let expected = slashing_evidence_remark_puzzle_hash_v1(&ev)?;
            if spend.coin.puzzle_hash != expected {
                return Err(SlashingError::AdmissionPuzzleHashMismatch {
                    expected,
                    got: spend.coin.puzzle_hash,
                });
            }
        }
    }
    Ok(())
}

/// Enforce the DSL-106 mempool policy over every evidence parsed
/// from a spend bundle's REMARK conditions. Currently one rule:
///
///   - `evidence.epoch + SLASH_LOOKBACK_EPOCHS < current_epoch`
///     → reject with `SlashingError::OffenseTooOld`.
///
/// Mempool policy runs BEFORE DSL-104 admission as a cheap filter:
/// stale evidence can never be slashed regardless of verifier
/// outcome, so there is no point paying BLS-verification cost on
/// a payload that the downstream verifier (DSL-011) would reject
/// anyway.
///
/// # Underflow guard
///
/// The predicate uses addition on the LHS so it cannot underflow
/// when `current_epoch < SLASH_LOOKBACK_EPOCHS` (early network
/// boot / genesis). At genesis every epoch-0 evidence is
/// admissible.
///
/// # Boundary
///
/// `ev.epoch == current_epoch - SLASH_LOOKBACK_EPOCHS` (when the
/// subtraction is well-defined) is admissible — the comparison is
/// strict `<`, not `<=`.
///
/// # Errors
///
/// - [`SlashingError::OffenseTooOld`] — first expired evidence
///   in iteration order. Iteration halts at the first failure so
///   one stale payload does not amplify verifier work.
pub fn enforce_slashing_evidence_mempool_policy(
    bundle: &SpendBundle,
    conditions: &HashMap<Bytes32, Vec<Vec<u8>>>,
    current_epoch: u64,
) -> Result<(), SlashingError> {
    for spend in bundle.coin_spends.iter() {
        let coin_id = spend.coin.coin_id();
        let empty = Vec::new();
        let payloads = conditions.get(&coin_id).unwrap_or(&empty);

        for ev in parse_slashing_evidence_from_conditions(payloads) {
            if ev.epoch + SLASH_LOOKBACK_EPOCHS < current_epoch {
                return Err(SlashingError::OffenseTooOld {
                    offense_epoch: ev.epoch,
                    current_epoch,
                });
            }
        }
    }
    Ok(())
}

/// Enforce the DSL-107 mempool-level dedup policy across
/// `pending_evidence` (already in the mempool) and
/// `incoming_evidence` (new REMARKs being admitted in this pass).
///
/// Fingerprint = `serde_json::to_vec(&ev)` bytes — the SAME bytes
/// that rode on the wire via DSL-102, so a byte-identical REMARK
/// payload collides without deriving any additional hash.
///
/// # Semantics
///
///   1. Every `pending_evidence` entry's fingerprint is inserted
///      into a `HashSet`.
///   2. For each `incoming_evidence` entry: compute its
///      fingerprint; if `HashSet::insert` returns `false`
///      (meaning the fingerprint was already present, from either
///      pending or a prior incoming), return
///      `SlashingError::DuplicateEvidence`.
///
/// Distinct from [`SlashingError::AlreadySlashed`] (DSL-026)
/// which operates at the manager layer on `evidence.hash()`;
/// DSL-107 is strictly upstream and catches spam BEFORE it
/// reaches any validator / bond machinery.
///
/// # Errors
///
/// - [`SlashingError::DuplicateEvidence`] — first collision
///   encountered. Iteration short-circuits so a single rogue
///   payload does not amplify policy cost.
/// - [`SlashingError::InvalidSlashingEvidence`] wrapping the
///   `serde_json` error if a payload fails to serialize. In
///   practice `SlashingEvidence` is infallibly serialisable;
///   the error path exists for completeness.
pub fn enforce_slashing_evidence_mempool_dedup_policy(
    pending_evidence: &[SlashingEvidence],
    incoming_evidence: &[SlashingEvidence],
) -> Result<(), SlashingError> {
    let mut seen: HashSet<Vec<u8>> =
        HashSet::with_capacity(pending_evidence.len() + incoming_evidence.len());

    for ev in pending_evidence {
        let fp = serde_json::to_vec(ev)
            .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("dedup fp: {e}")))?;
        seen.insert(fp);
    }
    for ev in incoming_evidence {
        let fp = serde_json::to_vec(ev)
            .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("dedup fp: {e}")))?;
        if !seen.insert(fp) {
            return Err(SlashingError::DuplicateEvidence);
        }
    }
    Ok(())
}

/// Enforce the DSL-108 block-level cap on evidence admissions.
///
/// Rejects when `evidences.len() > MAX_SLASH_PROPOSALS_PER_BLOCK`.
/// Boundary case (`== MAX`) admits — the cap is inclusive of
/// exactly-at-limit blocks.
///
/// # Why a hard cap
///
/// Each admitted evidence triggers DSL-103 puzzle-hash
/// derivation at admission time and the full verifier pipeline
/// (BLS + state lookup) at the slashing-manager layer
/// downstream. An unbounded REMARK list would let a single
/// block blow up validation time to DoS the chain. SPEC §2.8
/// fixes the cap at 64 so per-block cost stays predictable
/// regardless of mempool pressure.
///
/// # Errors
///
/// - [`SlashingError::BlockCapExceeded`] — carries the observed
///   `actual` count and the `MAX_SLASH_PROPOSALS_PER_BLOCK`
///   `limit`. Mirrored by DSL-119 on the appeal side with the
///   same variant but `MAX_APPEALS_PER_BLOCK` as the limit.
pub fn enforce_block_level_slashing_caps(
    evidences: &[SlashingEvidence],
) -> Result<(), SlashingError> {
    if evidences.len() > MAX_SLASH_PROPOSALS_PER_BLOCK {
        return Err(SlashingError::BlockCapExceeded {
            actual: evidences.len(),
            limit: MAX_SLASH_PROPOSALS_PER_BLOCK,
        });
    }
    Ok(())
}

/// Enforce the DSL-109 per-payload size cap.
///
/// Rejects any evidence whose `serde_json::to_vec` length
/// exceeds `MAX_SLASH_PROPOSAL_PAYLOAD_BYTES` (65_536).
///
/// Complements DSL-108 (count cap): DSL-108 bounds the NUMBER of
/// evidences per block; DSL-109 bounds the BYTES of each one.
/// Together they bound the total admission budget at
/// `MAX_SLASH_PROPOSALS_PER_BLOCK × MAX_SLASH_PROPOSAL_PAYLOAD_BYTES`
/// = 64 × 65_536 = 4 MiB worth of REMARK bytes per block,
/// which is the hard upper envelope on slashing-payload
/// bandwidth.
///
/// # Errors
///
/// - [`SlashingError::EvidencePayloadTooLarge`] — the first
///   oversize evidence in iteration order. Short-circuits; later
///   evidences in the batch are NOT checked.
/// - [`SlashingError::InvalidSlashingEvidence`] wrapping the
///   `serde_json` error if serialisation fails (infallible in
///   practice).
pub fn enforce_slashing_evidence_payload_cap(
    evidences: &[SlashingEvidence],
) -> Result<(), SlashingError> {
    for ev in evidences {
        let len = serde_json::to_vec(ev)
            .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("payload len: {e}")))?
            .len();
        if len > MAX_SLASH_PROPOSAL_PAYLOAD_BYTES {
            return Err(SlashingError::EvidencePayloadTooLarge {
                actual: len,
                limit: MAX_SLASH_PROPOSAL_PAYLOAD_BYTES,
            });
        }
    }
    Ok(())
}

/// Enforce the DSL-112 admission predicate over every appeal
/// parsed from a spend bundle's REMARK conditions.
///
/// Appeal-side analogue of
/// [`enforce_slashing_evidence_remark_admission`]: for each
/// `CoinSpend` look up its REMARK payloads, parse via DSL-110,
/// derive DSL-111 puzzle hash, compare with `coin.puzzle_hash`.
/// Mismatch → `AdmissionPuzzleHashMismatch` (shared variant;
/// DSL-113 exercises the fail path).
///
/// Bundle with zero appeals admits vacuously.
///
/// # Errors
///
/// - [`SlashingError::AdmissionPuzzleHashMismatch`] — first
///   mismatch. Iteration halts.
/// - [`SlashingError::InvalidSlashingEvidence`] — DSL-111 hash
///   derivation failure (extremely rare).
pub fn enforce_slash_appeal_remark_admission(
    bundle: &SpendBundle,
    conditions: &HashMap<Bytes32, Vec<Vec<u8>>>,
) -> Result<(), SlashingError> {
    for spend in bundle.coin_spends.iter() {
        let coin_id = spend.coin.coin_id();
        let empty = Vec::new();
        let payloads = conditions.get(&coin_id).unwrap_or(&empty);

        for ap in parse_slash_appeals_from_conditions(payloads) {
            let expected = slash_appeal_remark_puzzle_hash_v1(&ap)?;
            if spend.coin.puzzle_hash != expected {
                return Err(SlashingError::AdmissionPuzzleHashMismatch {
                    expected,
                    got: spend.coin.puzzle_hash,
                });
            }
        }
    }
    Ok(())
}

/// Enforce the DSL-114 mempool-level "appeal must reference a
/// known pending slash" rule.
///
/// Mempool admission runs before the slashing-manager's own
/// DSL-055 `UnknownEvidence` check. Catching the stale-target
/// case here avoids pointless bond-lock / BLS work on a payload
/// the manager would reject anyway.
///
/// # Errors
///
/// - [`SlashingError::UnknownEvidence`] carrying a lowercase-hex
///   rendering of the appeal's `evidence_hash` (matches the
///   DSL-055 diagnostic string for log-aggregator grep-friendly
///   pattern matching). Short-circuits on first miss.
pub fn enforce_slash_appeal_mempool_policy(
    appeals: &[SlashAppeal],
    pending_slashes: &std::collections::HashSet<Bytes32>,
) -> Result<(), SlashingError> {
    for ap in appeals {
        if !pending_slashes.contains(&ap.evidence_hash) {
            return Err(SlashingError::UnknownEvidence(hex_encode_lower(
                ap.evidence_hash.as_ref(),
            )));
        }
    }
    Ok(())
}

/// Enforce the DSL-115 appeal-window mempool policy.
///
/// For each appeal, look up its target pending slash's
/// `submitted_at_epoch` via `submitted_at` (map of `evidence_hash
/// → submitted_at`). If the map does NOT contain the entry, the
/// appeal is out of scope for this check — DSL-114
/// `enforce_slash_appeal_mempool_policy` handles unknown-hash
/// rejection separately.
///
/// Window predicate (inclusive on both ends):
///
/// ```text
/// appeal.filed_epoch <= submitted_at + SLASH_APPEAL_WINDOW_EPOCHS
/// ```
///
/// Strictly greater → reject. Matches DSL-056 manager-level
/// check byte-for-byte so the mempool and manager agree on the
/// boundary.
///
/// # Errors
///
/// - [`SlashingError::AppealWindowExpired`] carrying the
///   `submitted_at` epoch, the `window` constant, and the
///   appeal's `filed_epoch` as `current`. Mirrors the DSL-056
///   variant for unified diagnostics. Short-circuits on first
///   expired appeal.
pub fn enforce_slash_appeal_window_policy(
    appeals: &[SlashAppeal],
    submitted_at: &HashMap<Bytes32, u64>,
) -> Result<(), SlashingError> {
    for ap in appeals {
        if let Some(&submitted) = submitted_at.get(&ap.evidence_hash)
            && ap.filed_epoch > submitted + SLASH_APPEAL_WINDOW_EPOCHS
        {
            return Err(SlashingError::AppealWindowExpired {
                submitted_at: submitted,
                window: SLASH_APPEAL_WINDOW_EPOCHS,
                current: ap.filed_epoch,
            });
        }
    }
    Ok(())
}

/// Enforce the DSL-116 appeal terminal-status mempool policy.
///
/// Rejects any appeal whose target pending slash is in a terminal
/// status (`Finalised` or `Reverted`). Non-terminal statuses
/// (`Accepted`, `ChallengeOpen`) admit. Appeals whose hash is not
/// in the status lookup skip — DSL-114 owns that rejection.
///
/// # Errors
///
/// - [`SlashingError::SlashAlreadyFinalised`] (DSL-061 variant)
///   for `Finalised` targets.
/// - [`SlashingError::SlashAlreadyReverted`] (DSL-060 variant)
///   for `Reverted` targets.
///
/// Reuses the manager-layer variants rather than introducing a
/// combined `AppealForFinalisedSlash(hex)` — keeps the error
/// surface narrow and lets callers distinguish the two cases
/// downstream without string-matching.
pub fn enforce_slash_appeal_terminal_status_policy(
    appeals: &[SlashAppeal],
    status_by_hash: &HashMap<Bytes32, PendingSlashStatus>,
) -> Result<(), SlashingError> {
    for ap in appeals {
        match status_by_hash.get(&ap.evidence_hash) {
            Some(PendingSlashStatus::Finalised { .. }) => {
                return Err(SlashingError::SlashAlreadyFinalised);
            }
            Some(PendingSlashStatus::Reverted { .. }) => {
                return Err(SlashingError::SlashAlreadyReverted);
            }
            // Accepted / ChallengeOpen are still open for appeal;
            // absent entries are out of scope (DSL-114 handles).
            _ => {}
        }
    }
    Ok(())
}

/// Enforce the DSL-117 appeal-variant mempool policy.
///
/// Rejects any appeal whose payload variant disagrees with the
/// pending evidence's payload variant:
///
///   - Appeal::Proposer     ↔ Evidence::Proposer
///   - Appeal::Attester     ↔ Evidence::Attester
///   - Appeal::InvalidBlock ↔ Evidence::InvalidBlock
///
/// Any cross-variant pairing is an `AppealVariantMismatch` per
/// DSL-057 manager parity. Appeals whose hash is absent from the
/// evidence-variant lookup skip — DSL-114 owns that rejection.
///
/// # Errors
///
/// - [`SlashingError::AppealVariantMismatch`] — first mismatch
///   encountered. Short-circuits.
pub fn enforce_slash_appeal_variant_policy(
    appeals: &[SlashAppeal],
    evidence_payload_by_hash: &HashMap<Bytes32, SlashingEvidencePayload>,
) -> Result<(), SlashingError> {
    for ap in appeals {
        let Some(ev_payload) = evidence_payload_by_hash.get(&ap.evidence_hash) else {
            // Unknown hash: not this function's job. Skip.
            continue;
        };
        let ok = matches!(
            (&ap.payload, ev_payload),
            (
                SlashAppealPayload::Proposer(_),
                SlashingEvidencePayload::Proposer(_),
            ) | (
                SlashAppealPayload::Attester(_),
                SlashingEvidencePayload::Attester(_),
            ) | (
                SlashAppealPayload::InvalidBlock(_),
                SlashingEvidencePayload::InvalidBlock(_),
            )
        );
        if !ok {
            return Err(SlashingError::AppealVariantMismatch);
        }
    }
    Ok(())
}

/// Enforce the DSL-118 appeal mempool-level dedup policy
/// across `pending_appeals` (already in mempool) and
/// `incoming_appeals` (new REMARKs admitted this pass).
///
/// Appeal-side analogue of DSL-107. Fingerprint =
/// `serde_json::to_vec(&appeal)` bytes — byte-identical payloads
/// collide without re-deriving any hash. First collision
/// (pending↔incoming or within incoming) → reject. Separate from
/// DSL-058 manager-level `DuplicateAppeal` check (which operates
/// on the bincode appeal hash inside `PendingSlash::appeal_history`);
/// this runs strictly upstream.
///
/// # Errors
///
/// - [`SlashingError::DuplicateAppeal`] — first collision.
///   Short-circuits.
/// - [`SlashingError::InvalidSlashingEvidence`] wrapping the
///   `serde_json` error on serialisation failure (infallible in
///   practice).
pub fn enforce_slash_appeal_mempool_dedup_policy(
    pending_appeals: &[SlashAppeal],
    incoming_appeals: &[SlashAppeal],
) -> Result<(), SlashingError> {
    let mut seen: HashSet<Vec<u8>> =
        HashSet::with_capacity(pending_appeals.len() + incoming_appeals.len());

    for ap in pending_appeals {
        let fp = serde_json::to_vec(ap)
            .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("appeal dedup fp: {e}")))?;
        seen.insert(fp);
    }
    for ap in incoming_appeals {
        let fp = serde_json::to_vec(ap)
            .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("appeal dedup fp: {e}")))?;
        if !seen.insert(fp) {
            return Err(SlashingError::DuplicateAppeal);
        }
    }
    Ok(())
}

/// Enforce the DSL-119 block-level cap on appeal admissions.
///
/// Appeal-side analogue of DSL-108 `enforce_block_level_slashing_caps`.
/// Rejects when `appeals.len() > MAX_APPEALS_PER_BLOCK`.
/// Boundary (`== MAX`) admits via strict `>`.
///
/// Shares the `BlockCapExceeded` variant with DSL-108; the
/// distinction at the call site comes from the `limit` field
/// (which carries `MAX_APPEALS_PER_BLOCK` here vs
/// `MAX_SLASH_PROPOSALS_PER_BLOCK` there).
pub fn enforce_block_level_appeal_caps(appeals: &[SlashAppeal]) -> Result<(), SlashingError> {
    if appeals.len() > MAX_APPEALS_PER_BLOCK {
        return Err(SlashingError::BlockCapExceeded {
            actual: appeals.len(),
            limit: MAX_APPEALS_PER_BLOCK,
        });
    }
    Ok(())
}

/// Enforce the DSL-120 per-payload size cap on appeals.
///
/// Rejects any appeal whose `serde_json::to_vec` length exceeds
/// `MAX_APPEAL_PAYLOAD_BYTES` (131_072 — 2x the evidence cap
/// because appeal witnesses carry full block bodies for
/// invalid-block oracle re-execution).
///
/// Appeal-side analogue of DSL-109, reusing the existing
/// `SlashingError::AppealPayloadTooLarge` variant (DSL-063) for
/// a unified mempool + manager-layer error surface.
///
/// # Errors
///
/// - [`SlashingError::AppealPayloadTooLarge`] — first oversize
///   appeal in iteration order. Short-circuits.
/// - [`SlashingError::InvalidSlashingEvidence`] wrapping the
///   serde_json error on serialisation failure (infallible in
///   practice).
pub fn enforce_slash_appeal_payload_cap(appeals: &[SlashAppeal]) -> Result<(), SlashingError> {
    for ap in appeals {
        let len = serde_json::to_vec(ap)
            .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("appeal len: {e}")))?
            .len();
        if len > MAX_APPEAL_PAYLOAD_BYTES {
            return Err(SlashingError::AppealPayloadTooLarge {
                actual: len,
                limit: MAX_APPEAL_PAYLOAD_BYTES,
            });
        }
    }
    Ok(())
}

/// Lowercase-hex encode without the `0x` prefix. Used by DSL-114
/// and future DSL-116..118 appeal-mempool errors that carry hex
/// diagnostic strings. Mirrors the DSL-055 manager-side format
/// so log aggregators see identical string shapes from either
/// layer.
fn hex_encode_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
