//! Block-level admission dispatcher.
//!
//! Traces to: [SPEC §16.5](../../../docs/resources/SPEC.md) + §7.3,
//! catalogue row
//! [DSL-168](../../../docs/requirements/domains/remark/specs/DSL-168.md).
//!
//! # Role
//!
//! Previously embedders had to manually compose the REMARK pipeline per block: `parse_slashing_evidence_from_conditions` + `parse_slash_appeals_from_conditions` + cap enforcement + `SlashingManager::submit_evidence` / `submit_appeal`. DSL-168 bundles that work into a single [`process_block_admissions`] call producing a [`BlockAdmissionReport`] with per-envelope outcomes.
//!
//! # Processing order
//!
//! Evidence envelopes are processed BEFORE appeal envelopes so a same-block appeal can reference a same-block evidence admission (DSL-055 UnknownEvidence check).
//!
//! # Error handling
//!
//! Per-envelope failures populate the rejected vecs without aborting the block — a block with one bad evidence and ten good ones still admits ten. Block-cap overflow truncates the excess envelopes and counts the drop; it does NOT reject the block outright.

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::bonds::BondEscrow;
use crate::constants::{MAX_APPEALS_PER_BLOCK, MAX_SLASH_PROPOSALS_PER_BLOCK};
use crate::error::SlashingError;
use crate::manager::{SlashingManager, SlashingResult};
use crate::remark::appeal_wire::parse_slash_appeals_from_conditions;
use crate::remark::evidence_wire::parse_slashing_evidence_from_conditions;
use crate::traits::{EffectiveBalanceView, ProposerView, RewardPayout, ValidatorView};

/// Aggregate report produced by [`process_block_admissions`].
///
/// Traces to [DSL-168](../../../docs/requirements/domains/remark/specs/DSL-168.md).
/// Carries both successful admissions AND per-envelope rejections
/// so embedders can emit per-block telemetry without re-running
/// the admission pipeline.
///
/// # Serde contract
///
/// `Serialize + Deserialize + PartialEq + Eq + Default` — wire
/// format for RPC / audit / snapshot. See DSL-168 acceptance row
/// 7.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BlockAdmissionReport {
    /// `(evidence_hash, SlashingResult)` per successfully admitted
    /// evidence envelope. Order matches block-relative REMARK
    /// order so audit log readers see deterministic sequencing.
    pub admitted_evidences: Vec<(Bytes32, SlashingResult)>,
    /// `(evidence_hash, SlashingError)` per evidence envelope that
    /// parsed cleanly but failed verification, bond lock, capacity,
    /// etc. The hash is `evidence.hash()` at parse time (DSL-002).
    pub rejected_evidences: Vec<(Bytes32, SlashingError)>,
    /// `appeal_hash` per successfully admitted appeal (DSL-159
    /// content-addressed identity).
    pub admitted_appeals: Vec<Bytes32>,
    /// `(appeal_hash, SlashingError)` per appeal envelope that
    /// parsed cleanly but failed admission.
    pub rejected_appeals: Vec<(Bytes32, SlashingError)>,
    /// Count of evidence envelopes dropped by block-cap
    /// enforcement (`evidences.len() > MAX_SLASH_PROPOSALS_PER_BLOCK`).
    /// Dropped envelopes are NOT passed to `submit_evidence`.
    pub cap_dropped_evidences: usize,
    /// Count of appeal envelopes dropped by block-cap enforcement
    /// (`appeals.len() > MAX_APPEALS_PER_BLOCK`). Dropped
    /// envelopes are NOT passed to `submit_appeal`.
    pub cap_dropped_appeals: usize,
}

/// Single-call block-level admission dispatcher.
///
/// Implements [DSL-168](../../../docs/requirements/domains/remark/specs/DSL-168.md).
/// Traces to SPEC §16.5, §7.3.
///
/// # Signature
///
/// `payloads: &[P]` where `P: AsRef<[u8]>` — the raw REMARK
/// condition bodies in block-relative order. Mirrors the shape of
/// `parse_slashing_evidence_from_conditions` / `parse_slash_appeals_from_conditions`
/// so embedders pass the same iterator twice is not needed —
/// each parse function filters by its magic prefix so the two
/// payload spaces are disjoint by construction.
///
/// # Pipeline
///
/// 1. Parse evidence envelopes via
///    `parse_slashing_evidence_from_conditions` (DSL-106).
/// 2. Parse appeal envelopes via
///    `parse_slash_appeals_from_conditions` (DSL-111).
/// 3. Truncate each vec to its block cap
///    (`MAX_SLASH_PROPOSALS_PER_BLOCK` / `MAX_APPEALS_PER_BLOCK`),
///    counting the drop in the report. Truncation rather than
///    hard-reject lets a block that over-packs one envelope kind
///    still admit the other kinds — matches the DSL-108/119 "cap
///    enforcer" semantics.
/// 4. Call `SlashingManager::submit_evidence` per surviving
///    evidence. Ok → `admitted_evidences`, Err →
///    `rejected_evidences`.
/// 5. Call `SlashingManager::submit_appeal` per surviving appeal.
///    Ok → `admitted_appeals`, Err → `rejected_appeals`.
///
/// # Ordering invariant
///
/// Evidence processing precedes appeal processing so an appeal
/// REMARK in the same block can reference an evidence REMARK
/// admitted earlier in the same call. DSL-055 UnknownEvidence
/// would otherwise fire on the cross-REMARK case.
///
/// # Determinism
///
/// Output ordering follows input ordering (REMARK index within
/// the block). Both parse functions preserve block order; the
/// dispatcher's `Vec::extend` walks them in order; errors are
/// recorded as they happen.
#[allow(clippy::too_many_arguments)]
pub fn process_block_admissions<P>(
    payloads: &[P],
    manager: &mut SlashingManager,
    validator_set: &mut dyn ValidatorView,
    effective_balances: &dyn EffectiveBalanceView,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
    proposer: &dyn ProposerView,
    network_id: &Bytes32,
) -> BlockAdmissionReport
where
    P: AsRef<[u8]>,
{
    let mut report = BlockAdmissionReport::default();

    // ── Step 1: parse evidence envelopes ──────────────────
    let mut evidences = parse_slashing_evidence_from_conditions(payloads);

    // ── Step 2: parse appeal envelopes ────────────────────
    let mut appeals = parse_slash_appeals_from_conditions(payloads);

    // ── Step 3: truncate to block caps ────────────────────
    if evidences.len() > MAX_SLASH_PROPOSALS_PER_BLOCK {
        report.cap_dropped_evidences = evidences.len() - MAX_SLASH_PROPOSALS_PER_BLOCK;
        evidences.truncate(MAX_SLASH_PROPOSALS_PER_BLOCK);
    }
    if appeals.len() > MAX_APPEALS_PER_BLOCK {
        report.cap_dropped_appeals = appeals.len() - MAX_APPEALS_PER_BLOCK;
        appeals.truncate(MAX_APPEALS_PER_BLOCK);
    }

    // ── Step 4: submit_evidence per envelope ──────────────
    // Evidence FIRST so a same-block appeal can reference a
    // same-block evidence via DSL-055 UnknownEvidence dedup.
    for ev in evidences {
        let evidence_hash = ev.hash();
        match manager.submit_evidence(
            ev,
            validator_set,
            effective_balances,
            bond_escrow,
            reward_payout,
            proposer,
            network_id,
        ) {
            Ok(result) => report.admitted_evidences.push((evidence_hash, result)),
            Err(err) => report.rejected_evidences.push((evidence_hash, err)),
        }
    }

    // ── Step 5: submit_appeal per envelope ────────────────
    for ap in appeals {
        let appeal_hash = ap.hash();
        match manager.submit_appeal(&ap, bond_escrow) {
            Ok(()) => report.admitted_appeals.push(appeal_hash),
            Err(err) => report.rejected_appeals.push((appeal_hash, err)),
        }
    }

    report
}
