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

use std::collections::HashMap;

use chia_protocol::SpendBundle;
use dig_protocol::Bytes32;

use crate::error::SlashingError;
use crate::remark::evidence_wire::{
    parse_slashing_evidence_from_conditions, slashing_evidence_remark_puzzle_hash_v1,
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
