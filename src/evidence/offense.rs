//! `OffenseType` — the four discrete slashable consensus offenses.
//!
//! Traces to: [SPEC.md §3.2](../../docs/resources/SPEC.md), catalogue row
//! [DSL-001](../../docs/requirements/domains/evidence/specs/DSL-001.md).
//!
//! Scope reminder: validator slashing only. DFSP / storage-provider slashing
//! is out of scope for this crate.
//!
//! # Design
//!
//! Four variants, three BPS floors (both attester variants share
//! `ATTESTATION_BASE_BPS`). The variant-to-BPS mapping is protocol law — it
//! lives in `base_penalty_bps()` and nowhere else in the codebase. Downstream
//! callers (the base-slash formula in `SlashingManager::submit_evidence`,
//! DSL-022; the reporter-penalty path in `AppealAdjudicator`, DSL-069) query
//! this method rather than hard-coding the BPS values.
//!
//! Serde + `Copy` + `Eq` + `Hash` derives keep the enum cheap to pass by
//! value through every downstream type (`SlashingEvidence`, `VerifiedEvidence`,
//! `AppealAdjudicationResult`).

use serde::{Deserialize, Serialize};

use crate::constants::{ATTESTATION_BASE_BPS, EQUIVOCATION_BASE_BPS, INVALID_BLOCK_BASE_BPS};

/// The four slashable consensus offenses.
///
/// Per [SPEC §3.2](../../docs/resources/SPEC.md), a validator can be slashed
/// for exactly one of these reasons on the DIG L2 blockchain. Inactivity
/// leak is NOT a slashable event — it is continuous accounting
/// (see `InactivityScoreTracker`, SPEC §9).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OffenseType {
    /// Validator signed two different blocks at the same slot.
    ///
    /// Evidence: two `SignedBlockHeader`s with matching `slot` and
    /// `proposer_index` but different message hashes, both with valid BLS
    /// signatures under the validator's pubkey. Verified by
    /// `verify_proposer_slashing` (DSL-013).
    ProposerEquivocation,

    /// Validator proposed a block that fails canonical validation.
    ///
    /// Evidence: one `SignedBlockHeader` plus a failure witness that the
    /// consensus layer (via `InvalidBlockOracle`, DSL-020) can reproduce.
    /// Verified by `verify_invalid_block` (DSL-018..020).
    InvalidBlock,

    /// Validator cast two attestations with the same target epoch but
    /// different data — "double vote" in Ethereum terminology.
    ///
    /// Evidence: two `IndexedAttestation`s with `a.data.target.epoch ==
    /// b.data.target.epoch && a.data != b.data`, both aggregate-signed by
    /// an overlapping committee. Verified by `verify_attester_slashing`
    /// double-vote predicate (DSL-014).
    AttesterDoubleVote,

    /// Validator's attestations form a surround vote — one's FFG span
    /// strictly contains the other's.
    ///
    /// Evidence: two `IndexedAttestation`s where
    /// `a.source.epoch < b.source.epoch && a.target.epoch > b.target.epoch`
    /// (or the mirror). Verified by `verify_attester_slashing` surround-vote
    /// predicate (DSL-015).
    AttesterSurroundVote,
}

impl OffenseType {
    /// Base penalty in basis points (10_000 = 100%) for this offense.
    ///
    /// Implements [DSL-001](../../docs/requirements/domains/evidence/specs/DSL-001.md).
    /// Traces to SPEC §2.1 (BPS constants) and SPEC §3.2 (mapping table).
    ///
    /// # Returns
    ///
    /// | Variant | Return value | Source constant |
    /// |---------|-------------|-----------------|
    /// | `ProposerEquivocation` | 500 | `EQUIVOCATION_BASE_BPS` |
    /// | `InvalidBlock` | 300 | `INVALID_BLOCK_BASE_BPS` |
    /// | `AttesterDoubleVote` | 100 | `ATTESTATION_BASE_BPS` |
    /// | `AttesterSurroundVote` | 100 | `ATTESTATION_BASE_BPS` |
    ///
    /// # Invariants
    ///
    /// - Return value `< MAX_PENALTY_BPS` (1_000) for every variant.
    /// - Return value `> 0` for every variant.
    ///
    /// Both invariants are enforced by `tests/dsl_001_offense_type_bps_mapping_test.rs`.
    ///
    /// # Downstream consumers
    ///
    /// - Base-slash formula in `SlashingManager::submit_evidence`
    ///   (DSL-022): `base_slash = max(eff_bal * base_penalty_bps() / 10_000,
    ///   eff_bal / MIN_SLASHING_PENALTY_QUOTIENT)`.
    /// - Reporter-penalty path in `AppealAdjudicator` (DSL-069): uses
    ///   `InvalidBlock` BPS as the false-evidence cost.
    ///
    /// # Why a method, not a `const`
    ///
    /// A method keeps the variant-to-BPS mapping a single source of truth
    /// that `match` exhaustiveness can defend. If a new `OffenseType` variant
    /// is ever added, the compiler refuses to build until `base_penalty_bps()`
    /// is updated — which is exactly the review point the protocol wants.
    pub const fn base_penalty_bps(&self) -> u16 {
        match self {
            Self::ProposerEquivocation => EQUIVOCATION_BASE_BPS,
            Self::InvalidBlock => INVALID_BLOCK_BASE_BPS,
            Self::AttesterDoubleVote | Self::AttesterSurroundVote => ATTESTATION_BASE_BPS,
        }
    }
}
