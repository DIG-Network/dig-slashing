//! Error types for the slashing crate.
//!
//! Traces to: [SPEC.md §17.1](../docs/resources/SPEC.md) (SlashingError).
//!
//! # Design
//!
//! A single `SlashingError` enum covers every verifier and state-machine
//! failure mode. Variants align 1:1 with the rows in SPEC §17.1 so
//! downstream callers (and adjudicators) can pattern-match without
//! stringly-typed discrimination.
//!
//! New variants land as their DSL-NNN requirements are implemented. Each
//! variant's docstring points at the requirement that introduced it.

use thiserror::Error;

/// Every failure mode `dig-slashing`'s verifiers, manager, and adjudicator
/// can return.
///
/// Per SPEC §17.1. Variants carry the minimum context needed to diagnose
/// the failure without leaking internal state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SlashingError {
    /// `IndexedAttestation` failed its cheap structural check
    /// (DSL-005): empty indices, non-ascending/duplicate indices,
    /// over-cap length, or wrong-width signature.
    ///
    /// Consumed by `verify_attester_slashing` (DSL-014/DSL-015) before
    /// any BLS work. Reason string describes the specific violation.
    #[error("invalid indexed attestation: {0}")]
    InvalidIndexedAttestation(String),

    /// Aggregate BLS verify returned `false` OR the signature bytes /
    /// pubkey set could not be decoded at all.
    ///
    /// Raised by `IndexedAttestation::verify_signature` (DSL-006) and
    /// by `verify_proposer_slashing` / `verify_invalid_block` (DSL-013 /
    /// DSL-018). Intentionally coarse: the security model does not
    /// distinguish "bad pubkey width", "missing validator index", or
    /// "cryptographic mismatch" — all three are equally invalid
    /// evidence and callers MUST reject the envelope uniformly.
    #[error("BLS signature verification failed")]
    BlsVerifyFailed,

    /// `AttesterSlashing` payload failed a structural / BLS
    /// precondition in DSL-014..016: byte-identical attestations,
    /// structural violation bubbled up from DSL-005, or BLS verify
    /// failure on one of the two aggregates.
    ///
    /// Reason string names the specific violation. Predicate-failure
    /// paths use the dedicated [`SlashingError::AttesterSlashingNotSlashable`]
    /// and [`SlashingError::EmptySlashableIntersection`] variants so
    /// appeals (DSL-042, DSL-043) can distinguish without string
    /// matching.
    #[error("invalid attester slashing: {0}")]
    InvalidAttesterSlashing(String),

    /// Neither the double-vote (DSL-014) nor the surround-vote (DSL-015)
    /// predicate holds for the two `AttestationData`s.
    ///
    /// Raised by DSL-017. Mirrored at the appeal layer by
    /// `AttesterAppealGround::NotSlashableByPredicate` (DSL-042).
    #[error("attestations do not prove a slashable offense")]
    AttesterSlashingNotSlashable,

    /// The intersection of `attestation_a.attesting_indices` and
    /// `attestation_b.attesting_indices` is empty — no validator
    /// participated in both, so there is nobody to slash.
    ///
    /// Raised by DSL-016 after the slashable-predicate check succeeds
    /// but the intersection yields zero indices. Mirrored at the appeal
    /// layer by `AttesterAppealGround::EmptyIntersection` (DSL-043).
    #[error("attester slashing intersecting indices empty")]
    EmptySlashableIntersection,

    /// `InvalidBlockProof` payload failed one of the preconditions in
    /// DSL-018..020: BLS verify failure over `block_signing_message`,
    /// `header.epoch != evidence.epoch`, out-of-range
    /// `failure_witness`, or the optional `InvalidBlockOracle`
    /// rejected the re-execution.
    ///
    /// Reason string names the specific violation. Appeals
    /// (DSL-049..054) distinguish the categories at their own layer.
    #[error("invalid block evidence: {0}")]
    InvalidSlashingEvidence(String),

    /// `ProposerSlashing` payload failed one of the preconditions in
    /// DSL-013: slot mismatch, proposer mismatch, identical headers,
    /// bad signature bytes, inactive validator, or BLS verify failure
    /// on one of the two signatures.
    ///
    /// Reason string names the specific violation for diagnostics
    /// (appeals in DSL-034..040 distinguish the same categories by
    /// structured variants; this coarse string is only the verifier's
    /// rejection channel).
    #[error("invalid proposer slashing: {0}")]
    InvalidProposerSlashing(String),

    /// A validator index named in the evidence is not registered in
    /// the validator view.
    ///
    /// Raised by DSL-013 (accused proposer) and DSL-018 (invalid-block
    /// proposer). Carries the offending index.
    #[error("validator not registered: {0}")]
    ValidatorNotRegistered(u32),

    /// Duplicate `submit_evidence` for an `evidence.hash()` already in
    /// the manager's `processed` map.
    ///
    /// Raised by DSL-026 as the FIRST pipeline check — before verify,
    /// capacity check, bond lock, or any state mutation. Persists
    /// across pending statuses (`Accepted`, `ChallengeOpen`,
    /// `Reverted`, `Finalised`) until a reorg rewind (DSL-129) or
    /// prune clears the entry.
    #[error("evidence already slashed")]
    AlreadySlashed,

    /// `ProposerView::proposer_at_slot(current_slot)` returned `None`.
    ///
    /// Raised by DSL-025 reward routing. A `None` here is a
    /// consensus-layer bug — the proposer at the current slot must
    /// always exist at admission time. Surfaces as a hard error
    /// rather than silently dropping the proposer reward.
    #[error("proposer unavailable at current slot")]
    ProposerUnavailable,

    /// `PendingSlashBook` at capacity; new slashes cannot be admitted
    /// until existing ones finalise or revert.
    ///
    /// Raised by DSL-027. `MAX_PENDING_SLASHES = 4_096` caps memory +
    /// pruning cost. Admission attempt at capacity performs no bond
    /// lock or validator mutation.
    #[error("pending slash book full")]
    PendingBookFull,

    /// Reporter bond lock failed — principal lacks collateral or the
    /// escrow rejected the tag.
    ///
    /// Raised by DSL-023 in `SlashingManager::submit_evidence` when
    /// `BondEscrow::lock(reporter_idx, REPORTER_BOND_MOJOS, Reporter(hash))`
    /// returns `Err(_)`. No state mutation occurs — the manager has
    /// not yet touched `ValidatorEntry::slash_absolute`.
    #[error("bond lock failed")]
    BondLockFailed,

    /// The evidence reporter named themselves among the slashable
    /// validators (self-accuse).
    ///
    /// Raised by `verify_evidence` (DSL-012) when
    /// `evidence.reporter_validator_index ∈ evidence.slashable_validators()`.
    /// Blocks a validator from self-slashing to collect the
    /// whistleblower reward (DSL-025 reward routing). Payload is the
    /// offending validator index so the adjudicator can log without
    /// re-deriving it.
    #[error("reporter cannot accuse self (index {0})")]
    ReporterIsAccused(u32),

    /// Appeal filed after the slash's appeal window closed.
    ///
    /// Raised by DSL-056. The window is `[submitted_at_epoch,
    /// submitted_at_epoch + SLASH_APPEAL_WINDOW_EPOCHS]` — inclusive
    /// on BOTH ends (the boundary epoch itself is still a valid
    /// filing). Bond is NOT locked on this path; precondition order
    /// guarantees this.
    #[error(
        "appeal window expired: submitted_at={submitted_at}, window={window}, current={current}"
    )]
    AppealWindowExpired {
        /// Epoch the slash was admitted at.
        submitted_at: u64,
        /// `SLASH_APPEAL_WINDOW_EPOCHS` at the time of admission.
        window: u64,
        /// `appeal.filed_epoch` — the epoch the appeal claims it
        /// was filed at.
        current: u64,
    },

    /// Appeal's `evidence_hash` does not match any entry in the
    /// `PendingSlashBook`.
    ///
    /// Raised by DSL-055 as the FIRST precondition in
    /// `SlashingManager::submit_appeal` — checked BEFORE any bond
    /// lock so callers can retry cheaply. The carried string is the
    /// hex encoding of the 32-byte evidence hash for diagnostic
    /// logging (the raw bytes remain available at the call site).
    #[error("unknown evidence: {0}")]
    UnknownEvidence(String),

    /// Offense epoch is older than `SLASH_LOOKBACK_EPOCHS` relative to
    /// the current epoch.
    ///
    /// Raised by `verify_evidence` (DSL-011) as the very first check —
    /// cheap filter BEFORE any BLS or validator-view work. The check
    /// is `evidence.epoch + SLASH_LOOKBACK_EPOCHS < current_epoch`,
    /// phrased with addition on the LHS to avoid underflow when
    /// `current_epoch < SLASH_LOOKBACK_EPOCHS` (e.g., at network boot).
    /// Carries both epochs so adjudicators can diagnose the exact
    /// delta without re-deriving it.
    #[error("offense too old: offense_epoch={offense_epoch}, current_epoch={current_epoch}")]
    OffenseTooOld {
        /// Epoch the evidence claims the offense occurred at.
        offense_epoch: u64,
        /// Current epoch as seen by the verifier.
        current_epoch: u64,
    },
}
