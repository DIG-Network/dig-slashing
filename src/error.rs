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
