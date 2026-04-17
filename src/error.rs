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
}
