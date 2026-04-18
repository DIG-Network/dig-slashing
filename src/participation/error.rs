//! Errors produced by the participation tracker.
//!
//! Traces to: [SPEC §17.2](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-078..080](../../../docs/requirements/domains/participation/specs/).
//!
//! # Scope
//!
//! Separate error enum from `SlashingError` — participation
//! bookkeeping is a non-slashing code path, and mixing the two
//! would force consumers to match exhaustively on variants that
//! do not apply to them. The runtime may convert a
//! `ParticipationError` into whatever its own error surface
//! needs.

use thiserror::Error;

/// Failure modes for `ParticipationTracker` operations.
///
/// Traces to SPEC §17.2.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParticipationError {
    /// `attesting_indices[i] >= validator_count` — the tracker's
    /// per-validator storage is sized at construction and cannot
    /// accommodate indices beyond it.
    ///
    /// Raised by DSL-078 `record_attestation`. Carries the
    /// offending index for diagnostics.
    #[error("validator index out of range: {0}")]
    IndexOutOfRange(u32),

    /// `attesting_indices` is not strictly ascending (either
    /// non-monotonic or contains duplicates).
    ///
    /// Raised by DSL-079 `record_attestation`. The evidence
    /// canonicalisation layer (DSL-005) guarantees ascending
    /// indices for any valid attestation; a violation here is
    /// either a bug or a deliberately-malformed input.
    #[error("attesting indices not strictly ascending")]
    NonAscendingIndices,
}
