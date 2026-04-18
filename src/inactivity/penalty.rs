//! Inactivity-leak regime detection + penalty math.
//!
//! Traces to: [SPEC §9.1](../../../docs/resources/SPEC.md),
//! catalogue row
//! [DSL-087](../../../docs/requirements/domains/inactivity/specs/DSL-087.md).

use crate::constants::MIN_EPOCHS_TO_INACTIVITY_PENALTY;

/// Return `true` iff the network is currently in an inactivity-
/// leak regime.
///
/// Implements DSL-087. Traces to SPEC §9.1.
///
/// # Predicate
///
/// ```text
/// current_epoch.saturating_sub(finalized_epoch) > MIN_EPOCHS_TO_INACTIVITY_PENALTY
/// ```
///
/// Strict greater-than — a gap of exactly
/// `MIN_EPOCHS_TO_INACTIVITY_PENALTY` epochs is STILL the normal
/// regime. The stall kicks in on the next boundary.
///
/// # Saturating subtraction
///
/// `current_epoch < finalized_epoch` is a post-reorg transient.
/// Saturating subtraction collapses to 0, which cannot exceed
/// the threshold — returns `false`. Prevents an unsigned-
/// underflow panic when finality advances past the current
/// counter during a chain reorg.
#[must_use]
pub fn in_finality_stall(current_epoch: u64, finalized_epoch: u64) -> bool {
    current_epoch.saturating_sub(finalized_epoch) > MIN_EPOCHS_TO_INACTIVITY_PENALTY
}
