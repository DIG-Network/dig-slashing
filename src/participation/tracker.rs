//! `ParticipationTracker` — two-epoch attestation-flag state
//! machine.
//!
//! Traces to: [SPEC §8.2](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-078..080](../../../docs/requirements/domains/participation/specs/).
//!
//! # Role
//!
//! Holds per-validator `ParticipationFlags` for the current
//! epoch + the previous epoch. Consumers call:
//!
//!   - `record_attestation` (DSL-078) per admitted attestation
//!     to OR the flags into `current_epoch`.
//!   - `rotate_epoch` (DSL-080) at each epoch boundary to shift
//!     current → previous and reset current to zero.
//!
//! Two epochs of state are retained because Altair-parity
//! rewards at finalisation (DSL-081..086) read the PREVIOUS
//! epoch's flags (the "attested" epoch), not the current one.
//!
//! # Storage shape
//!
//! `Vec<ParticipationFlags>` indexed by validator_index. Size
//! fixed at construction — consumers resize via
//! `resize_validator_count` (future DSL) when the validator set
//! grows.

use crate::participation::error::ParticipationError;
use crate::participation::flags::ParticipationFlags;

/// Per-validator two-epoch attestation-flag store.
///
/// Implements DSL-078 (+ DSL-079/080 in later commits). Traces
/// to SPEC §8.2.
///
/// # Fields
///
/// - `current_epoch` — flags accumulated during the in-flight
///   epoch.
/// - `previous_epoch` — flags from the just-completed epoch.
///   Read by reward / penalty delta computation (DSL-082..086).
/// - `current_epoch_number` — monotonically advancing epoch
///   counter. Driven forward by `rotate_epoch` (DSL-080).
///
/// # Storage size
///
/// Both vecs are sized at construction to `validator_count`.
/// Out-of-range indices return
/// `ParticipationError::IndexOutOfRange` rather than panicking
/// — record_attestation is called with adversary-controllable
/// indices (attesters may be newly registered or slashed
/// between admission and record), and the tracker is expected
/// to degrade gracefully.
#[derive(Debug, Clone)]
pub struct ParticipationTracker {
    current_epoch: Vec<ParticipationFlags>,
    previous_epoch: Vec<ParticipationFlags>,
    current_epoch_number: u64,
}

impl ParticipationTracker {
    /// New tracker sized for `validator_count` slots, starting
    /// at `initial_epoch`. Both epoch vectors initialise to
    /// `ParticipationFlags::default()` (all-zero).
    #[must_use]
    pub fn new(validator_count: usize, initial_epoch: u64) -> Self {
        Self {
            current_epoch: vec![ParticipationFlags::default(); validator_count],
            previous_epoch: vec![ParticipationFlags::default(); validator_count],
            current_epoch_number: initial_epoch,
        }
    }

    /// Current epoch counter. Advanced by
    /// `rotate_epoch` (DSL-080).
    #[must_use]
    pub fn current_epoch_number(&self) -> u64 {
        self.current_epoch_number
    }

    /// Flag bits accumulated for `validator_index` during the
    /// current epoch. `None` when the index is out of range.
    #[must_use]
    pub fn current_flags(&self, validator_index: u32) -> Option<ParticipationFlags> {
        self.current_epoch.get(validator_index as usize).copied()
    }

    /// Flag bits from the previous (finalisable) epoch for
    /// `validator_index`. `None` when the index is out of range.
    /// Consumed by DSL-082/083 reward-delta math.
    #[must_use]
    pub fn previous_flags(&self, validator_index: u32) -> Option<ParticipationFlags> {
        self.previous_epoch.get(validator_index as usize).copied()
    }

    /// Number of validator slots the tracker can address.
    /// `attesting_indices` with values `>= validator_count`
    /// return `IndexOutOfRange`.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.current_epoch.len()
    }

    /// Record an attestation: apply `flags` to every entry in
    /// `attesting_indices` via bit-OR into the current epoch's
    /// per-validator bucket.
    ///
    /// Implements [DSL-078](../../../docs/requirements/domains/participation/specs/DSL-078.md).
    ///
    /// # Errors
    ///
    /// Returns `ParticipationError::IndexOutOfRange(i)` for the
    /// FIRST offending index; later indices are not touched.
    /// Structural non-ascending / duplicate checks land in
    /// DSL-079 and run before this bit-OR pass in that cycle.
    ///
    /// # Behaviour
    ///
    /// - Bit-OR is additive. `record_attestation(.., TIMELY_SOURCE)`
    ///   followed by `record_attestation(.., TIMELY_TARGET)` on
    ///   the same validator leaves both bits set.
    /// - `current_epoch_number` is NOT mutated — epoch
    ///   advancement is the sole responsibility of `rotate_epoch`
    ///   (DSL-080).
    pub fn record_attestation(
        &mut self,
        _data: &crate::evidence::attestation_data::AttestationData,
        attesting_indices: &[u32],
        flags: ParticipationFlags,
    ) -> Result<(), ParticipationError> {
        for idx in attesting_indices {
            let i = *idx as usize;
            if i >= self.current_epoch.len() {
                return Err(ParticipationError::IndexOutOfRange(*idx));
            }
            self.current_epoch[i].0 |= flags.0;
        }
        Ok(())
    }
}
