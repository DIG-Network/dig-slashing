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

    /// Advance to a new epoch: swap current → previous, reset
    /// current to `validator_count` zero-initialised slots, and
    /// update `current_epoch_number`.
    ///
    /// Implements [DSL-080](../../../docs/requirements/domains/participation/specs/DSL-080.md).
    /// Traces to SPEC §8.2, §10.
    ///
    /// # Ordering
    ///
    /// 1. `swap(previous, current)` — what was accumulated during
    ///    the just-finished epoch moves into `previous_epoch`.
    ///    DSL-082..086 reward / penalty math reads these bits.
    /// 2. `current.clear(); current.resize(validator_count, 0)` —
    ///    accept validator-set growth at the boundary. New
    ///    validators that activated this epoch get zero flags.
    /// 3. `current_epoch_number = new_epoch`.
    ///
    /// # Shrinking validator set
    ///
    /// If `validator_count < old.len()`, the trailing entries
    /// are dropped. This is the correct behaviour for exited
    /// validators — their previous-epoch flags are preserved
    /// (in the just-swapped `previous_epoch`), only the current
    /// -epoch slot is discarded.
    ///
    /// # Previous-epoch sizing
    ///
    /// `previous_epoch` keeps whatever length `current` had
    /// before rotation. Downstream reward math reads
    /// `previous_flags(idx)` via `.get(idx).copied()`, so
    /// out-of-range reads return `None` rather than panicking.
    pub fn rotate_epoch(&mut self, new_epoch: u64, validator_count: usize) {
        std::mem::swap(&mut self.previous_epoch, &mut self.current_epoch);
        self.current_epoch.clear();
        self.current_epoch
            .resize(validator_count, ParticipationFlags::default());
        self.current_epoch_number = new_epoch;
    }

    /// Rewind the tracker on fork-choice reorg.
    ///
    /// Implements the participation leg of DSL-130
    /// `rewind_all_on_reorg`. Drops both flag vectors and
    /// reinstates `new_tip_epoch` as the current epoch with
    /// zero-initialised flags.
    ///
    /// Why zero-fill instead of restoring pre-reorg state: the
    /// tracker does NOT retain historical snapshots (each
    /// `rotate_epoch` overwrites in place). Post-rewind, flag
    /// accumulation resumes fresh from the new canonical tip —
    /// the reward-delta pass at the NEXT epoch boundary
    /// observes no activity over the rewound span (conservative;
    /// no false reward credits from a ghost chain). Also zero-
    /// fills the `previous_epoch` slot so the first post-rewind
    /// `compute_flag_deltas` cannot read ghost data.
    ///
    /// Returns the number of epochs dropped
    /// (`old_current_epoch - new_tip_epoch`, saturating at 0
    /// when the tip is already current or ahead).
    pub fn rewind_on_reorg(&mut self, new_tip_epoch: u64, validator_count: usize) -> u64 {
        let dropped = self.current_epoch_number.saturating_sub(new_tip_epoch);
        // DSL-153 acceptance: `depth == 0` is a genuine no-op — the
        // orchestrator occasionally fires rewind_all_on_reorg with
        // `new_tip_epoch == current_epoch_number` for safety after a
        // recovery restart, and those callers must observe no flag /
        // epoch-number mutation. Skipping the rotate_epoch call also
        // avoids an unnecessary Vec resize when the validator count
        // is unchanged.
        if dropped == 0 {
            return 0;
        }
        // rotate_epoch zeroes the current slot; the swap in
        // rotate_epoch would otherwise preserve ghost `previous`
        // data from the reorged chain, so clear previous too.
        self.rotate_epoch(new_tip_epoch, validator_count);
        self.previous_epoch.clear();
        self.previous_epoch
            .resize(validator_count, ParticipationFlags::default());
        dropped
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
        // DSL-079: strict-ascending structural check runs BEFORE
        // the bit-OR pass so a malformed attestation does not
        // mutate any validator's flags.
        for w in attesting_indices.windows(2) {
            if w[0] == w[1] {
                return Err(ParticipationError::DuplicateIndex(w[0]));
            }
            if w[0] > w[1] {
                return Err(ParticipationError::NonAscendingIndices);
            }
        }

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
