//! Epoch-boundary orchestration.
//!
//! Traces to: [SPEC §10](../docs/resources/SPEC.md).
//!
//! # Role
//!
//! [`run_epoch_boundary`] is the single public entry point an
//! embedder calls once per epoch-boundary to drive every
//! per-epoch piece of slashing state forward in a FIXED,
//! spec-mandated order. Each downstream step depends on the
//! state produced by earlier steps; reordering is a protocol
//! error and pinned by DSL-127's order tests.
//!
//! Spec-mandated step order:
//!
//!   1. Compute flag deltas over `participation`'s previous-epoch
//!      flags.
//!   2. Update inactivity scores over the same previous-epoch
//!      flags.
//!   3. Compute inactivity-leak penalties for the ending epoch.
//!   4. Finalise expired slashes (correlation penalty + reporter-
//!      bond release + exit lock).
//!   5. Rotate `ParticipationTracker` to `current_epoch_ending + 1`.
//!   6. Advance `SlashingManager` epoch.
//!   7. Resize trackers if `validator_count` changed.
//!   8. Prune old processed evidence + correlation-window
//!      entries.
//!
//! # Why this order
//!
//! - **1 before 2** — `update_for_epoch` reads the same
//!   previous-epoch flags the flag-delta computation reads.
//!   Running the update first would rotate the tracker before
//!   the delta pass, losing the previous-epoch data permanently.
//! - **3 before 4** — finalise uses correlation data that must
//!   reflect the most recent inactivity update; if penalties
//!   were computed after finalise, the cohort would use stale
//!   scores.
//! - **4 before 5** — `finalise_expired_slashes` reads
//!   `correlation_window` entries keyed by the CURRENT epoch;
//!   rotating the participation tracker first would confuse
//!   other consumers into believing the new epoch is active
//!   while the manager is still mid-finalise.
//! - **8 last** — pruning drops evidence and correlation rows
//!   that would otherwise be needed by earlier steps.

use std::collections::BTreeMap;

use dig_epoch::CORRELATION_WINDOW_EPOCHS;

use dig_protocol::Bytes32;

use crate::bonds::BondEscrow;
use crate::error::SlashingError;
use crate::inactivity::{InactivityScoreTracker, in_finality_stall};
use crate::manager::{FinalisationResult, SlashingManager};
use crate::participation::{FlagDelta, ParticipationTracker, compute_flag_deltas};
use crate::protection::SlashingProtection;
use crate::traits::{CollateralSlasher, EffectiveBalanceView, RewardPayout, ValidatorView};

/// Per-epoch finality view. Returns the epoch of the most
/// recently FINALIZED Casper-FFG checkpoint. DSL-127 consults
/// this to derive [`in_finality_stall`]; the orchestrator does
/// not require a full Casper view, only the finalized-epoch
/// height.
///
/// Implemented by the embedder's consensus integration (DSL-143
/// full surface). Shipped here early because DSL-127 is the
/// first caller.
pub trait JustificationView {
    /// Epoch of the most recent finalized checkpoint. `0` at
    /// genesis before any checkpoint has finalized.
    fn latest_finalized_epoch(&self) -> u64;
}

/// Summary produced by [`run_epoch_boundary`]. Carries every
/// side-effect the caller needs to route downstream (logging,
/// reward payouts, state snapshots).
///
/// The struct intentionally contains vectors rather than
/// callback channels — the orchestrator is infallible by
/// construction and produces a complete report in one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochBoundaryReport {
    /// Per-validator reward/penalty deltas from DSL-082/083.
    pub flag_deltas: Vec<FlagDelta>,
    /// Per-validator inactivity-leak penalties from DSL-091/092.
    /// Empty outside a finality stall.
    pub inactivity_penalties: Vec<(u32, u64)>,
    /// Slashes finalised this epoch (DSL-029..033).
    pub finalisations: Vec<FinalisationResult>,
    /// Whether a finality stall was in effect at the start of
    /// the epoch boundary. Drives inactivity-leak branches.
    pub in_finality_stall: bool,
    /// Number of stale processed-evidence entries pruned
    /// (step 8). Observability only.
    pub pruned_entries: usize,
}

/// Drive one epoch-boundary pass. See module docs for order.
///
/// # Signatures
///
/// Every trait argument is `&mut dyn` / `&dyn` so the embedder
/// can inject concrete state views without committing to
/// generics on the slashing crate. The `usize` +`u64` scalars
/// are snapshot values measured at block N-1 (the block that
/// closes the epoch).
///
/// # Invariants
///
/// - After the call:
///   - `participation.current_epoch_number() == current_epoch_ending + 1`
///   - `manager.current_epoch() == current_epoch_ending + 1`
///   - `inactivity.validator_count() == validator_count`
#[allow(clippy::too_many_arguments)]
pub fn run_epoch_boundary(
    manager: &mut SlashingManager,
    participation: &mut ParticipationTracker,
    inactivity: &mut InactivityScoreTracker,
    validator_set: &mut dyn ValidatorView,
    effective_balances: &dyn EffectiveBalanceView,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
    justification: &dyn JustificationView,
    current_epoch_ending: u64,
    validator_count: usize,
    total_active_balance: u64,
) -> EpochBoundaryReport {
    // Derive finality-stall state ONCE up front. Both the
    // inactivity-score update (step 2) and the penalty
    // computation (step 3) branch on it; deriving here keeps
    // them consistent even if `justification` is a racing
    // reference (should not happen under the chain lock, but
    // defensive).
    let finalized_epoch = justification.latest_finalized_epoch();
    let stall = in_finality_stall(current_epoch_ending, finalized_epoch);

    // `reward_payout` is threaded through the signature for
    // future steps that route direct payouts (currently
    // finalise drives its own payout path via validator_set).
    // Touch the reference to silence the unused-parameter lint
    // without changing behaviour.
    let _ = &reward_payout;

    // ── Step 1: flag deltas over previous-epoch flags ─────
    let flag_deltas = compute_flag_deltas(
        participation,
        effective_balances,
        total_active_balance,
        stall,
    );

    // ── Step 2: inactivity-score update (reads same flags) ─
    inactivity.update_for_epoch(participation, stall);

    // ── Step 3: inactivity-leak penalties for ending epoch ─
    let inactivity_penalties = inactivity.epoch_penalties(effective_balances, stall);

    // ── Step 4: finalise expired slashes ─────────────────
    let finalisations = manager.finalise_expired_slashes(
        validator_set,
        effective_balances,
        bond_escrow,
        total_active_balance,
    );

    // ── Step 5: rotate participation tracker ──────────────
    participation.rotate_epoch(current_epoch_ending + 1, validator_count);

    // ── Step 6: advance SlashingManager epoch ─────────────
    manager.set_epoch(current_epoch_ending + 1);

    // ── Step 7: resize trackers if validator count changed ─
    if inactivity.validator_count() != validator_count {
        inactivity.resize_for(validator_count);
    }

    // ── Step 8: prune old processed evidence + corr-window ─
    // Cutoff = current_epoch_ending.saturating_sub(CORRELATION_WINDOW_EPOCHS).
    // Keeps everything within the correlation window reachable
    // by future DSL-030 cohort-sum computations.
    let cutoff = current_epoch_ending.saturating_sub(u64::from(CORRELATION_WINDOW_EPOCHS));
    let pruned_entries = manager.prune_processed_older_than(cutoff);

    EpochBoundaryReport {
        flag_deltas,
        inactivity_penalties,
        finalisations,
        in_finality_stall: stall,
        pruned_entries,
    }
}

// `BTreeMap` imported above for Visualiser-friendly diff when
// the module grows; currently not used directly. Suppress with
// a no-op to avoid unused-import churn.
#[allow(dead_code)]
type _KeepBTreeMap<K, V> = BTreeMap<K, V>;

/// Summary produced by [`rewind_all_on_reorg`]. Carries per-
/// subsystem rewind outcomes so the caller (a chain-shell
/// orchestrator) can log or emit metrics without re-deriving
/// the rewind scope from internal tracker state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReorgReport {
    /// Evidence hashes rewound by
    /// [`SlashingManager::rewind_on_reorg`] (DSL-129).
    pub rewound_pending_slashes: Vec<Bytes32>,
    /// Epochs dropped from the participation tracker (= reorg
    /// depth at the moment the tracker was rewound).
    pub participation_epochs_dropped: u64,
    /// Epochs dropped from the inactivity tracker (same depth —
    /// the inactivity tracker does not carry an epoch counter,
    /// so the caller's computed depth is carried through for
    /// uniform metric reporting).
    pub inactivity_epochs_dropped: u64,
    /// Whether `SlashingProtection::reconcile_with_chain_tip`
    /// was called. `true` in every successful rewind; exposed
    /// as a field for symmetry / future branching.
    pub protection_rewound: bool,
}

/// Global reorg orchestrator. Rewinds every slashing-state
/// subsystem in a fixed order.
///
/// Implements [DSL-130](../docs/requirements/domains/orchestration/specs/DSL-130.md).
/// Traces to SPEC §13.
///
/// # Step order
///
///   1. [`SlashingManager::rewind_on_reorg`] (DSL-129) — must
///      run FIRST because it reads validator-set state that the
///      other rewinds do not touch; running it after a
///      participation rewind would confuse the `is_slashed`
///      check inside `credit_stake` / `restore_status`.
///   2. [`ParticipationTracker::rewind_on_reorg`] — zero-fills
///      both flag vectors and anchors current_epoch at the
///      new tip.
///   3. [`InactivityScoreTracker::rewind_on_reorg`] — zero-
///      fills every score.
///   4. [`SlashingProtection::reconcile_with_chain_tip`]
///      (DSL-099) — caps proposal + attestation watermarks at
///      the new tip and clears the attested-block hash binding.
///
/// After success, `manager.current_epoch()` is reset to
/// `new_tip_epoch` so the orchestration state carries the
/// post-reorg epoch forward.
///
/// # Depth limit
///
/// `current - new_tip_epoch > CORRELATION_WINDOW_EPOCHS` ⇒
/// `SlashingError::ReorgTooDeep`. The correlation window is
/// the deepest state we can reconstruct — older `slashed_in_window`
/// rows have been pruned (DSL-127 step 8) and no subsystem
/// retains snapshots further back.
///
/// # Errors
///
/// - [`SlashingError::ReorgTooDeep`] — reorg depth exceeds
///   retention. No state is mutated; caller must recover via a
///   longer-range reconciliation path (checkpoint restore /
///   full resync).
#[allow(clippy::too_many_arguments)]
pub fn rewind_all_on_reorg(
    manager: &mut SlashingManager,
    participation: &mut ParticipationTracker,
    inactivity: &mut InactivityScoreTracker,
    protection: &mut SlashingProtection,
    validator_set: &mut dyn ValidatorView,
    collateral: Option<&mut dyn CollateralSlasher>,
    bond_escrow: &mut dyn BondEscrow,
    new_tip_epoch: u64,
    new_tip_slot: u64,
    validator_count: usize,
) -> Result<ReorgReport, SlashingError> {
    let current_epoch = manager.current_epoch();
    let depth = current_epoch.saturating_sub(new_tip_epoch);
    let limit = u64::from(CORRELATION_WINDOW_EPOCHS);
    if depth > limit {
        return Err(SlashingError::ReorgTooDeep { depth, limit });
    }

    // ── Step 1: manager rewind ────────────────────────────
    let rewound_pending_slashes =
        manager.rewind_on_reorg(new_tip_epoch, validator_set, collateral, bond_escrow);

    // ── Step 2: participation rewind ──────────────────────
    let participation_epochs_dropped =
        participation.rewind_on_reorg(new_tip_epoch, validator_count);

    // ── Step 3: inactivity rewind ─────────────────────────
    let inactivity_epochs_dropped = inactivity.rewind_on_reorg(depth);

    // ── Step 4: protection reconcile ──────────────────────
    protection.reconcile_with_chain_tip(new_tip_slot, new_tip_epoch);

    // Anchor the manager's epoch at the new tip so future
    // epoch-boundary passes compute correctly.
    manager.set_epoch(new_tip_epoch);

    Ok(ReorgReport {
        rewound_pending_slashes,
        participation_epochs_dropped,
        inactivity_epochs_dropped,
        protection_rewound: true,
    })
}
