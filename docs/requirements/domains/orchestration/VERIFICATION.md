# Orchestration — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-127](NORMATIVE.md#DSL-127) | ✅ | run_epoch_boundary fixed ordering | 5 tests against new `src/orchestration.rs`. Opens Phase 8. `pub fn run_epoch_boundary` drives the 8-step pipeline: flag_deltas → inactivity update → penalties → finalise → rotate participation → advance manager → resize → prune. New `JustificationView` trait (DSL-143 preview, single `latest_finalized_epoch` method) + `EpochBoundaryReport` struct. Adds `SlashingManager::prune_processed_older_than(cutoff)` returning count; also sweeps `slashed_in_window` range older than cutoff. 5 tests use outcome-based ordering (full fake impls of `ValidatorView`/`EffectiveBalanceView`/`BondEscrow`/`RewardPayout`/`JustificationView`): end-to-end report population + epoch counters advanced; inactivity score `update_for_epoch` runs before finalise (stall triggers +=4 score on miss); prune is last (cutoff uses post-advance state); validator-count mismatch triggers resize to match; stall state propagated per `justification.latest_finalized_epoch`. Test file: `tests/dsl_127_epoch_boundary_order_test.rs`. |
| [DSL-128](NORMATIVE.md#DSL-128) | ❌ | SlashingSystem::genesis | 4 tests: all state zero/empty, epoch matches params, in_finality_stall false at (0,0), trackers sized to initial_validator_count. |
| [DSL-129](NORMATIVE.md#DSL-129) | ❌ | SlashingManager::rewind_on_reorg | 5 tests: credits stake, restores collateral, releases bond in full, removes from processed, no reporter penalty, returns hash list. |
| [DSL-130](NORMATIVE.md#DSL-130) | ❌ | rewind_all_on_reorg + ReorgTooDeep | 4 tests: all four components rewound, depth > 36 rejected, shallow ok, ReorgReport populated. |

| [DSL-165](NORMATIVE.md#DSL-165) | ❌ | EpochBoundaryReport + ReorgReport + FlagDelta serde | 6 tests: each type bincode + json, empty vecs, stall flag both. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
