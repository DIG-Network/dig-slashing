# Orchestration — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-127](NORMATIVE.md#DSL-127) | ❌ | run_epoch_boundary fixed ordering | 5 tests: step order via trace, finalise sees post-inactivity-update state, prune is last, validator-count resize, stall-state propagated to report. |
| [DSL-128](NORMATIVE.md#DSL-128) | ❌ | SlashingSystem::genesis | 4 tests: all state zero/empty, epoch matches params, in_finality_stall false at (0,0), trackers sized to initial_validator_count. |
| [DSL-129](NORMATIVE.md#DSL-129) | ❌ | SlashingManager::rewind_on_reorg | 5 tests: credits stake, restores collateral, releases bond in full, removes from processed, no reporter penalty, returns hash list. |
| [DSL-130](NORMATIVE.md#DSL-130) | ❌ | rewind_all_on_reorg + ReorgTooDeep | 4 tests: all four components rewound, depth > 36 rejected, shallow ok, ReorgReport populated. |

| [DSL-165](NORMATIVE.md#DSL-165) | ❌ | EpochBoundaryReport + ReorgReport + FlagDelta serde | 6 tests: each type bincode + json, empty vecs, stall flag both. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
