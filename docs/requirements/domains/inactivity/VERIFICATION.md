# Inactivity Accounting — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-087](NORMATIVE.md#DSL-087) | ❌ | `in_finality_stall` threshold `current - finalized > 4` | Unit test `dsl_087_in_finality_stall_threshold_test.rs`: boundary cases around `MIN_EPOCHS_TO_INACTIVITY_PENALTY` (3 → false, 4 → false, 5 → true), saturating behaviour when `finalized > current`. |
| [DSL-088](NORMATIVE.md#DSL-088) | ❌ | `update_for_epoch` decrements on target hit | Unit test `dsl_088_inactivity_score_hit_decrement_test.rs`: target-timely flag drops score by 1, saturating at 0, applies both in and out of stall. |
| [DSL-089](NORMATIVE.md#DSL-089) | ❌ | `update_for_epoch` +4 on target miss in stall | Unit test `dsl_089_inactivity_score_miss_in_stall_increment_test.rs`: target-miss + stall increments by `INACTIVITY_SCORE_BIAS` (4); target-miss out of stall does not add bias. |
| [DSL-090](NORMATIVE.md#DSL-090) | ❌ | `update_for_epoch` global recovery −16 out of stall | Unit test `dsl_090_inactivity_score_out_of_stall_recovery_test.rs`: all validators lose `INACTIVITY_SCORE_RECOVERY_RATE` (16) once per epoch out of stall, saturating at 0; no recovery during stall. |
| [DSL-091](NORMATIVE.md#DSL-091) | ❌ | `epoch_penalties` empty out of stall | Unit test `dsl_091_inactivity_penalty_no_stall_empty_test.rs`: with non-zero scores and `in_finality_stall=false`, returned vec is empty. |
| [DSL-092](NORMATIVE.md#DSL-092) | ❌ | Penalty `eff_bal * score / 16_777_216` | Unit test `dsl_092_inactivity_penalty_formula_test.rs`: explicit fixture (`eff_bal`, `score`) pairs; integer division truncation; only non-zero penalties emitted. |
| [DSL-093](NORMATIVE.md#DSL-093) | ❌ | `resize_for` grows vec; new entries start at 0 | Unit test `dsl_093_inactivity_resize_test.rs`: grow from N to N+K, first N preserved, last K are 0; idempotent when equal. |
| [DSL-155](NORMATIVE.md#DSL-155) | ❌ | InactivityScoreTracker::rewind_on_reorg | 3 tests: restores ring-buffer snapshot; depth=0 no-op; depth at ring limit. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
