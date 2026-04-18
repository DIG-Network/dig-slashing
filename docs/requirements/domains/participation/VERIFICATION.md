# Participation & Rewards — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-074](NORMATIVE.md#DSL-074) | ✅ | ParticipationFlags bits set/has | 5 tests against new `ParticipationFlags(u8)` in `src/participation/flags.rs`: `Default::default()` → 0, `set(0)` → `has(0)` true + `is_source_timely()`, other bits untouched (0b0000_0101 after `set(0); set(2)`), idempotent `set(i)` twice, named accessors match `has(index)` for 3 flags. Adds `TIMELY_SOURCE_FLAG_INDEX=0`, `TIMELY_TARGET_FLAG_INDEX=1`, `TIMELY_HEAD_FLAG_INDEX=2` constants. Opens Phase 3 Participation. Test file: `tests/dsl_074_participation_flags_bits_test.rs`. |
| [DSL-075](NORMATIVE.md#DSL-075) | ✅ | classify_timeliness TIMELY_SOURCE | 4 tests against new `classify_timeliness(data, inclusion_slot, source_is_justified, _target, _head)` in `src/participation/timeliness.rs`: delay=1 (=MIN) + justified → set, delay=5 (=MAX) + justified → set, delay=6 or delay=0 → unset, in-range + unjustified (loop 1..=5) → unset. Closed interval `[1, 5]` via `RangeInclusive::contains`. Adds `MIN_ATTESTATION_INCLUSION_DELAY = 1` + `TIMELY_SOURCE_MAX_DELAY_SLOTS = 5` constants. Test file: `tests/dsl_075_classify_timely_source_test.rs`. |
| [DSL-076](NORMATIVE.md#DSL-076) | ✅ | classify_timeliness TIMELY_TARGET | 4 tests extending `classify_timeliness`: delay=1 + canonical → set, delay=32 (= `TIMELY_TARGET_MAX_DELAY_SLOTS`, SLOTS_PER_EPOCH boundary) + canonical → set, delay=33 or 0 → unset, in-range + non-canonical → unset. Adds `TIMELY_TARGET_MAX_DELAY_SLOTS = 32` constant. Wider window than `TIMELY_SOURCE` (1..=5). Test file: `tests/dsl_076_classify_timely_target_test.rs`. |
| [DSL-077](NORMATIVE.md#DSL-077) | ✅ | classify_timeliness TIMELY_HEAD | 4 tests: delay=1 + canonical head → `TIMELY_HEAD` set (strict equality, not range), delay=2 → unset, delay=0 → unset, non-canonical head → unset. Strictest of the three flags — only inclusion in the very next block after origin slot credits the head vote. Test file: `tests/dsl_077_classify_timely_head_test.rs`. |
| [DSL-078](NORMATIVE.md#DSL-078) | ❌ | ParticipationTracker::record_attestation | 4 tests: sets flags per index, additive with prior flags, respects array bounds. |
| [DSL-079](NORMATIVE.md#DSL-079) | ❌ | ParticipationTracker non-ascending rejection | 3 tests: non-ascending → error, duplicate → error, single-element ok. |
| [DSL-080](NORMATIVE.md#DSL-080) | ❌ | ParticipationTracker::rotate_epoch | 4 tests: swap, zero current, resize, epoch number update. |
| [DSL-081](NORMATIVE.md#DSL-081) | ❌ | base_reward formula | 4 tests: formula exact for known pairs, isqrt behaviour, saturation, zero-balance edge. |
| [DSL-082](NORMATIVE.md#DSL-082) | ❌ | compute_flag_deltas reward on hit | 4 tests: each flag alone, all flags set, weight math. |
| [DSL-083](NORMATIVE.md#DSL-083) | ❌ | compute_flag_deltas penalty head exempt | 4 tests: SOURCE miss penalty, TARGET miss penalty, HEAD miss no penalty, all-miss composite. |
| [DSL-084](NORMATIVE.md#DSL-084) | ❌ | compute_flag_deltas stall zeroes rewards | 3 tests: stall → reward=0; penalties still applied; out-of-stall normal. |
| [DSL-085](NORMATIVE.md#DSL-085) | ❌ | proposer_inclusion_reward formula | 3 tests: base * 8 / 56 exact; zero-base edge; rounding. |
| [DSL-086](NORMATIVE.md#DSL-086) | ❌ | WEIGHT_DENOMINATOR = 64 no sync | 2 tests: denominator value, sum of assigned weights == 62. |

| [DSL-153](NORMATIVE.md#DSL-153) | ❌ | ParticipationTracker::rewind_on_reorg | 4 tests: restores snapshot, epoch decrements, resize applied, depth=0 no-op. |
| [DSL-154](NORMATIVE.md#DSL-154) | ❌ | ParticipationFlags serde roundtrip | 4 tests: bincode, serde_json, vec, all bit patterns. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
