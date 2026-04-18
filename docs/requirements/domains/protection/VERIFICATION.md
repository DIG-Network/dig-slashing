# Slashing Protection — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-094](NORMATIVE.md#DSL-094) | ✅ | check_proposal_slot monotonic | 4 tests against new `SlashingProtection` in `src/protection.rs`: default state → `check(10)=true`, `record(10)+check(10)=false` (equivocation self-check), `record(10)+check(9/5/0)=false`, `record(10)+check(11)=true` (and chained `record(11)+check(11)=false`). Opens Phase 5 Protection. Test file: `tests/dsl_094_protection_proposal_monotonic_test.rs`. |
| [DSL-095](NORMATIVE.md#DSL-095) | ❌ | check_attestation same epoch different hash | 3 tests: same hash ok, different hash fails, case-insensitive hash compare. |
| [DSL-096](NORMATIVE.md#DSL-096) | ❌ | would_surround self-check | 4 tests: genuine surround rejected, exact match ok, flanking allowed, edge. |
| [DSL-097](NORMATIVE.md#DSL-097) | ❌ | record_proposal / record_attestation persist | 3 tests: proposal watermark set, attestation fields set, hash hex-encoded. |
| [DSL-098](NORMATIVE.md#DSL-098) | ❌ | rewind_attestation_to_epoch clears hash | 3 tests: hash cleared, epochs lowered, no-op if already lower. |
| [DSL-099](NORMATIVE.md#DSL-099) | ❌ | reconcile_with_chain_tip rewinds both | 3 tests: both watermarks lowered; surround check re-passes. |
| [DSL-100](NORMATIVE.md#DSL-100) | ❌ | Legacy JSON loads (no hash field → None) | 2 tests: legacy file loads, hash=None. |
| [DSL-101](NORMATIVE.md#DSL-101) | ❌ | Save/load roundtrip | 3 tests: all fields preserved, case-insensitive compare, hex format. |

| [DSL-156](NORMATIVE.md#DSL-156) | ❌ | rewind_proposal_to_slot | 4 tests: higher lowered, lower unchanged, equal unchanged, idempotent. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
