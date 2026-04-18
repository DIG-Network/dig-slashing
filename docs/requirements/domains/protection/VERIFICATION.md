# Slashing Protection — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-094](NORMATIVE.md#DSL-094) | ✅ | check_proposal_slot monotonic | 4 tests against new `SlashingProtection` in `src/protection.rs`: default state → `check(10)=true`, `record(10)+check(10)=false` (equivocation self-check), `record(10)+check(9/5/0)=false`, `record(10)+check(11)=true` (and chained `record(11)+check(11)=false`). Opens Phase 5 Protection. Test file: `tests/dsl_094_protection_proposal_monotonic_test.rs`. |
| [DSL-095](NORMATIVE.md#DSL-095) | ✅ | check_attestation same epoch different hash | 4 tests against new `check_attestation(source_epoch, target_epoch, &Bytes32)` + `record_attestation` in `src/protection.rs`: record(5,10,h) + same-hash re-check → true (restart re-sign), record(5,10,h1) + check(5,10,h2) → false, case-insensitive hex compare via serde JSON uppercase mutation → true, (src=5,tgt=10) + `last_attested_block_hash=None` via JSON injection → false. Adds `last_attested_{source,target}_epoch: u64` + `last_attested_block_hash: Option<String>` fields (lowercase 0x-hex). Test file: `tests/dsl_095_protection_attestation_same_epoch_different_hash_test.rs`. |
| [DSL-096](NORMATIVE.md#DSL-096) | ✅ | would_surround self-check | 4 tests against `check_attestation` + private `would_surround` predicate in `src/protection.rs`: prior (3,5) + candidate (2,6) → false (classic surround), same (src,tgt) + same hash → true / + different hash → false via DSL-095 fallthrough (strict `<`/`>` excludes exact match), flanking (5,7) and (4,10) → true, same-source-higher-target (3,6)/(2,5)/(1,4) → all true (either predicate leg non-strict). Surround guard runs BEFORE DSL-095 same-coord branch so slashable surrounds short-circuit regardless of stored hash. Test file: `tests/dsl_096_protection_surround_vote_self_check_test.rs`. |
| [DSL-097](NORMATIVE.md#DSL-097) | ❌ | record_proposal / record_attestation persist | 3 tests: proposal watermark set, attestation fields set, hash hex-encoded. |
| [DSL-098](NORMATIVE.md#DSL-098) | ❌ | rewind_attestation_to_epoch clears hash | 3 tests: hash cleared, epochs lowered, no-op if already lower. |
| [DSL-099](NORMATIVE.md#DSL-099) | ❌ | reconcile_with_chain_tip rewinds both | 3 tests: both watermarks lowered; surround check re-passes. |
| [DSL-100](NORMATIVE.md#DSL-100) | ❌ | Legacy JSON loads (no hash field → None) | 2 tests: legacy file loads, hash=None. |
| [DSL-101](NORMATIVE.md#DSL-101) | ❌ | Save/load roundtrip | 3 tests: all fields preserved, case-insensitive compare, hex format. |

| [DSL-156](NORMATIVE.md#DSL-156) | ❌ | rewind_proposal_to_slot | 4 tests: higher lowered, lower unchanged, equal unchanged, idempotent. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
