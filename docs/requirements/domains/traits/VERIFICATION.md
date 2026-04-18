# Traits — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-131](NORMATIVE.md#DSL-131) | ✅ | ValidatorEntry::slash_absolute saturation | 5 tests pin the `ValidatorEntry::slash_absolute(amount, epoch)` contract via reference `MockValidator`. Opens Phase 9 External-State Traits. Semantics: `debited = min(amount, stake); stake -= debited; status = Slashed{epoch}; return debited`. Saturation is load-bearing — DSL-022 + DSL-030 debits can exceed remaining stake on partially-slashed validators. 5 tests: under-stake exact, at-stake zeroes balance, over-stake saturates (including `u64::MAX` vs 1 mojo), status flips on any call including zero-amount (DSL-162 compat), repeated debits compose with epoch updating to latest call. Test file: `tests/dsl_131_validator_entry_slash_absolute_saturation_test.rs`. |
| [DSL-132](NORMATIVE.md#DSL-132) | ❌ | ValidatorEntry::credit_stake | 3 tests: credit adds to stake; inverse of slash_absolute; returns credited amount. |
| [DSL-133](NORMATIVE.md#DSL-133) | ❌ | ValidatorEntry::restore_status | 3 tests: Slashed → Active returns true; Active → Active returns false; idempotent. |
| [DSL-134](NORMATIVE.md#DSL-134) | ❌ | ValidatorEntry::is_active_at_epoch | 4 tests: activation boundary active; pre-activation inactive; exit boundary inactive; post-exit inactive. |
| [DSL-135](NORMATIVE.md#DSL-135) | ❌ | ValidatorEntry::schedule_exit | 2 tests: persists exit epoch; overridable. |
| [DSL-136](NORMATIVE.md#DSL-136) | ❌ | ValidatorView::get / get_mut | 3 tests: live idx returns Some; out-of-range None; mut mirrors. |
| [DSL-137](NORMATIVE.md#DSL-137) | ❌ | EffectiveBalanceView::get / total_active | 3 tests: per-validator get; total_active sum consistency; includes only actives. |
| [DSL-138](NORMATIVE.md#DSL-138) | ❌ | PublicKeyLookup::pubkey_of | 2 tests: known idx returns key; blanket impl via ValidatorView. |
| [DSL-139](NORMATIVE.md#DSL-139) | ❌ | CollateralSlasher symmetry | 3 tests: slash+credit roundtrip; NoCollateral is soft; error types. |
| [DSL-140](NORMATIVE.md#DSL-140) | ❌ | BondEscrow::escrowed | 3 tests: locked amount returned; unknown tag returns 0; no panic. |
| [DSL-141](NORMATIVE.md#DSL-141) | ❌ | RewardPayout::pay | 3 tests: pays address; multiple pays accumulate; zero amount no-op. |
| [DSL-142](NORMATIVE.md#DSL-142) | ❌ | RewardClawback::claw_back partial | 4 tests: full clawback returns amount; partial returns < amount; zero ok; saturates. |
| [DSL-143](NORMATIVE.md#DSL-143) | ❌ | JustificationView contract | 5 tests: each method callable; returns structured data; canonical_target_root None for uncommitted. |
| [DSL-144](NORMATIVE.md#DSL-144) | ❌ | ProposerView::proposer_at_slot | 3 tests: committed slot Some; future slot None; current_slot monotonic. |
| [DSL-145](NORMATIVE.md#DSL-145) | ❌ | InvalidBlockOracle::re_execute determinism | 3 tests: same inputs same outcome; Valid vs Invalid cases; no hidden state. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
