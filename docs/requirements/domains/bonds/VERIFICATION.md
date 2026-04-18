# Bonds & Rewards Routing — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-121](NORMATIVE.md#DSL-121) | ✅ | BondEscrow::lock InsufficientBalance | 3 tests pin the `BondEscrow::lock` trait contract. Opens Phase 7 Bonds. Ships a reference `MockBondEscrow` (HashMap-backed free balance + (principal,tag)→amount escrow map) as the canonical trait-contract spec that downstream `dig-collateral` impls must satisfy. Sufficient balance → Ok + `escrowed==amount` + verifies distinct tags on same principal are independent slots; insufficient balance → `BondError::InsufficientBalance { have, need }` with exact values + escrow untouched on failure; same `(principal, tag)` twice → `BondError::DoubleLock { tag }` carrying offending tag + original state preserved. `DoubleLock` prioritised over `InsufficientBalance` in the mock: tag uniqueness is a structural invariant, balance is transient. Test file: `tests/dsl_121_bond_lock_insufficient_balance_test.rs`. |
| [DSL-122](NORMATIVE.md#DSL-122) | ❌ | BondEscrow::forfeit returns mojos | 3 tests: returns locked amount, zeroes tag, no-op on zero. |
| [DSL-123](NORMATIVE.md#DSL-123) | ❌ | BondEscrow::release full | 3 tests: credits stake, zeroes tag, no-op on zero. |
| [DSL-124](NORMATIVE.md#DSL-124) | ❌ | REPORTER_BOND_MOJOS = MIN/64 | 2 tests: constant value; lock amount on submit_evidence. |
| [DSL-125](NORMATIVE.md#DSL-125) | ❌ | APPELLANT_BOND_MOJOS = MIN/64 | 2 tests: constant value; lock amount on submit_appeal. |
| [DSL-126](NORMATIVE.md#DSL-126) | ❌ | BOND_AWARD_TO_WINNER_BPS = 5_000 | 4 tests: constant value; split math on sustained, rejected, rounding. |

| [DSL-166](NORMATIVE.md#DSL-166) | ❌ | BondTag variants distinguishable | 5 tests: PartialEq, Hash differ, separate escrow slots, serde discriminator, Copy. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
