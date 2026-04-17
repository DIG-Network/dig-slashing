# Bonds & Rewards Routing — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-121](NORMATIVE.md#DSL-121) | ❌ | BondEscrow::lock InsufficientBalance | 3 tests: ok on sufficient, err with have/need fields, escrowed() reflects lock. |
| [DSL-122](NORMATIVE.md#DSL-122) | ❌ | BondEscrow::forfeit returns mojos | 3 tests: returns locked amount, zeroes tag, no-op on zero. |
| [DSL-123](NORMATIVE.md#DSL-123) | ❌ | BondEscrow::release full | 3 tests: credits stake, zeroes tag, no-op on zero. |
| [DSL-124](NORMATIVE.md#DSL-124) | ❌ | REPORTER_BOND_MOJOS = MIN/64 | 2 tests: constant value; lock amount on submit_evidence. |
| [DSL-125](NORMATIVE.md#DSL-125) | ❌ | APPELLANT_BOND_MOJOS = MIN/64 | 2 tests: constant value; lock amount on submit_appeal. |
| [DSL-126](NORMATIVE.md#DSL-126) | ❌ | BOND_AWARD_TO_WINNER_BPS = 5_000 | 4 tests: constant value; split math on sustained, rejected, rounding. |

| [DSL-166](NORMATIVE.md#DSL-166) | ❌ | BondTag variants distinguishable | 5 tests: PartialEq, Hash differ, separate escrow slots, serde discriminator, Copy. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
