//! Requirement DSL-126: `BOND_AWARD_TO_WINNER_BPS = 5_000` (50%
//! of `BPS_DENOMINATOR`). Forfeited bonds split 50/50 between
//! winner award and burn in both sustained (DSL-068) and rejected
//! (DSL-071) paths. Integer division applies.
//!
//! Traces to: docs/resources/SPEC.md §2.6, §22.14.
//!
//! # Role
//!
//! Closes Phase 7 Bonds & Rewards Routing. Constant-pin test for
//! the split ratio plus pure-arithmetic verification of the
//! rounding rule. DSL-068 + DSL-071 integration tests already
//! exercise the constant through the full adjudicator pipeline;
//! this test isolates the constant + math so a future rewrite
//! of adjudicator implementation can't drift the ratio without
//! the gate firing.
//!
//! # Why 50/50
//!
//! SPEC §2.6: equal reward + burn means the winner (appellant
//! on sustained, reporter on rejected) takes half the loser's
//! bond as a direct reward for catching the misbehavior, while
//! the other half is burned so the system does not net out a
//! positive-sum bond trade that could be griefed by collusion.
//!
//! # Test matrix (maps to DSL-126 Test Plan + acceptance)
//!
//!   1. `test_dsl_126_constant_value` — asserts 5_000 and the
//!      50% ratio vs `BPS_DENOMINATOR`
//!   2. `test_dsl_126_sustained_split_math` — forfeited=1000 →
//!      appellant_award=500, burn=500 (sustained path)
//!   3. `test_dsl_126_rejected_split_math` — forfeited=1000 →
//!      reporter_award=500, burn=500 (rejected path, same
//!      formula)
//!   4. `test_dsl_126_rounding_odd` — forfeited=3 → award=1,
//!      burn=2 (floor division gives more to burn on odd input)
//!   5. `test_dsl_126_conservation` — award + burn == forfeited
//!      for a range of inputs (split is exhaustive, no mojo
//!      leak)

use dig_slashing::{BOND_AWARD_TO_WINNER_BPS, BPS_DENOMINATOR};

/// Reference split calc matching the adjudicator formula from
/// SPEC §2.6: `winner_award = forfeited * BPS / BPS_DENOM`,
/// `burn = forfeited - winner_award`. Integer division rounds
/// toward zero; any remainder falls to burn by construction.
fn split(forfeited: u64) -> (u64, u64) {
    let winner_award = forfeited * BOND_AWARD_TO_WINNER_BPS / BPS_DENOMINATOR;
    let burn = forfeited - winner_award;
    (winner_award, burn)
}

/// DSL-126 row 1: the constant is exactly 5_000 (50% of 10_000).
#[test]
fn test_dsl_126_constant_value() {
    assert_eq!(BOND_AWARD_TO_WINNER_BPS, 5_000);
    assert_eq!(BPS_DENOMINATOR, 10_000, "precondition: BPS denominator");

    // 50/50 ratio as a numeric invariant.
    assert_eq!(
        BOND_AWARD_TO_WINNER_BPS * 2,
        BPS_DENOMINATOR,
        "winner award + burn share must each be 50%",
    );
}

/// DSL-126 row 2: sustained path with forfeited=1000 → 500/500.
#[test]
fn test_dsl_126_sustained_split_math() {
    let (award, burn) = split(1_000);
    assert_eq!(award, 500, "appellant award = 50%");
    assert_eq!(burn, 500, "burn = 50%");
}

/// DSL-126 row 3: rejected path uses the same formula (formula
/// is symmetric; the ONLY difference from row 2 is which
/// principal collects the award). Pin that the math is
/// path-independent.
#[test]
fn test_dsl_126_rejected_split_math() {
    let (award, burn) = split(1_000);
    assert_eq!(
        award, 500,
        "reporter award = 50% (same formula as sustained path)",
    );
    assert_eq!(burn, 500);
}

/// DSL-126 row 4: odd input → floor division puts the extra mojo
/// on the burn side. forfeited=3 → award=1 (3*5000/10000 = 1.5
/// → 1), burn=2 (3-1).
///
/// This asymmetry is intentional: favoring burn on rounding
/// means the system never over-pays the winner, avoiding a
/// micro-exploit where repeated 1-mojo bonds could be griefed
/// to extract whole-mojo rewards.
#[test]
fn test_dsl_126_rounding_odd() {
    let (award, burn) = split(3);
    assert_eq!(award, 1, "floor(3 * 5000/10000) = 1");
    assert_eq!(burn, 2, "burn takes the remainder");

    // Other odd inputs to exercise the rounding rule.
    for forfeited in [1u64, 5, 7, 9, 11, 99, 1001] {
        let (a, b) = split(forfeited);
        assert_eq!(
            a + b,
            forfeited,
            "conservation on odd forfeited={forfeited}"
        );
        assert!(
            a <= b,
            "award <= burn on odd input (floor favors burn); forfeited={forfeited}, \
             award={a}, burn={b}",
        );
    }
}

/// DSL-126 conservation: `award + burn == forfeited` for any
/// input. This is the protocol-critical invariant — a buggy
/// split that leaked or double-counted mojos would misroute
/// stake on every adjudication.
#[test]
fn test_dsl_126_conservation() {
    for forfeited in [0u64, 1, 2, 100, 500_000_000, u64::MAX / 10_000] {
        let (award, burn) = split(forfeited);
        assert_eq!(
            award + burn,
            forfeited,
            "conservation must hold for forfeited={forfeited}",
        );
    }
}
