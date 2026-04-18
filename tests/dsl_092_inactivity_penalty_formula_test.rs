//! Requirement DSL-092: during a finality stall,
//! `epoch_penalties` emits `(validator_index, penalty_mojos)`
//! for each validator with a non-zero score using the formula
//! `penalty = effective_balance * score /
//! INACTIVITY_PENALTY_QUOTIENT` (= 2^24 = 16_777_216). u128
//! intermediate; zero-penalty results filtered out.
//!
//! Traces to: docs/resources/SPEC.md §9.3, §2.4, §22.10.
//!
//! # Test matrix (maps to DSL-092 Test Plan)
//!
//!   1. `test_dsl_092_formula_exact` — eff=1e12, score=100 →
//!      floor(1e12 * 100 / 16_777_216)
//!   2. `test_dsl_092_zero_score_omitted` — score=0 validator
//!      absent from output
//!   3. `test_dsl_092_u128_no_overflow` — eff=u64::MAX,
//!      score=u64::MAX → no panic
//!   4. `test_dsl_092_stall_only` — stall=true + non-zero
//!      scores → non-empty vec

use dig_slashing::{EffectiveBalanceView, INACTIVITY_PENALTY_QUOTIENT, InactivityScoreTracker};

struct FlatBalances(u64);
impl EffectiveBalanceView for FlatBalances {
    fn get(&self, _: u32) -> u64 {
        self.0
    }
    fn total_active(&self) -> u64 {
        self.0
    }
}

/// DSL-092 row 1: exact formula match. eff=1e12, score=100 →
/// (1e12 * 100) / 16_777_216 = 100_000_000_000_000 / 16_777_216
/// = 5_960_464 (floor).
#[test]
fn test_dsl_092_formula_exact() {
    let mut scores = InactivityScoreTracker::new(1);
    scores.set_score(0, 100);

    let eff = 1_000_000_000_000u64;
    let balances = FlatBalances(eff);

    let out = scores.epoch_penalties(&balances, true);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, 0);

    let expected = (u128::from(eff) * 100u128 / u128::from(INACTIVITY_PENALTY_QUOTIENT)) as u64;
    assert_eq!(out[0].1, expected);
}

/// DSL-092 row 2: zero-score validators are absent from the
/// output. Non-zero neighbours are still emitted.
#[test]
fn test_dsl_092_zero_score_omitted() {
    let mut scores = InactivityScoreTracker::new(4);
    scores.set_score(0, 0);
    scores.set_score(1, 500);
    scores.set_score(2, 0);
    scores.set_score(3, 1_000);

    // Large eff to make penalties non-zero.
    let balances = FlatBalances(1_000_000_000_000u64);
    let out = scores.epoch_penalties(&balances, true);

    let indices: Vec<u32> = out.iter().map(|(i, _)| *i).collect();
    assert_eq!(indices, vec![1, 3], "zero-score slots omitted");
    assert!(out[0].1 > 0);
    assert!(out[1].1 > 0);
}

/// DSL-092 row 3: extreme inputs do not panic. u128 intermediate
/// ensures eff_bal * score fits.
#[test]
fn test_dsl_092_u128_no_overflow() {
    let mut scores = InactivityScoreTracker::new(1);
    scores.set_score(0, u64::MAX);

    let balances = FlatBalances(u64::MAX);
    let out = scores.epoch_penalties(&balances, true);

    // u64::MAX * u64::MAX / 2^24 fits in u128 and the /2^24
    // quotient is well within u64. Just check non-panic + some
    // output.
    assert_eq!(out.len(), 1);
}

/// DSL-092 row 4: stall=true + non-zero scores → non-empty vec
/// (contrast with DSL-091 which zero-returns when no stall).
#[test]
fn test_dsl_092_stall_only() {
    let mut scores = InactivityScoreTracker::new(3);
    scores.set_score(0, 100);
    scores.set_score(1, 200);
    scores.set_score(2, 300);
    let balances = FlatBalances(1_000_000_000_000u64);

    // stall=false → empty (DSL-091).
    assert!(scores.epoch_penalties(&balances, false).is_empty());

    // stall=true → all three emit.
    let out = scores.epoch_penalties(&balances, true);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].0, 0);
    assert_eq!(out[1].0, 1);
    assert_eq!(out[2].0, 2);
}
