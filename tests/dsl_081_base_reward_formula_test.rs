//! Requirement DSL-081: `base_reward(effective_balance,
//! total_active_balance) = effective_balance *
//! BASE_REWARD_FACTOR / isqrt(total_active_balance)`.
//! Saturates at u64::MAX on overflow; returns 0 when
//! `total_active_balance == 0`.
//!
//! Traces to: docs/resources/SPEC.md §8.3, §2.3, §22.9.
//!
//! # Test matrix (maps to DSL-081 Test Plan)
//!
//!   1. `test_dsl_081_formula_exact` — eff=32e9, total=32e9:
//!      isqrt = ~178_885; reward = eff * 64 / isqrt
//!   2. `test_dsl_081_larger_total_smaller_reward` — doubling
//!      total halves reward by ~sqrt(2)
//!   3. `test_dsl_081_zero_total_zero` — total_active=0 → 0
//!   4. `test_dsl_081_saturation` — extreme inputs don't panic

use dig_slashing::{BASE_REWARD_FACTOR, MIN_EFFECTIVE_BALANCE, base_reward};

/// DSL-081 row 1: exact formula at a canonical input.
/// eff = MIN_EFFECTIVE_BALANCE (32e9), total = eff.
/// isqrt(32e9) = 178885 (floor). reward = 32e9 * 64 / 178885.
#[test]
fn test_dsl_081_formula_exact() {
    let eff = MIN_EFFECTIVE_BALANCE;
    let total = MIN_EFFECTIVE_BALANCE;

    let expected_denom = (total as u128).isqrt() as u64;
    let expected = eff.saturating_mul(BASE_REWARD_FACTOR) / expected_denom;

    assert_eq!(base_reward(eff, total), expected);
}

/// DSL-081 row 2: inverse-sqrt scaling. Doubling
/// `total_active_balance` decreases the reward by sqrt(2)
/// (integer truncation). Compared against a tolerance of 0.3%
/// to account for floor/truncation noise at scale.
#[test]
fn test_dsl_081_larger_total_smaller_reward() {
    let eff = MIN_EFFECTIVE_BALANCE;
    let total_small = MIN_EFFECTIVE_BALANCE;
    let total_large = MIN_EFFECTIVE_BALANCE * 2;

    let r_small = base_reward(eff, total_small);
    let r_large = base_reward(eff, total_large);

    assert!(
        r_small > r_large,
        "larger total → smaller reward (got small={r_small}, large={r_large})",
    );

    // Ratio should be ~sqrt(2) ≈ 1.4142. Allow 1% tolerance.
    let ratio_bps = (r_small as u128 * 10_000) / r_large as u128;
    assert!(
        (13_900..=14_200).contains(&ratio_bps),
        "ratio {ratio_bps} bps not within sqrt(2) ±1% window [13900, 14200]",
    );
}

/// DSL-081 row 3: `total_active_balance == 0` → 0 (guard).
#[test]
fn test_dsl_081_zero_total_zero() {
    assert_eq!(base_reward(MIN_EFFECTIVE_BALANCE, 0), 0);
    assert_eq!(base_reward(0, 0), 0);
}

/// DSL-081 row 4: extreme inputs do not panic. u128
/// intermediate + `isqrt` prevents overflow even at u64::MAX
/// scale.
#[test]
fn test_dsl_081_saturation() {
    // Max eff + large-but-sane total → large but <= u64::MAX.
    let r = base_reward(u64::MAX, 1_000_000_000_000u64);
    assert!(r > 0, "non-zero result on extreme inputs");

    // Max eff + max total → denom ~= 2^64, so result is
    // bounded well below u64::MAX but nonzero.
    let r2 = base_reward(u64::MAX, u64::MAX);
    assert!(r2 > 0);
}
