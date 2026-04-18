//! Requirement DSL-085: `proposer_inclusion_reward(base) =
//! base * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR -
//! PROPOSER_WEIGHT) = base * 8 / 56`.
//!
//! Traces to: docs/resources/SPEC.md §8.4, §2.3, §22.9.
//!
//! # Test matrix (maps to DSL-085 Test Plan)
//!
//!   1. `test_dsl_085_formula_base_56` — base=56 → 8 (exact)
//!   2. `test_dsl_085_base_zero_zero` — base=0 → 0
//!   3. `test_dsl_085_round_integer` — base=100 → 14 (floor
//!      of 800/56 ≈ 14.28)
//!   4. `test_dsl_085_saturation` — base=u64::MAX → no panic

use dig_slashing::{PROPOSER_WEIGHT, WEIGHT_DENOMINATOR, proposer_inclusion_reward};

/// DSL-085 row 1: base=56 → 8. Exact integer math:
/// `56 * 8 / 56 = 8`.
#[test]
fn test_dsl_085_formula_base_56() {
    assert_eq!(proposer_inclusion_reward(56), 8);
    assert_eq!(PROPOSER_WEIGHT, 8);
    assert_eq!(WEIGHT_DENOMINATOR - PROPOSER_WEIGHT, 56);
}

/// DSL-085 row 2: base=0 → 0.
#[test]
fn test_dsl_085_base_zero_zero() {
    assert_eq!(proposer_inclusion_reward(0), 0);
}

/// DSL-085 row 3: base=100 → 100 * 8 / 56 = 800 / 56 = 14
/// (integer truncation).
#[test]
fn test_dsl_085_round_integer() {
    assert_eq!(proposer_inclusion_reward(100), 14);
}

/// DSL-085 row 4: base=u64::MAX does not panic. Saturating
/// multiplication caps the intermediate; division by 56
/// produces a deterministic answer.
#[test]
fn test_dsl_085_saturation() {
    // Saturating_mul → u64::MAX, then /56.
    let r = proposer_inclusion_reward(u64::MAX);
    assert_eq!(r, u64::MAX / 56);
    assert!(r > 0);
}
