//! Requirement DSL-086: `WEIGHT_DENOMINATOR == 64` and the
//! four assigned weights sum to 62 — the 2 missing units
//! correspond to Ethereum Altair's `SYNC_REWARD_WEIGHT` slot
//! which DIG does NOT ship (no sync committee).
//!
//! Traces to: docs/resources/SPEC.md §2.3, §22.9.
//!
//! # Role
//!
//! Constant-sanity test that locks the weight-table shape.
//! Prevents accidental rebalancing — any change to an
//! individual weight MUST update the sum assertion here,
//! which surfaces the change in review.
//!
//! # Test matrix (maps to DSL-086 Test Plan)
//!
//!   1. `test_dsl_086_denominator_64` — `WEIGHT_DENOMINATOR == 64`
//!   2. `test_dsl_086_weights_sum_62` — sum of the 4 assigned
//!      weights equals 62 (14+26+14+8)

use dig_slashing::{
    PROPOSER_WEIGHT, TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT,
    WEIGHT_DENOMINATOR,
};

/// DSL-086 row 1: `WEIGHT_DENOMINATOR == 64`. Matches Ethereum
/// Altair even though DIG omits the sync-committee slot — the
/// denominator is shared, the numerator just sums to less.
#[test]
fn test_dsl_086_denominator_64() {
    assert_eq!(WEIGHT_DENOMINATOR, 64);
}

/// DSL-086 row 2: four assigned weights sum to 62. The missing
/// 2 units would have gone to Ethereum's `SYNC_REWARD_WEIGHT`.
/// DIG explicitly reserves them rather than redistributing to
/// keep the formula compatibility window open for future sync-
/// committee-style features.
#[test]
fn test_dsl_086_weights_sum_62() {
    let sum = TIMELY_SOURCE_WEIGHT + TIMELY_TARGET_WEIGHT + TIMELY_HEAD_WEIGHT + PROPOSER_WEIGHT;
    assert_eq!(sum, 62);
    assert_eq!(
        WEIGHT_DENOMINATOR - sum,
        2,
        "2-unit gap preserved for future sync-committee slot",
    );

    // Individual assignments documented so any drift is
    // surfaced in a diff.
    assert_eq!(TIMELY_SOURCE_WEIGHT, 14);
    assert_eq!(TIMELY_TARGET_WEIGHT, 26);
    assert_eq!(TIMELY_HEAD_WEIGHT, 14);
    assert_eq!(PROPOSER_WEIGHT, 8);
}
