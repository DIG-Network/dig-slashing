//! Requirement DSL-091: `InactivityScoreTracker::epoch_penalties`
//! returns an empty vec whenever `in_finality_stall == false`.
//! Inactivity penalties debit ONLY during a stall — outside of
//! one, scores merely decay (DSL-090).
//!
//! Traces to: docs/resources/SPEC.md §9.3, §22.10.
//!
//! # Test matrix (maps to DSL-091 Test Plan)
//!
//!   1. `test_dsl_091_no_stall_empty` — stall=false, mixed
//!      scores [100, 200, 0] → `vec![]`
//!   2. `test_dsl_091_zero_scores_no_stall_empty` — stall=false,
//!      all zero → `vec![]`

use dig_slashing::{EffectiveBalanceView, InactivityScoreTracker, MIN_EFFECTIVE_BALANCE};

struct FlatBalances;
impl EffectiveBalanceView for FlatBalances {
    fn get(&self, _: u32) -> u64 {
        MIN_EFFECTIVE_BALANCE
    }
    fn total_active(&self) -> u64 {
        MIN_EFFECTIVE_BALANCE * 3
    }
}

/// DSL-091 row 1: stall=false with non-zero scores → empty vec.
#[test]
fn test_dsl_091_no_stall_empty() {
    let mut scores = InactivityScoreTracker::new(3);
    scores.set_score(0, 100);
    scores.set_score(1, 200);
    scores.set_score(2, 0);

    let out = scores.epoch_penalties(&FlatBalances, false);
    assert!(out.is_empty(), "no-stall → empty vec regardless of scores");
}

/// DSL-091 row 2: stall=false with all zero scores → empty vec.
/// Negative control — the empty-vec behaviour is driven by the
/// stall flag, not the score values.
#[test]
fn test_dsl_091_zero_scores_no_stall_empty() {
    let scores = InactivityScoreTracker::new(5);

    let out = scores.epoch_penalties(&FlatBalances, false);
    assert!(out.is_empty());
}
