//! Requirement DSL-093: `InactivityScoreTracker::resize_for`
//! grows / shrinks the score vector. New slots initialise to 0;
//! existing entries preserved; trailing entries dropped on
//! shrink; same-size → no-op.
//!
//! Traces to: docs/resources/SPEC.md §9.2, §10, §22.10.
//!
//! # Test matrix (maps to DSL-093 Test Plan)
//!
//!   1. `test_dsl_093_grow_new_zero` — size 5 → 10 adds 5
//!      zero entries
//!   2. `test_dsl_093_existing_unchanged` — pre-populated
//!      scores survive grow
//!   3. `test_dsl_093_shrink_truncates` — 10 → 5 drops trailing
//!      entries; length = 5
//!   4. `test_dsl_093_noop_same_size` — resize to current size
//!      is a no-op

use dig_slashing::InactivityScoreTracker;

/// DSL-093 row 1: grow adds zero-initialised trailing slots.
#[test]
fn test_dsl_093_grow_new_zero() {
    let mut scores = InactivityScoreTracker::new(5);
    assert_eq!(scores.validator_count(), 5);

    scores.resize_for(10);
    assert_eq!(scores.validator_count(), 10);
    // All 10 entries should be 0 since we started fresh.
    for idx in 0u32..10 {
        assert_eq!(scores.score(idx), Some(0));
    }
}

/// DSL-093 row 2: pre-populated entries survive a grow.
#[test]
fn test_dsl_093_existing_unchanged() {
    let mut scores = InactivityScoreTracker::new(3);
    scores.set_score(0, 42);
    scores.set_score(1, 100);
    scores.set_score(2, 7);

    scores.resize_for(6);

    assert_eq!(scores.score(0), Some(42));
    assert_eq!(scores.score(1), Some(100));
    assert_eq!(scores.score(2), Some(7));
    // New slots initialise to 0.
    assert_eq!(scores.score(3), Some(0));
    assert_eq!(scores.score(4), Some(0));
    assert_eq!(scores.score(5), Some(0));
}

/// DSL-093 row 3: shrink drops trailing entries. Length matches
/// the new `validator_count`.
#[test]
fn test_dsl_093_shrink_truncates() {
    let mut scores = InactivityScoreTracker::new(10);
    for idx in 0u32..10 {
        scores.set_score(idx, u64::from(idx + 1));
    }

    scores.resize_for(5);
    assert_eq!(scores.validator_count(), 5);

    // Preserved entries still at their original values.
    for idx in 0u32..5 {
        assert_eq!(scores.score(idx), Some(u64::from(idx + 1)));
    }
    // Indices beyond the new len are out of range.
    assert!(scores.score(5).is_none());
    assert!(scores.score(9).is_none());
}

/// DSL-093 row 4: resize to the same length is a no-op on
/// existing data.
#[test]
fn test_dsl_093_noop_same_size() {
    let mut scores = InactivityScoreTracker::new(4);
    scores.set_score(0, 11);
    scores.set_score(1, 22);
    scores.set_score(2, 33);
    scores.set_score(3, 44);

    scores.resize_for(4);
    assert_eq!(scores.validator_count(), 4);
    assert_eq!(scores.score(0), Some(11));
    assert_eq!(scores.score(1), Some(22));
    assert_eq!(scores.score(2), Some(33));
    assert_eq!(scores.score(3), Some(44));
}
