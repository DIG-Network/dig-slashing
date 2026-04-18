//! Requirement DSL-087: `in_finality_stall(current_epoch,
//! finalized_epoch)` returns `true` iff the gap exceeds
//! `MIN_EPOCHS_TO_INACTIVITY_PENALTY` (= 4). Strict
//! greater-than; saturating subtraction handles the
//! post-reorg `current < finalized` transient.
//!
//! Traces to: docs/resources/SPEC.md §9.1, §2.4, §22.10.
//!
//! # Test matrix (maps to DSL-087 Test Plan)
//!
//!   1. `test_dsl_087_gap_5_stall` — gap=5 → true
//!   2. `test_dsl_087_gap_4_no_stall` — gap=4 → false (boundary)
//!   3. `test_dsl_087_equal_no_stall` — gap=0 → false
//!   4. `test_dsl_087_current_less_saturating` — current<final
//!      → false (no panic)

use dig_slashing::{MIN_EPOCHS_TO_INACTIVITY_PENALTY, in_finality_stall};

/// DSL-087 row 1: gap=5 → true. Smallest gap exceeding the
/// cap (4).
#[test]
fn test_dsl_087_gap_5_stall() {
    assert_eq!(MIN_EPOCHS_TO_INACTIVITY_PENALTY, 4);
    assert!(in_finality_stall(5, 0));
    assert!(in_finality_stall(100, 95)); // gap=5
}

/// DSL-087 row 2: gap exactly 4 → false. Strict
/// greater-than, so boundary stays in the normal regime.
#[test]
fn test_dsl_087_gap_4_no_stall() {
    assert!(!in_finality_stall(4, 0));
    assert!(!in_finality_stall(100, 96)); // gap=4
}

/// DSL-087 row 3: current == finalized → gap=0 → false.
#[test]
fn test_dsl_087_equal_no_stall() {
    assert!(!in_finality_stall(0, 0));
    assert!(!in_finality_stall(100, 100));
    assert!(!in_finality_stall(1, 0)); // gap=1
    assert!(!in_finality_stall(3, 0)); // gap=3
}

/// DSL-087 row 4: current < finalized (post-reorg transient)
/// → saturating_sub collapses to 0 → false. No panic.
#[test]
fn test_dsl_087_current_less_saturating() {
    assert!(!in_finality_stall(2, 5));
    assert!(!in_finality_stall(0, u64::MAX));
}
