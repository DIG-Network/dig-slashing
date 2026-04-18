//! Requirement DSL-094: `SlashingProtection::check_proposal_slot`
//! returns `true` iff `slot > self.last_proposed_slot`. After
//! `record_proposal(n)`, same or lower slot fails.
//!
//! Traces to: docs/resources/SPEC.md §14.1, §22.11.
//!
//! # Role
//!
//! Opens Phase 5 Protection. Self-slashing guard for the
//! proposer-equivocation case: once a validator signs at slot
//! N, they must never sign another block at slot ≤ N.
//!
//! # Test matrix (maps to DSL-094 Test Plan)
//!
//!   1. `test_dsl_094_first_ok` — default state, check(10) →
//!      true
//!   2. `test_dsl_094_same_after_record_false` — record(10),
//!      check(10) → false (equivocation self-check)
//!   3. `test_dsl_094_lower_after_record_false` — record(10),
//!      check(9) → false
//!   4. `test_dsl_094_higher_after_record_true` — record(10),
//!      check(11) → true

use dig_slashing::SlashingProtection;

/// DSL-094 row 1: fresh state allows any slot > 0.
#[test]
fn test_dsl_094_first_ok() {
    let p = SlashingProtection::new();
    assert!(p.check_proposal_slot(10));
    assert!(p.check_proposal_slot(1));
    // slot = 0 fails because 0 > 0 is false.
    assert!(!p.check_proposal_slot(0));
}

/// DSL-094 row 2: same slot after record → false. The
/// canonical proposer-equivocation self-check — signing twice
/// at the same slot is what DSL-013 slashes.
#[test]
fn test_dsl_094_same_after_record_false() {
    let mut p = SlashingProtection::new();
    p.record_proposal(10);
    assert!(!p.check_proposal_slot(10));
    assert_eq!(p.last_proposed_slot(), 10);
}

/// DSL-094 row 3: lower slot after record → false. Prevents a
/// reorg + restart from tricking the validator into signing a
/// slot they already signed earlier.
#[test]
fn test_dsl_094_lower_after_record_false() {
    let mut p = SlashingProtection::new();
    p.record_proposal(10);
    assert!(!p.check_proposal_slot(9));
    assert!(!p.check_proposal_slot(0));
    assert!(!p.check_proposal_slot(5));
}

/// DSL-094 row 4: strictly greater slot after record → true.
/// Monotonic advance is the allowed case.
#[test]
fn test_dsl_094_higher_after_record_true() {
    let mut p = SlashingProtection::new();
    p.record_proposal(10);
    assert!(p.check_proposal_slot(11));
    assert!(p.check_proposal_slot(100));

    // Chained: record higher, then check around the new
    // boundary.
    p.record_proposal(11);
    assert!(!p.check_proposal_slot(11));
    assert!(p.check_proposal_slot(12));
}
