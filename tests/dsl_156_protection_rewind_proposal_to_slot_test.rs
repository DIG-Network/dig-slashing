//! Requirement DSL-156: `SlashingProtection::rewind_proposal_to_slot`
//! lowers `last_proposed_slot` to at most `new_tip_slot`.
//!
//! Traces to: docs/resources/SPEC.md §14.3.
//!
//! # Role
//!
//! Companion to DSL-098 (`rewind_attestation_to_epoch`). Called by:
//!
//!   - DSL-099 `reconcile_with_chain_tip` — composes this with the
//!     attestation-rewind under one entry point.
//!   - DSL-130 `rewind_all_on_reorg` — triggered on global fork-
//!     choice reorg.
//!
//! # Predicate
//!
//! ```text
//!   if last_proposed_slot > new_tip_slot → last_proposed_slot = new_tip_slot
//!   else                                 → no-op
//! ```
//!
//! Strict `>` so a rewind to the exact current value is a no-op.
//! Critical: `last_proposed_slot` MUST NEVER be RAISED by a
//! rewind — raising would weaken the slashing-protection guard
//! (`check_proposal_slot` would suddenly allow re-signing old
//! slots), violating DSL-094's monotonic safety property.
//!
//! # Test matrix (maps to DSL-156 Test Plan)
//!
//!   1. `test_dsl_156_higher_slot_lowered` — last=20, rewind(10) →
//!      last=10. Positive case: rewind actually fires.
//!   2. `test_dsl_156_lower_unchanged` — last=5, rewind(10) →
//!      last=5. Rewind MUST NOT raise (DSL-094 safety).
//!   3. `test_dsl_156_equal_unchanged` — last=10, rewind(10) →
//!      last=10. Boundary: strict `>` means equal is no-op.
//!   4. `test_dsl_156_idempotent` — repeated calls with same tip
//!      leave state unchanged after first call.

use dig_slashing::SlashingProtection;

/// DSL-156 row 1: `last > new_tip` → lowered to `new_tip`.
///
/// Exercises the primary rewind path: a reorged chain tip lower
/// than the validator's recorded last-proposed slot. Post-rewind,
/// `check_proposal_slot(new_tip)` still returns false (strict
/// `>` predicate in DSL-094), and `check_proposal_slot(new_tip+1)`
/// returns true — proving the guard was genuinely loosened to
/// match the rewound chain.
#[test]
fn test_dsl_156_higher_slot_lowered() {
    let mut p = SlashingProtection::new();
    p.record_proposal(20);
    assert_eq!(p.last_proposed_slot(), 20);

    p.rewind_proposal_to_slot(10);
    assert_eq!(p.last_proposed_slot(), 10, "20 > 10 → rewound to 10");

    // Post-rewind, slot 11 is now signable (pre-rewind it was not).
    assert!(
        p.check_proposal_slot(11),
        "DSL-094 guard tracks the rewound slot",
    );
    assert!(!p.check_proposal_slot(10), "strict `>` at boundary");
}

/// DSL-156 row 2: `last < new_tip` → unchanged (NEVER raise).
///
/// The critical safety invariant: rewind MUST NOT push
/// `last_proposed_slot` upward. A higher value would silently
/// allow re-signing of slots between the old value and the new
/// tip, which is the canonical proposer-equivocation attack. Pin
/// the non-raising behavior so any refactor that flips the
/// comparison direction breaks this test loudly.
#[test]
fn test_dsl_156_lower_unchanged() {
    let mut p = SlashingProtection::new();
    p.record_proposal(5);

    p.rewind_proposal_to_slot(10);
    assert_eq!(
        p.last_proposed_slot(),
        5,
        "5 < 10 → unchanged; rewind MUST NEVER raise last_proposed_slot",
    );
}

/// DSL-156 row 3: `last == new_tip` → unchanged.
///
/// Boundary condition for the strict `>` guard. When the reorged
/// chain tip exactly matches the validator's last-proposed slot,
/// no rewind is necessary — the stored slot is already consistent
/// with the tip. Pinning this keeps the method from accidentally
/// using non-strict `>=` which would be observationally identical
/// here but would break the DSL-156 idempotence contract below.
#[test]
fn test_dsl_156_equal_unchanged() {
    let mut p = SlashingProtection::new();
    p.record_proposal(10);

    p.rewind_proposal_to_slot(10);
    assert_eq!(
        p.last_proposed_slot(),
        10,
        "equal slot is a no-op (strict `>` predicate)",
    );
}

/// DSL-156 row 4: idempotence.
///
/// Calling `rewind_proposal_to_slot(tip)` twice produces the same
/// state as calling it once. Exercises both paths:
///   (a) lower-path: rewind fires on first call, second call is
///       no-op because the slot is already at tip.
///   (b) no-op path: first call is no-op, second call also no-op.
/// The DSL-130 orchestrator may call `reconcile_with_chain_tip`
/// multiple times per reorg; idempotence means the caller does
/// not have to dedup.
#[test]
fn test_dsl_156_idempotent() {
    // Path (a): rewind fires then stabilises.
    let mut p = SlashingProtection::new();
    p.record_proposal(20);
    p.rewind_proposal_to_slot(10);
    assert_eq!(p.last_proposed_slot(), 10);
    p.rewind_proposal_to_slot(10);
    assert_eq!(
        p.last_proposed_slot(),
        10,
        "second call at same tip is no-op",
    );
    p.rewind_proposal_to_slot(10);
    assert_eq!(
        p.last_proposed_slot(),
        10,
        "third call at same tip is still no-op",
    );

    // Path (b): no-op-then-no-op when last already below tip.
    let mut q = SlashingProtection::new();
    q.record_proposal(5);
    q.rewind_proposal_to_slot(100);
    q.rewind_proposal_to_slot(100);
    assert_eq!(q.last_proposed_slot(), 5, "idempotent no-op path");
}
