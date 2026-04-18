//! Requirement DSL-148: `SlashingManager::new(current_epoch)`
//! constructs an empty manager at the given epoch;
//! `set_epoch(e)` updates current_epoch (caller-enforced
//! forward progression).
//!
//! Traces to: docs/resources/SPEC.md §7.2.
//!
//! # Role
//!
//! Baseline constructor + epoch setter. Distinguishes from
//! DSL-128 `SlashingSystem::genesis` which wraps this plus
//! the participation + inactivity trackers. DSL-148 is the
//! standalone manager entry point — tests that exercise only
//! the manager (no trackers) use this.
//!
//! # Test matrix (maps to DSL-148 Test Plan + acceptance)
//!
//!   1. `test_dsl_148_new_empty_state` — new(0) has empty
//!      processed + empty book + empty correlation window
//!   2. `test_dsl_148_new_preserves_epoch` — new(100) →
//!      `current_epoch() == 100`
//!   3. `test_dsl_148_set_epoch_updates` — `set_epoch(5)` →
//!      current_epoch flips
//!   4. `test_dsl_148_set_epoch_monotonic_agnostic` — set_epoch
//!      allows moving backwards (caller enforces monotonicity)
//!   5. `test_dsl_148_default_is_new_zero` — `Default::default()`
//!      equivalent to `new(0)`

use dig_protocol::Bytes32;
use dig_slashing::SlashingManager;

/// DSL-148 row 1: fresh manager has empty internal state.
#[test]
fn test_dsl_148_new_empty_state() {
    let m = SlashingManager::new(0);
    assert_eq!(m.current_epoch(), 0);
    assert_eq!(m.book().len(), 0);
    assert!(m.book().is_empty());
    // is_processed on any probe hash returns false.
    let probe = Bytes32::new([0x11u8; 32]);
    assert!(!m.is_processed(&probe));
    // slashed_in_window rows absent for any (epoch, idx).
    assert!(!m.is_slashed_in_window(0, 0));
    assert!(!m.is_slashed_in_window(100, 7));
}

/// DSL-148 row 2: non-zero genesis epoch preserved.
#[test]
fn test_dsl_148_new_preserves_epoch() {
    let m = SlashingManager::new(100);
    assert_eq!(m.current_epoch(), 100);
    // Internal state still empty.
    assert_eq!(m.book().len(), 0);

    // Arbitrary non-zero values round-trip.
    for epoch in [1u64, 42, 1_234, u64::MAX] {
        let m = SlashingManager::new(epoch);
        assert_eq!(m.current_epoch(), epoch);
    }
}

/// DSL-148 row 3: set_epoch flips the internal counter.
#[test]
fn test_dsl_148_set_epoch_updates() {
    let mut m = SlashingManager::new(0);
    m.set_epoch(5);
    assert_eq!(m.current_epoch(), 5);

    m.set_epoch(100);
    assert_eq!(m.current_epoch(), 100);
}

/// DSL-148 row 4: set_epoch is monotonic-agnostic. The trait
/// does NOT enforce forward-only; callers (DSL-127
/// run_epoch_boundary + DSL-130 rewind_all_on_reorg) enforce
/// directionality at their own layer. Reorg-driven rewinds
/// depend on this flexibility — DSL-130 calls set_epoch with
/// new_tip_epoch which may be BEFORE current_epoch.
#[test]
fn test_dsl_148_set_epoch_monotonic_agnostic() {
    let mut m = SlashingManager::new(100);

    // Forward moves.
    m.set_epoch(101);
    assert_eq!(m.current_epoch(), 101);

    // Backward moves allowed (reorg scenario).
    m.set_epoch(50);
    assert_eq!(m.current_epoch(), 50, "backward move permitted");

    // Zero move.
    m.set_epoch(50);
    assert_eq!(m.current_epoch(), 50);
}

/// DSL-148 row 5: `Default::default()` equivalent to `new(0)`.
/// Downstream consumers occasionally instantiate via Default
/// for test fixtures; pin the equivalence so a future Default
/// refactor cannot drift from the DSL-128-spec genesis shape.
#[test]
fn test_dsl_148_default_is_new_zero() {
    let defaulted = SlashingManager::default();
    assert_eq!(defaulted.current_epoch(), 0);
    assert_eq!(defaulted.book().len(), 0);
    assert!(!defaulted.is_processed(&Bytes32::new([0; 32])));
}
