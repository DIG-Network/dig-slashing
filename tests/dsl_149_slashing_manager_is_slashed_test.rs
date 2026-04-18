//! Requirement DSL-149: `SlashingManager::is_slashed(idx,
//! validator_set)` delegates to
//! `ValidatorView::get(idx)?.is_slashed()`. Unknown idx → false.
//! Read-only: no mutation.
//!
//! Traces to: docs/resources/SPEC.md §7.2.
//!
//! # Role
//!
//! Thin convenience wrapper so callers can query slash status
//! without awkwardly chaining `.get(idx).map(...).unwrap_or(false)`
//! themselves. Paired with DSL-136 `ValidatorView::get`
//! out-of-range semantics.
//!
//! # Test matrix (maps to DSL-149 Test Plan + acceptance)
//!
//!   1. `test_dsl_149_slashed_true` — slashed validator → true
//!   2. `test_dsl_149_active_false` — active validator → false
//!   3. `test_dsl_149_unknown_false` — out-of-range → false
//!   4. `test_dsl_149_read_only` — manager + validator_set
//!      unchanged after call

use std::cell::RefCell;

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::{SlashingManager, ValidatorEntry, ValidatorView};

struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    is_slashed: RefCell<bool>,
}
impl ValidatorEntry for MockValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        self.ph
    }
    fn effective_balance(&self) -> u64 {
        32_000_000_000
    }
    fn is_slashed(&self) -> bool {
        *self.is_slashed.borrow()
    }
    fn activation_epoch(&self) -> u64 {
        0
    }
    fn exit_epoch(&self) -> u64 {
        u64::MAX
    }
    fn is_active_at_epoch(&self, _: u64) -> bool {
        true
    }
    fn slash_absolute(&mut self, _: u64, _: u64) -> u64 {
        *self.is_slashed.borrow_mut() = true;
        0
    }
    fn credit_stake(&mut self, _: u64) -> u64 {
        0
    }
    fn restore_status(&mut self) -> bool {
        false
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct MockValidatorSet {
    entries: Vec<MockValidator>,
}
impl MockValidatorSet {
    fn new(n: usize) -> Self {
        Self {
            entries: (0..n)
                .map(|_| MockValidator {
                    pk: PublicKey::default(),
                    ph: Bytes32::new([0u8; 32]),
                    is_slashed: RefCell::new(false),
                })
                .collect(),
        }
    }
}
impl ValidatorView for MockValidatorSet {
    fn get(&self, idx: u32) -> Option<&dyn ValidatorEntry> {
        self.entries
            .get(idx as usize)
            .map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, idx: u32) -> Option<&mut dyn ValidatorEntry> {
        self.entries
            .get_mut(idx as usize)
            .map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// DSL-149 row 1: slashed validator → true.
#[test]
fn test_dsl_149_slashed_true() {
    let m = SlashingManager::new(10);
    let vs = MockValidatorSet::new(3);
    *vs.entries[1].is_slashed.borrow_mut() = true;

    assert!(m.is_slashed(1, &vs));
}

/// DSL-149 row 2: active validator → false.
#[test]
fn test_dsl_149_active_false() {
    let m = SlashingManager::new(10);
    let vs = MockValidatorSet::new(3);
    // All three start active (is_slashed=false).
    for idx in 0u32..3 {
        assert!(!m.is_slashed(idx, &vs));
    }
}

/// DSL-149 row 3: unknown idx → false, no panic.
#[test]
fn test_dsl_149_unknown_false() {
    let m = SlashingManager::new(10);
    let vs = MockValidatorSet::new(3);

    assert!(!m.is_slashed(3, &vs), "len boundary");
    assert!(!m.is_slashed(100, &vs));
    assert!(!m.is_slashed(u32::MAX, &vs));
}

/// DSL-149 row 4: read-only — no side effects on manager or
/// validator set.
#[test]
fn test_dsl_149_read_only() {
    let m = SlashingManager::new(10);
    let vs = MockValidatorSet::new(3);
    *vs.entries[1].is_slashed.borrow_mut() = true;

    let before_slashed = *vs.entries[1].is_slashed.borrow();
    let before_manager_epoch = m.current_epoch();
    let before_book_len = m.book().len();

    // Call is_slashed multiple times.
    for _ in 0..5 {
        let _ = m.is_slashed(1, &vs);
        let _ = m.is_slashed(99, &vs);
    }

    assert_eq!(*vs.entries[1].is_slashed.borrow(), before_slashed);
    assert_eq!(m.current_epoch(), before_manager_epoch);
    assert_eq!(m.book().len(), before_book_len);
}
