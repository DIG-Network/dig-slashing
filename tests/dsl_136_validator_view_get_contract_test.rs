//! Requirement DSL-136: `ValidatorView::get(idx)` returns
//! `Some(&dyn ValidatorEntry)` for `idx < len()`, `None` for
//! out-of-range indices. `get_mut` mirrors with a mutable
//! borrow; mutations through it are visible on the next
//! `get` call.
//!
//! Traces to: docs/resources/SPEC.md §15.1.
//!
//! # Role
//!
//! Every path that consults validator state — DSL-013
//! verifier, DSL-022 slash_absolute, DSL-064 revert, DSL-129
//! reorg rewind — goes through `ValidatorView`. This DSL pins
//! the boundary behaviour so a buggy impl returning `Some`
//! past `len()` cannot create phantom validators.
//!
//! # Test matrix (maps to DSL-136 Test Plan + acceptance)
//!
//!   1. `test_dsl_136_get_live` — every index in `0..len`
//!      returns Some
//!   2. `test_dsl_136_get_out_of_range_none` — `len`, `len+1`,
//!      `u32::MAX` all return None
//!   3. `test_dsl_136_get_mut_observable` — `get_mut` +
//!      mutation surfaces on the next `get`
//!   4. `test_dsl_136_len_consistent` — `len` matches the
//!      number of constructable indices
//!   5. `test_dsl_136_empty_set_all_none` — a zero-length set
//!      returns None for every index

use std::cell::RefCell;

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::{ValidatorEntry, ValidatorView};

struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    stake: RefCell<u64>,
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
        *self.stake.borrow()
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
    fn slash_absolute(&mut self, amount: u64, _: u64) -> u64 {
        let mut bal = self.stake.borrow_mut();
        let actual = amount.min(*bal);
        *bal -= actual;
        *self.is_slashed.borrow_mut() = true;
        actual
    }
    fn credit_stake(&mut self, amount: u64) -> u64 {
        *self.stake.borrow_mut() += amount;
        amount
    }
    fn restore_status(&mut self) -> bool {
        let changed = *self.is_slashed.borrow();
        *self.is_slashed.borrow_mut() = false;
        changed
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct MockValidatorSet {
    entries: Vec<MockValidator>,
}
impl MockValidatorSet {
    fn with_count(n: usize) -> Self {
        Self {
            entries: (0..n)
                .map(|_| MockValidator {
                    pk: PublicKey::default(),
                    ph: Bytes32::new([0u8; 32]),
                    stake: RefCell::new(32_000_000_000),
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

/// DSL-136 row 1: live indices return Some.
#[test]
fn test_dsl_136_get_live() {
    let vs = MockValidatorSet::with_count(5);
    for idx in 0u32..5 {
        assert!(vs.get(idx).is_some(), "idx {idx} must be Some");
    }
}

/// DSL-136 row 2: out-of-range indices return None.
#[test]
fn test_dsl_136_get_out_of_range_none() {
    let vs = MockValidatorSet::with_count(5);
    // Immediately past len.
    assert!(vs.get(5).is_none(), "len boundary None");
    assert!(vs.get(6).is_none());
    assert!(vs.get(100).is_none());
    // u32::MAX stress.
    assert!(vs.get(u32::MAX).is_none());
}

/// DSL-136 row 3: `get_mut` allows mutation visible to a
/// subsequent `get`. Chain: get_mut → credit_stake → get →
/// observe the increased balance. Proves the trait surface
/// doesn't accidentally clone or materialise read-only copies.
#[test]
fn test_dsl_136_get_mut_observable() {
    let mut vs = MockValidatorSet::with_count(3);
    let before = vs.get(1).unwrap().effective_balance();

    let m = vs.get_mut(1).expect("mut borrow");
    m.credit_stake(1_000);

    let after = vs.get(1).unwrap().effective_balance();
    assert_eq!(
        after,
        before + 1_000,
        "mutation through get_mut must be observable via get",
    );

    // get_mut on out-of-range is None (symmetric with `get`).
    assert!(vs.get_mut(100).is_none());
}

/// DSL-136 row 4: `len` matches the number of constructable
/// indices.
#[test]
fn test_dsl_136_len_consistent() {
    for n in [0usize, 1, 5, 100] {
        let vs = MockValidatorSet::with_count(n);
        assert_eq!(vs.len(), n);
        // Exactly `n` valid indices.
        if n > 0 {
            assert!(vs.get((n - 1) as u32).is_some());
            assert!(vs.get(n as u32).is_none());
        }
    }
}

/// DSL-136 bonus: empty set is a hard None for every index.
/// Bootstrap pre-activation scenarios construct a zero-length
/// ValidatorView; consumers must not crash on the degenerate
/// shape.
#[test]
fn test_dsl_136_empty_set_all_none() {
    let vs = MockValidatorSet::with_count(0);
    assert_eq!(vs.len(), 0);
    for idx in [0u32, 1, 100, u32::MAX] {
        assert!(vs.get(idx).is_none(), "idx {idx} must be None on empty set");
    }
}
