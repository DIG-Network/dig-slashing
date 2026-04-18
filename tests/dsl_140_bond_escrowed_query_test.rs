//! Requirement DSL-140: `BondEscrow::escrowed(idx, tag)` is the
//! read-side query.
//!
//!   - After lock(idx, amount, tag) → returns `amount`.
//!   - After release / forfeit → returns 0.
//!   - Unknown `(idx, tag)` → returns 0 (no panic).
//!   - Read-only (never mutates).
//!
//! Traces to: docs/resources/SPEC.md §12.3, §15.4.
//!
//! # Role
//!
//! The ONLY read-side surface on BondEscrow. Consumers:
//!   - DSL-023 submit_evidence inspects the escrow to verify a
//!     bond was locked.
//!   - Adjudicator DSL-068/071 inspects escrow pre-forfeit to
//!     compute the winner-award split.
//!   - Tests (including DSL-121..123) use it as the observable
//!     for the lock/release/forfeit state transitions.
//!
//! # Test matrix (maps to DSL-140 Test Plan + acceptance)
//!
//!   1. `test_dsl_140_after_lock_returns_amount` — lock(500)
//!      then escrowed → 500
//!   2. `test_dsl_140_after_release_zero` — release drops to 0
//!   3. `test_dsl_140_after_forfeit_zero` — forfeit drops to 0
//!      (parallel path to release)
//!   4. `test_dsl_140_unknown_tag_zero` — never-locked pairing
//!      returns 0, no panic
//!   5. `test_dsl_140_read_only` — repeated escrowed calls yield
//!      the same value, no state drift

use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::{BondError, BondEscrow, BondTag};

/// Minimal reference BondEscrow matching DSL-121..123 contract.
struct MockBondEscrow {
    free: HashMap<u32, u64>,
    escrow: HashMap<(u32, BondTag), u64>,
}
impl MockBondEscrow {
    fn new() -> Self {
        Self {
            free: HashMap::new(),
            escrow: HashMap::new(),
        }
    }
    fn credit(&mut self, idx: u32, amount: u64) {
        *self.free.entry(idx).or_insert(0) += amount;
    }
}
impl BondEscrow for MockBondEscrow {
    fn lock(&mut self, idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError> {
        if self.escrow.contains_key(&(idx, tag)) {
            return Err(BondError::DoubleLock { tag });
        }
        let have = *self.free.get(&idx).unwrap_or(&0);
        if have < amount {
            return Err(BondError::InsufficientBalance { have, need: amount });
        }
        *self.free.get_mut(&idx).unwrap() -= amount;
        self.escrow.insert((idx, tag), amount);
        Ok(())
    }
    fn release(&mut self, idx: u32, _: u64, tag: BondTag) -> Result<(), BondError> {
        match self.escrow.remove(&(idx, tag)) {
            Some(amt) => {
                *self.free.entry(idx).or_insert(0) += amt;
                Ok(())
            }
            None => Err(BondError::TagNotFound { tag }),
        }
    }
    fn forfeit(&mut self, idx: u32, _: u64, tag: BondTag) -> Result<u64, BondError> {
        self.escrow
            .remove(&(idx, tag))
            .ok_or(BondError::TagNotFound { tag })
    }
    fn escrowed(&self, idx: u32, tag: BondTag) -> u64 {
        *self.escrow.get(&(idx, tag)).unwrap_or(&0)
    }
}

/// DSL-140 row 1: post-lock, escrowed returns the locked amount.
#[test]
fn test_dsl_140_after_lock_returns_amount() {
    let mut e = MockBondEscrow::new();
    e.credit(7, 10_000);
    let tag = BondTag::Reporter(Bytes32::new([0x11u8; 32]));

    e.lock(7, 500, tag).unwrap();
    assert_eq!(e.escrowed(7, tag), 500);
}

/// DSL-140 row 2: release drops escrowed to 0.
#[test]
fn test_dsl_140_after_release_zero() {
    let mut e = MockBondEscrow::new();
    e.credit(7, 10_000);
    let tag = BondTag::Reporter(Bytes32::new([0x22u8; 32]));

    e.lock(7, 500, tag).unwrap();
    e.release(7, 500, tag).unwrap();
    assert_eq!(e.escrowed(7, tag), 0);
}

/// DSL-140 row 3: forfeit drops escrowed to 0 (parallel to
/// release). Distinguishes that `escrowed` zeros on EITHER
/// drain path, not just release.
#[test]
fn test_dsl_140_after_forfeit_zero() {
    let mut e = MockBondEscrow::new();
    e.credit(7, 10_000);
    let tag = BondTag::Reporter(Bytes32::new([0x33u8; 32]));

    e.lock(7, 500, tag).unwrap();
    let _ = e.forfeit(7, 500, tag).unwrap();
    assert_eq!(e.escrowed(7, tag), 0);
}

/// DSL-140 row 4: unknown (idx, tag) pairing returns 0, no
/// panic. Both for never-locked tags AND for never-seen
/// validator indices.
#[test]
fn test_dsl_140_unknown_tag_zero() {
    let e = MockBondEscrow::new();
    // Never-locked tag + never-seen validator idx.
    let tag = BondTag::Reporter(Bytes32::new([0x44u8; 32]));
    assert_eq!(e.escrowed(7, tag), 0);
    assert_eq!(e.escrowed(u32::MAX, tag), 0);

    // Different tag on a principal that has OTHER locks → 0.
    let mut e = MockBondEscrow::new();
    e.credit(7, 10_000);
    let tag_a = BondTag::Reporter(Bytes32::new([0x55u8; 32]));
    e.lock(7, 500, tag_a).unwrap();
    // Ask about an un-locked appellant tag on same principal.
    let tag_b = BondTag::Appellant(Bytes32::new([0x55u8; 32]));
    assert_eq!(e.escrowed(7, tag_b), 0, "different tag → 0");
    // But the original locked tag still reports correctly.
    assert_eq!(e.escrowed(7, tag_a), 500);
}

/// DSL-140 row 5: read-only invariance. Repeated `escrowed`
/// calls return the same value, never drift. Guards against a
/// buggy impl that advances an internal cursor.
#[test]
fn test_dsl_140_read_only() {
    let mut e = MockBondEscrow::new();
    e.credit(7, 10_000);
    let tag = BondTag::Reporter(Bytes32::new([0x66u8; 32]));
    e.lock(7, 500, tag).unwrap();

    for _ in 0..10 {
        assert_eq!(e.escrowed(7, tag), 500);
    }
}
