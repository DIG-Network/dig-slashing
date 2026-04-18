//! Requirement DSL-121: `BondEscrow::lock` contract.
//!
//!   1. Sufficient stake → `Ok(())` and `escrowed(principal,
//!      tag) == amount`.
//!   2. Insufficient stake → `Err(BondError::InsufficientBalance
//!      { have, need })`.
//!   3. Same `(principal, tag)` locked twice →
//!      `Err(BondError::DoubleLock { tag })`.
//!
//! Traces to: docs/resources/SPEC.md §12.3, §22.14.
//!
//! # Role
//!
//! `dig-slashing` defines the trait surface; the test ships a
//! minimal reference implementation (`MockBondEscrow` below) that
//! pins the three contract branches. Downstream `dig-collateral`
//! or equivalent concrete impls MUST satisfy the same contract —
//! this test doubles as the trait-contract spec.
//!
//! # Test matrix (maps to DSL-121 Test Plan + acceptance)
//!
//!   1. `test_dsl_121_lock_success` — balance covers amount →
//!      Ok + `escrowed == amount`
//!   2. `test_dsl_121_insufficient` — balance < amount →
//!      InsufficientBalance carrying exact `have`, `need`
//!   3. `test_dsl_121_double_lock_rejected` — same tag twice →
//!      DoubleLock carrying the tag

use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::{BondError, BondEscrow, BondTag};

/// Minimal reference `BondEscrow`. Tracks a per-principal free
/// balance plus an `(principal, tag) → amount` escrow map. Matches
/// the SPEC §12.3 semantics precisely — `lock` decrements free
/// balance, inserts into escrow, errors on insufficient balance or
/// pre-existing tag.
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

    fn credit(&mut self, principal: u32, amount: u64) {
        *self.free.entry(principal).or_insert(0) += amount;
    }
}

impl BondEscrow for MockBondEscrow {
    fn lock(&mut self, principal: u32, amount: u64, tag: BondTag) -> Result<(), BondError> {
        // DoubleLock has priority over InsufficientBalance in this
        // impl — tag uniqueness is a structural invariant while
        // balance is a transient state. The manager's DSL-026
        // dedup should prevent DoubleLock in practice; when it
        // fires we want the error that names the structural bug.
        if self.escrow.contains_key(&(principal, tag)) {
            return Err(BondError::DoubleLock { tag });
        }
        let have = *self.free.get(&principal).unwrap_or(&0);
        if have < amount {
            return Err(BondError::InsufficientBalance { have, need: amount });
        }
        *self.free.get_mut(&principal).unwrap() -= amount;
        self.escrow.insert((principal, tag), amount);
        Ok(())
    }

    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        // DSL-121 does not exercise release; out of scope.
        Ok(())
    }

    fn forfeit(&mut self, _: u32, _: u64, _: BondTag) -> Result<u64, BondError> {
        Ok(0)
    }

    fn escrowed(&self, principal: u32, tag: BondTag) -> u64 {
        *self.escrow.get(&(principal, tag)).unwrap_or(&0)
    }
}

/// DSL-121 row 1: sufficient balance → Ok + escrow updated.
#[test]
fn test_dsl_121_lock_success() {
    let mut e = MockBondEscrow::new();
    e.credit(11, 10_000);

    let tag = BondTag::Reporter(Bytes32::new([0x11u8; 32]));
    e.lock(11, 1_000, tag)
        .expect("sufficient balance must admit");

    assert_eq!(e.escrowed(11, tag), 1_000, "escrowed reflects lock");

    // A different tag on the same principal is a distinct slot.
    // Tag uniqueness is per-(principal, tag) not per-principal.
    let tag2 = BondTag::Appellant(Bytes32::new([0x11u8; 32]));
    e.lock(11, 500, tag2).expect("distinct tag must admit");
    assert_eq!(e.escrowed(11, tag2), 500);
    assert_eq!(e.escrowed(11, tag), 1_000, "prior lock preserved");
}

/// DSL-121 row 2: insufficient balance → exact InsufficientBalance
/// with both fields populated. The error is the contract signal
/// the slashing manager uses to surface DSL-028 `BondLockFailed`.
#[test]
fn test_dsl_121_insufficient() {
    let mut e = MockBondEscrow::new();
    e.credit(11, 100);

    let tag = BondTag::Reporter(Bytes32::new([0x22u8; 32]));
    let err = e
        .lock(11, 1_000, tag)
        .expect_err("under-funded principal must reject");

    let BondError::InsufficientBalance { have, need } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(have, 100, "have = principal's free balance");
    assert_eq!(need, 1_000, "need = the amount requested");

    // State unchanged: escrow empty, free balance intact.
    assert_eq!(e.escrowed(11, tag), 0, "failed lock must not touch escrow",);
}

/// DSL-121 row 3: same (principal, tag) twice → DoubleLock. The
/// variant carries the offending tag so adjudicators can log
/// without re-deriving.
#[test]
fn test_dsl_121_double_lock_rejected() {
    let mut e = MockBondEscrow::new();
    e.credit(11, 10_000);

    let tag = BondTag::Reporter(Bytes32::new([0x33u8; 32]));
    e.lock(11, 1_000, tag).unwrap();

    let err = e
        .lock(11, 500, tag)
        .expect_err("same tag twice must reject");
    let BondError::DoubleLock { tag: got_tag } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(got_tag, tag, "DoubleLock carries the offending tag");

    // State unchanged by the failed second lock: original amount
    // still in escrow, free balance untouched from its post-first-
    // lock value.
    assert_eq!(e.escrowed(11, tag), 1_000);
}
