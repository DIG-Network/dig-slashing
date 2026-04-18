//! Requirement DSL-123: `BondEscrow::release` contract.
//!
//!   1. Credits the full escrowed amount back to the principal's
//!      free stake.
//!   2. Zeroes the tag — subsequent `escrowed` returns 0.
//!   3. Release on an unknown tag → `BondError::TagNotFound`.
//!
//! Traces to: docs/resources/SPEC.md §12.3, §22.14.
//!
//! # Role
//!
//! DSL-031 `finalise_expired_slashes` calls `release` to return
//! the reporter bond when the challenge window closes without a
//! winning appeal. Symmetric on the appeal side: a REJECTED
//! appeal whose evidence-side slash later finalises would also
//! release the reporter bond through this path.
//!
//! # Test matrix (maps to DSL-123 Test Plan + acceptance)
//!
//!   1. `test_dsl_123_release_credits_stake` — lock + release →
//!      free balance restored to exact pre-lock value
//!   2. `test_dsl_123_zeroes_tag` — post-release `escrowed` == 0
//!   3. `test_dsl_123_empty_tag_err` — release on never-locked
//!      tag → TagNotFound { tag }
//!   4. `test_dsl_123_double_release_err` — release twice on same
//!      tag: second call TagNotFound (symmetric to DSL-122
//!      double-forfeit)

use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::{BondError, BondEscrow, BondTag};

/// Reference mock with explicit free-balance tracking so the
/// `credits_stake` test can verify the credit actually lands.
/// Copy-paste from DSL-121/122 per SPEC §22 self-containment.
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

    fn free_balance(&self, principal: u32) -> u64 {
        *self.free.get(&principal).unwrap_or(&0)
    }
}

impl BondEscrow for MockBondEscrow {
    fn lock(&mut self, principal: u32, amount: u64, tag: BondTag) -> Result<(), BondError> {
        let have = *self.free.get(&principal).unwrap_or(&0);
        if have < amount {
            return Err(BondError::InsufficientBalance { have, need: amount });
        }
        if self.escrow.contains_key(&(principal, tag)) {
            return Err(BondError::DoubleLock { tag });
        }
        *self.free.get_mut(&principal).unwrap() -= amount;
        self.escrow.insert((principal, tag), amount);
        Ok(())
    }

    fn release(&mut self, principal: u32, _amount: u64, tag: BondTag) -> Result<(), BondError> {
        // Full-release contract: returns the ENTIRE escrowed
        // amount to free stake, independent of the passed `amount`
        // (matches forfeit's symmetric semantics in DSL-122).
        match self.escrow.remove(&(principal, tag)) {
            Some(escrowed) => {
                *self.free.entry(principal).or_insert(0) += escrowed;
                Ok(())
            }
            None => Err(BondError::TagNotFound { tag }),
        }
    }

    fn forfeit(&mut self, _: u32, _: u64, _: BondTag) -> Result<u64, BondError> {
        Ok(0)
    }

    fn escrowed(&self, principal: u32, tag: BondTag) -> u64 {
        *self.escrow.get(&(principal, tag)).unwrap_or(&0)
    }
}

/// DSL-123 row 1: free balance returns to its pre-lock state.
/// Lock 500 out of 10_000 → free=9_500, escrow=500. Release →
/// free=10_000, escrow=0.
#[test]
fn test_dsl_123_release_credits_stake() {
    let mut e = MockBondEscrow::new();
    e.credit(11, 10_000);
    let tag = BondTag::Reporter(Bytes32::new([0x11u8; 32]));

    e.lock(11, 500, tag).unwrap();
    assert_eq!(e.free_balance(11), 9_500, "post-lock free balance");
    assert_eq!(e.escrowed(11, tag), 500);

    e.release(11, 500, tag)
        .expect("release on locked tag must succeed");
    assert_eq!(
        e.free_balance(11),
        10_000,
        "free balance restored to pre-lock value",
    );
}

/// DSL-123 row 2: tag is gone after release. Mirrors DSL-122
/// forfeit's tag-zero guarantee.
#[test]
fn test_dsl_123_zeroes_tag() {
    let mut e = MockBondEscrow::new();
    e.credit(11, 10_000);
    let tag = BondTag::Reporter(Bytes32::new([0x22u8; 32]));

    e.lock(11, 500, tag).unwrap();
    e.release(11, 500, tag).unwrap();
    assert_eq!(e.escrowed(11, tag), 0, "post-release: tag zeroed");
}

/// DSL-123 row 3: release on never-locked tag → TagNotFound.
#[test]
fn test_dsl_123_empty_tag_err() {
    let mut e = MockBondEscrow::new();
    let tag = BondTag::Reporter(Bytes32::new([0x33u8; 32]));
    let err = e
        .release(11, 500, tag)
        .expect_err("release on empty tag rejects");
    let BondError::TagNotFound { tag: got } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(got, tag);
}

/// Row 4: double-release is symmetric to double-forfeit (DSL-122).
/// Second call on an already-released tag returns TagNotFound.
/// Prevents double-crediting the same bond to free stake.
#[test]
fn test_dsl_123_double_release_err() {
    let mut e = MockBondEscrow::new();
    e.credit(11, 10_000);
    let tag = BondTag::Reporter(Bytes32::new([0x44u8; 32]));

    e.lock(11, 500, tag).unwrap();
    e.release(11, 500, tag).unwrap();

    let err = e.release(11, 500, tag).expect_err("double-release rejects");
    assert!(matches!(err, BondError::TagNotFound { .. }));

    // Balance was NOT double-credited.
    assert_eq!(
        e.free_balance(11),
        10_000,
        "failed double-release must not touch free balance",
    );
}
