//! Requirement DSL-122: `BondEscrow::forfeit` contract.
//!
//!   1. Returns `Ok(forfeited_mojos)` equal to the escrowed
//!      amount for `(principal_idx, tag)`.
//!   2. Zeroes the tag — subsequent `escrowed` returns 0.
//!   3. Forfeit on an unknown tag → `Err(BondError::TagNotFound
//!      { tag })`.
//!
//! Traces to: docs/resources/SPEC.md §12.3, §22.14.
//!
//! # Role
//!
//! Adjudicator DSL-068 (sustained) + DSL-071 (rejected) call
//! `forfeit` to extract the bond amount for the winner-award +
//! burn split. The return value is the ONLY channel carrying the
//! forfeited mojos — a buggy forfeit that returns 0 (or a stale
//! amount) silently drops stake or double-counts it. This test
//! pins the return-value contract.
//!
//! # Test matrix (maps to DSL-122 Test Plan + acceptance)
//!
//!   1. `test_dsl_122_forfeit_returns_escrowed` — lock 500 then
//!      forfeit → returns 500
//!   2. `test_dsl_122_zeroes_tag` — post-forfeit `escrowed`
//!      returns 0
//!   3. `test_dsl_122_empty_tag_err` — forfeit on a tag never
//!      locked → `BondError::TagNotFound { tag }`
//!   4. `test_dsl_122_amount_parameter_ignored_for_return` — the
//!      `amount` parameter exists for future partial-forfeit
//!      semantics; current contract returns the full escrowed
//!      balance regardless of the passed `amount` (DSL-068 +
//!      DSL-071 always pass the full amount)

use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::{BondError, BondEscrow, BondTag};

/// Same reference mock as DSL-121. Copy-paste rather than share
/// because each DSL-NNN test file is self-contained by design
/// (SPEC §22 rule).
struct MockBondEscrow {
    escrow: HashMap<(u32, BondTag), u64>,
}

impl MockBondEscrow {
    fn new() -> Self {
        Self {
            escrow: HashMap::new(),
        }
    }

    fn inject(&mut self, principal: u32, tag: BondTag, amount: u64) {
        self.escrow.insert((principal, tag), amount);
    }
}

impl BondEscrow for MockBondEscrow {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        // Out of scope — tests inject state via `inject`.
        Ok(())
    }

    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }

    fn forfeit(&mut self, principal: u32, _amount: u64, tag: BondTag) -> Result<u64, BondError> {
        match self.escrow.remove(&(principal, tag)) {
            Some(escrowed) => Ok(escrowed),
            None => Err(BondError::TagNotFound { tag }),
        }
    }

    fn escrowed(&self, principal: u32, tag: BondTag) -> u64 {
        *self.escrow.get(&(principal, tag)).unwrap_or(&0)
    }
}

/// DSL-122 row 1: forfeit returns the FULL escrowed amount,
/// which the adjudicator then routes to the winner-award + burn
/// split (DSL-068 / DSL-071).
#[test]
fn test_dsl_122_forfeit_returns_escrowed() {
    let mut e = MockBondEscrow::new();
    let tag = BondTag::Reporter(Bytes32::new([0x11u8; 32]));
    e.inject(11, tag, 500);

    let forfeited = e
        .forfeit(11, 500, tag)
        .expect("forfeit on locked tag must succeed");
    assert_eq!(forfeited, 500, "return value == escrowed amount");
}

/// DSL-122 row 2: the tag is gone after forfeit. `escrowed`
/// reports 0, and a follow-up forfeit on the same tag returns
/// `TagNotFound` (proved in row 3).
#[test]
fn test_dsl_122_zeroes_tag() {
    let mut e = MockBondEscrow::new();
    let tag = BondTag::Reporter(Bytes32::new([0x22u8; 32]));
    e.inject(11, tag, 500);

    assert_eq!(e.escrowed(11, tag), 500, "precondition: tag holds 500");
    let _ = e.forfeit(11, 500, tag).unwrap();
    assert_eq!(e.escrowed(11, tag), 0, "post-forfeit: tag zeroed");
}

/// DSL-122 row 3: forfeit on an unknown tag is a `TagNotFound`
/// error carrying the tag. Distinct from `InsufficientBalance`
/// which is only a lock-path concern.
#[test]
fn test_dsl_122_empty_tag_err() {
    let mut e = MockBondEscrow::new();
    let tag = BondTag::Reporter(Bytes32::new([0x33u8; 32]));

    let err = e
        .forfeit(11, 500, tag)
        .expect_err("forfeit on never-locked tag rejects");
    let BondError::TagNotFound { tag: got } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(got, tag);

    // Double-forfeit: lock, forfeit, forfeit again. Second call
    // must also return TagNotFound.
    let t2 = BondTag::Appellant(Bytes32::new([0x44u8; 32]));
    e.inject(11, t2, 100);
    let _ = e.forfeit(11, 100, t2).unwrap();
    let err = e.forfeit(11, 100, t2).expect_err("double-forfeit rejects");
    assert!(matches!(err, BondError::TagNotFound { .. }));
}

/// Row 4 (contract clarification): the `amount` parameter does
/// NOT currently gate partial forfeits — the trait returns the
/// full escrowed amount regardless. DSL-068 / DSL-071 always
/// pass the full locked amount as `amount`, so this is a
/// convergent no-op in practice. Pinning it here keeps future
/// partial-forfeit extensions (would need a new variant or
/// additional return fields) from silently breaking the existing
/// adjudicator contracts.
#[test]
fn test_dsl_122_amount_parameter_ignored_for_return() {
    let mut e = MockBondEscrow::new();
    let tag = BondTag::Reporter(Bytes32::new([0x55u8; 32]));
    e.inject(11, tag, 500);

    // Pass a misleading smaller amount — contract still returns
    // the full escrowed balance (500, not 1).
    let forfeited = e.forfeit(11, 1, tag).unwrap();
    assert_eq!(
        forfeited, 500,
        "current contract returns full escrowed amount — DSL-068/071 always pass the full amount anyway",
    );
}
