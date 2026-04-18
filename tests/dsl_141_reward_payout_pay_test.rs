//! Requirement DSL-141: `RewardPayout::pay(principal_ph, amount)`.
//!
//!   - Single pay recorded against `principal_ph` with `amount`.
//!   - Multiple pays to same address accumulate.
//!   - `amount == 0` is a no-op by the protocol contract; a
//!     mock MAY still record a zero entry (the spec permits
//!     either, per §12.1).
//!
//! Traces to: docs/resources/SPEC.md §12.1.
//!
//! # Role
//!
//! `RewardPayout` is the single reward-distribution surface.
//! Consumers:
//!   - DSL-025 submit_evidence routes whistleblower + proposer
//!     rewards.
//!   - DSL-068 sustained appeal pays appellant the winner-award
//!     half of the reporter bond.
//!   - DSL-071 rejected appeal pays reporter the winner-award
//!     half of the appellant bond.
//!
//! Implementation is downstream (dig-collateral or equivalent)
//! and may batch / coalesce. DSL-141 only pins the CALLER-visible
//! contract: pays are per-call, additive across calls.
//!
//! # Test matrix (maps to DSL-141 Test Plan + acceptance)
//!
//!   1. `test_dsl_141_single_pay_recorded` — pay(ph, 100) →
//!      total(ph) == 100
//!   2. `test_dsl_141_multiple_pays_accumulate` — pay(ph, 100)
//!      + pay(ph, 50) → total == 150
//!   3. `test_dsl_141_zero_no_op` — pay(ph, 0) acceptable; the
//!      caller does not need to branch on zero
//!   4. `test_dsl_141_multiple_principals_isolated` — pays to
//!      different puzzle hashes stay separate (no cross-account
//!      contamination)

use std::cell::RefCell;
use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::RewardPayout;

/// Reference mock that accumulates per-address totals.
struct MockPayout {
    ledger: RefCell<HashMap<Bytes32, u64>>,
}
impl MockPayout {
    fn new() -> Self {
        Self {
            ledger: RefCell::new(HashMap::new()),
        }
    }
    fn total(&self, ph: Bytes32) -> u64 {
        *self.ledger.borrow().get(&ph).unwrap_or(&0)
    }
    fn entries(&self) -> usize {
        self.ledger.borrow().len()
    }
}
impl RewardPayout for MockPayout {
    fn pay(&mut self, ph: Bytes32, amount: u64) {
        *self.ledger.borrow_mut().entry(ph).or_insert(0) += amount;
    }
}

/// DSL-141 row 1: one pay recorded.
#[test]
fn test_dsl_141_single_pay_recorded() {
    let mut p = MockPayout::new();
    let ph = Bytes32::new([0x11u8; 32]);
    p.pay(ph, 100);
    assert_eq!(p.total(ph), 100);
}

/// DSL-141 row 2: repeated pays to the same address accumulate.
/// Critical for DSL-025 where the whistleblower reward is
/// routed alongside the proposer reward and both land on the
/// SAME puzzle hash when the reporter == proposer (edge case).
#[test]
fn test_dsl_141_multiple_pays_accumulate() {
    let mut p = MockPayout::new();
    let ph = Bytes32::new([0x22u8; 32]);
    p.pay(ph, 100);
    p.pay(ph, 50);
    p.pay(ph, 25);
    assert_eq!(p.total(ph), 175, "100 + 50 + 25");
}

/// DSL-141 row 3: pay(ph, 0) is tolerated. SPEC §12.1 permits
/// either a pure no-op or a recorded zero entry; callers MUST
/// NOT branch on the observable behavior. The mock records the
/// zero via `+= 0` which is harmless.
#[test]
fn test_dsl_141_zero_no_op() {
    let mut p = MockPayout::new();
    let ph = Bytes32::new([0x33u8; 32]);
    p.pay(ph, 0);
    // Under this mock, total stays at 0 (no increment happened).
    assert_eq!(p.total(ph), 0);
    // Follow-up non-zero pay still works cleanly.
    p.pay(ph, 42);
    assert_eq!(p.total(ph), 42);
}

/// DSL-141 row 4: pays to different addresses stay isolated.
/// No cross-account contamination — critical because
/// DSL-025/068/071 may route rewards to multiple puzzle hashes
/// within a single admission.
#[test]
fn test_dsl_141_multiple_principals_isolated() {
    let mut p = MockPayout::new();
    let ph_a = Bytes32::new([0xAAu8; 32]);
    let ph_b = Bytes32::new([0xBBu8; 32]);
    let ph_c = Bytes32::new([0xCCu8; 32]);

    p.pay(ph_a, 100);
    p.pay(ph_b, 50);
    p.pay(ph_c, 25);

    assert_eq!(p.total(ph_a), 100);
    assert_eq!(p.total(ph_b), 50);
    assert_eq!(p.total(ph_c), 25);
    assert_eq!(p.entries(), 3);

    // Repeated pay to one principal leaves others untouched.
    p.pay(ph_a, 200);
    assert_eq!(p.total(ph_a), 300);
    assert_eq!(p.total(ph_b), 50);
    assert_eq!(p.total(ph_c), 25);
}
