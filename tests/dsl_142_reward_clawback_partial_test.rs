//! Requirement DSL-142: `RewardClawback::claw_back(ph, amount)`
//! returns mojos ACTUALLY deducted from the principal's reward
//! account.
//!
//!   - balance >= amount → returns `amount` (full).
//!   - balance < amount → returns `balance` (partial; the
//!     principal already withdrew some of the optimistic
//!     reward).
//!   - balance == 0 → returns 0.
//!   - Saturating subtraction: no underflow panic even at
//!     u64::MAX balances.
//!   - Composable: second clawback sees post-first balance.
//!
//! Traces to: docs/resources/SPEC.md §12.2.
//!
//! # Role
//!
//! DSL-067 sustained appeal calls `claw_back` on both the
//! whistleblower reward AND the proposer reward that were paid
//! optimistically at DSL-025 admission. DSL-073 adjudicator
//! absorbs the partial-return shortfall from the forfeited
//! reporter bond's burn leg.
//!
//! The partial-return contract is LOAD-BEARING: validator
//! reward accounts are spendable between admission and
//! sustained-appeal, so some of the optimistic payout may have
//! already left the account. The adjudicator MUST know the
//! actual clawed-back amount to compute the shortfall-absorption
//! (DSL-073 ClawbackResult::shortfall).
//!
//! # Test matrix (maps to DSL-142 Test Plan + acceptance)
//!
//!   1. `test_dsl_142_full_clawback` — balance covers amount →
//!      returns full amount
//!   2. `test_dsl_142_partial_clawback` — balance < amount →
//!      returns exact balance
//!   3. `test_dsl_142_empty_balance_zero` — balance=0 → 0
//!   4. `test_dsl_142_saturating` — amount exceeds balance at
//!      u64::MAX scale; no underflow panic
//!   5. `test_dsl_142_composes` — multiple clawbacks compose;
//!      second sees post-first balance

use std::cell::RefCell;
use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::RewardClawback;

/// Reference mock with per-address balances.
struct MockClawback {
    balances: RefCell<HashMap<Bytes32, u64>>,
}
impl MockClawback {
    fn new() -> Self {
        Self {
            balances: RefCell::new(HashMap::new()),
        }
    }
    fn set(&self, ph: Bytes32, amount: u64) {
        self.balances.borrow_mut().insert(ph, amount);
    }
    fn get(&self, ph: Bytes32) -> u64 {
        *self.balances.borrow().get(&ph).unwrap_or(&0)
    }
}
impl RewardClawback for MockClawback {
    fn claw_back(&mut self, ph: Bytes32, amount: u64) -> u64 {
        let mut balances = self.balances.borrow_mut();
        let bal = balances.entry(ph).or_insert(0);
        // SPEC §12.2: saturating subtraction. Return actual
        // clawed amount; adjudicator reads this to compute
        // shortfall (DSL-073).
        let clawed = amount.min(*bal);
        *bal -= clawed;
        clawed
    }
}

/// DSL-142 row 1: full clawback — balance covers amount.
#[test]
fn test_dsl_142_full_clawback() {
    let mut c = MockClawback::new();
    let ph = Bytes32::new([0x11u8; 32]);
    c.set(ph, 100);

    let clawed = c.claw_back(ph, 60);
    assert_eq!(clawed, 60, "full amount clawed");
    assert_eq!(c.get(ph), 40, "balance = 100 - 60");
}

/// DSL-142 row 2: partial clawback — balance < amount. Return
/// value reflects ACTUAL deduction, not requested amount.
#[test]
fn test_dsl_142_partial_clawback() {
    let mut c = MockClawback::new();
    let ph = Bytes32::new([0x22u8; 32]);
    c.set(ph, 40);

    let clawed = c.claw_back(ph, 100);
    assert_eq!(
        clawed, 40,
        "return = actual clawed (balance), not requested (100)",
    );
    assert_eq!(c.get(ph), 0, "balance exhausted");
}

/// DSL-142 row 3: empty balance → 0 clawed.
#[test]
fn test_dsl_142_empty_balance_zero() {
    let mut c = MockClawback::new();
    let ph = Bytes32::new([0x33u8; 32]);
    // Never set — balance implicitly 0.
    let clawed = c.claw_back(ph, 50);
    assert_eq!(clawed, 0);

    // Explicit 0 — same outcome.
    let ph2 = Bytes32::new([0x34u8; 32]);
    c.set(ph2, 0);
    assert_eq!(c.claw_back(ph2, 50), 0);
}

/// DSL-142 row 4: saturating subtraction at u64::MAX scale.
/// Large balance + normal clawback requested: returns `amount`,
/// balance shrinks by `amount`. No underflow panic.
#[test]
fn test_dsl_142_saturating() {
    let mut c = MockClawback::new();
    let ph = Bytes32::new([0x44u8; 32]);
    c.set(ph, u64::MAX - 5);

    let clawed = c.claw_back(ph, 100);
    assert_eq!(clawed, 100, "full clawback on huge balance");
    assert_eq!(c.get(ph), u64::MAX - 105);

    // Conversely: tiny balance, clawback(u64::MAX) — saturates
    // at balance, no panic.
    let ph2 = Bytes32::new([0x55u8; 32]);
    c.set(ph2, 5);
    let clawed = c.claw_back(ph2, u64::MAX);
    assert_eq!(clawed, 5);
    assert_eq!(c.get(ph2), 0);
}

/// DSL-142 row 5: composability. Two clawbacks on the same
/// principal — second sees post-first balance.
#[test]
fn test_dsl_142_composes() {
    let mut c = MockClawback::new();
    let ph = Bytes32::new([0x66u8; 32]);
    c.set(ph, 100);

    let first = c.claw_back(ph, 60);
    assert_eq!(first, 60);
    assert_eq!(c.get(ph), 40);

    // Second claw of 50 sees only 40 → returns 40.
    let second = c.claw_back(ph, 50);
    assert_eq!(second, 40, "second clawback sees post-first balance (40)",);
    assert_eq!(c.get(ph), 0);

    // Third clawback on exhausted balance → 0.
    assert_eq!(c.claw_back(ph, 10), 0);
}
