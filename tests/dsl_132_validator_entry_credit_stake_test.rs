//! Requirement DSL-132: `ValidatorEntry::credit_stake(amount)`
//! is the inverse of `slash_absolute`.
//!
//! ```text
//! delta = min(amount, u64::MAX - stake)  # saturating add delta
//! stake += delta
//! return delta
//! ```
//!
//! Traces to: docs/resources/SPEC.md §15.1.
//!
//! # Role
//!
//! Consumers:
//!   - DSL-064 sustained-appeal revert (credit back the
//!     debited base slash).
//!   - DSL-129 reorg rewind (credit back every slashed
//!     validator in the rewound window).
//!
//! The saturating-add semantic is a defensive envelope — in
//! practice validator stakes are bounded well below u64::MAX,
//! so the branch never fires. Pinning it here prevents a future
//! refactor to a plain `+` from introducing a silent overflow
//! panic.
//!
//! # Test matrix (maps to DSL-132 Test Plan + acceptance)
//!
//!   1. `test_dsl_132_credits_mojos` — stake=0, credit(50) →
//!      stake=50, return=50
//!   2. `test_dsl_132_inverse_of_slash` — slash(30) then
//!      credit(30) restores original stake
//!   3. `test_dsl_132_saturates` — stake=u64::MAX-5,
//!      credit(100) → stake=u64::MAX, return=5 (actual delta,
//!      not requested)
//!   4. `test_dsl_132_zero_credit_noop` — credit(0) returns 0,
//!      stake unchanged

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::ValidatorEntry;

/// Reference impl with SPEC §15.1 credit_stake semantics —
/// including the saturating-delta return value on overflow
/// (DSL-131's mock returned the requested amount; DSL-132
/// requires actual delta).
struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    stake: u64,
    is_slashed: bool,
}

impl MockValidator {
    fn with_stake(stake: u64) -> Self {
        Self {
            pk: PublicKey::default(),
            ph: Bytes32::new([0u8; 32]),
            stake,
            is_slashed: false,
        }
    }
}

impl ValidatorEntry for MockValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        self.ph
    }
    fn effective_balance(&self) -> u64 {
        self.stake
    }
    fn is_slashed(&self) -> bool {
        self.is_slashed
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
        let debited = amount.min(self.stake);
        self.stake -= debited;
        self.is_slashed = true;
        debited
    }
    fn credit_stake(&mut self, amount: u64) -> u64 {
        // SPEC §15.1: saturating add, return actual delta. On
        // overflow the requested amount may exceed the
        // reachable delta (u64::MAX - stake); the return value
        // must carry the TRUE delta so callers reconciling
        // pre-/post-state see a consistent number.
        let room = u64::MAX - self.stake;
        let delta = amount.min(room);
        self.stake += delta;
        delta
    }
    fn restore_status(&mut self) -> bool {
        let changed = self.is_slashed;
        self.is_slashed = false;
        changed
    }
    fn schedule_exit(&mut self, _: u64) {}
}

/// DSL-132 row 1: straightforward credit to a zero-stake
/// validator.
#[test]
fn test_dsl_132_credits_mojos() {
    let mut v = MockValidator::with_stake(0);
    let credited = v.credit_stake(50);
    assert_eq!(credited, 50);
    assert_eq!(v.effective_balance(), 50);
}

/// DSL-132 row 2: inverse of slash_absolute. slash(30) then
/// credit(30) restores the original stake exactly. This is the
/// DSL-064 sustained-appeal revert invariant.
#[test]
fn test_dsl_132_inverse_of_slash() {
    let mut v = MockValidator::with_stake(100);
    let debited = v.slash_absolute(30, 5);
    assert_eq!(debited, 30);
    assert_eq!(v.effective_balance(), 70);

    let credited = v.credit_stake(30);
    assert_eq!(credited, 30);
    assert_eq!(v.effective_balance(), 100, "original stake restored");
}

/// DSL-132 row 3: saturation at u64::MAX. stake near MAX,
/// credit(100) → stake=MAX, return=actual delta (5, not 100).
///
/// The return-value carries the TRUE delta so a caller doing
/// pre/post balance reconciliation sees a consistent number.
#[test]
fn test_dsl_132_saturates() {
    let mut v = MockValidator::with_stake(u64::MAX - 5);
    let credited = v.credit_stake(100);
    assert_eq!(
        credited, 5,
        "return = actual delta (5), NOT requested amount (100)",
    );
    assert_eq!(v.effective_balance(), u64::MAX, "stake saturated at MAX");

    // Crediting further is a pure no-op.
    assert_eq!(v.credit_stake(1_000), 0);
    assert_eq!(v.effective_balance(), u64::MAX);
}

/// DSL-132 bonus: zero-amount credit is a no-op. Return 0,
/// stake unchanged. Ensures the degenerate call shape doesn't
/// accidentally mutate state.
#[test]
fn test_dsl_132_zero_credit_noop() {
    let mut v = MockValidator::with_stake(100);
    assert_eq!(v.credit_stake(0), 0);
    assert_eq!(v.effective_balance(), 100);
}
