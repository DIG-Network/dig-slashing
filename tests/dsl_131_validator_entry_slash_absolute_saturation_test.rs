//! Requirement DSL-131: `ValidatorEntry::slash_absolute(amount,
//! epoch)` is the canonical stake debit. Semantics:
//!
//! ```text
//! debited = min(amount, current_stake)
//! stake -= debited
//! status = Slashed { epoch }
//! return debited
//! ```
//!
//! Traces to: docs/resources/SPEC.md §15.1.
//!
//! # Role
//!
//! Opens Phase 9 External-State Traits. `dig-slashing` does NOT
//! own validator storage; embedders implement `ValidatorEntry`.
//! DSL-131 pins the contract via a reference `MockValidator`
//! that every production impl must satisfy.
//!
//! The saturation semantic is load-bearing: DSL-022 base-slash
//! math can exceed the current stake on validators near zero
//! balance (partial prior slashes) and DSL-030 correlation
//! penalty can exceed what remains after DSL-022 debits. Both
//! paths rely on saturation rather than underflow.
//!
//! # Test matrix (maps to DSL-131 Test Plan + acceptance)
//!
//!   1. `test_dsl_131_under_stake` — amount < stake → exact
//!   2. `test_dsl_131_at_stake` — amount == stake → zero out
//!   3. `test_dsl_131_over_stake_saturates` — amount > stake →
//!      debit == stake, NO underflow
//!   4. `test_dsl_131_sets_slashed_status` — is_slashed flips
//!      true + epoch captured
//!   5. `test_dsl_131_repeated_debits` — multiple slash_absolute
//!      calls compose (later calls see already-debited stake)

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::ValidatorEntry;

/// Reference `ValidatorEntry` impl matching SPEC §15.1 exactly.
/// Production embedders may extend with durable storage / event
/// hooks, but the observable side-effects tested here MUST
/// match byte-for-byte.
struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    stake: u64,
    is_slashed: bool,
    slashed_at_epoch: Option<u64>,
}

impl MockValidator {
    fn new(stake: u64) -> Self {
        Self {
            pk: PublicKey::default(),
            ph: Bytes32::new([0u8; 32]),
            stake,
            is_slashed: false,
            slashed_at_epoch: None,
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
    fn slash_absolute(&mut self, amount_mojos: u64, epoch: u64) -> u64 {
        // SPEC §15.1: saturating debit. `min(amount, stake)`
        // prevents underflow without branching on individual
        // call-site overflow checks.
        let debited = amount_mojos.min(self.stake);
        self.stake -= debited;
        self.is_slashed = true;
        self.slashed_at_epoch = Some(epoch);
        debited
    }
    fn credit_stake(&mut self, amount: u64) -> u64 {
        self.stake = self.stake.saturating_add(amount);
        amount
    }
    fn restore_status(&mut self) -> bool {
        let changed = self.is_slashed;
        self.is_slashed = false;
        changed
    }
    fn schedule_exit(&mut self, _: u64) {}
}

/// DSL-131 row 1: under-stake debit is exact.
#[test]
fn test_dsl_131_under_stake() {
    let mut v = MockValidator::new(100);
    let debited = v.slash_absolute(30, 5);
    assert_eq!(debited, 30, "exact debit below stake");
    assert_eq!(v.effective_balance(), 70);
}

/// DSL-131 row 2: exact-stake debit zeroes the balance.
#[test]
fn test_dsl_131_at_stake() {
    let mut v = MockValidator::new(100);
    let debited = v.slash_absolute(100, 5);
    assert_eq!(debited, 100);
    assert_eq!(v.effective_balance(), 0);
}

/// DSL-131 row 3: over-stake saturates at stake. The protocol-
/// critical invariant: no underflow, no panic, return value
/// reflects what ACTUALLY got debited (not what was requested).
#[test]
fn test_dsl_131_over_stake_saturates() {
    let mut v = MockValidator::new(100);
    let debited = v.slash_absolute(200, 5);
    assert_eq!(
        debited, 100,
        "return = actual debit (stake), not requested amount",
    );
    assert_eq!(v.effective_balance(), 0, "stake saturates at 0");

    // Pathological: slash u64::MAX against 1 mojo.
    let mut v = MockValidator::new(1);
    let debited = v.slash_absolute(u64::MAX, 5);
    assert_eq!(debited, 1);
    assert_eq!(v.effective_balance(), 0);
}

/// DSL-131 row 4: status flips to slashed, epoch captured.
/// `is_slashed()` is the gate for DSL-026 dedup + DSL-162
/// already-slashed skip.
#[test]
fn test_dsl_131_sets_slashed_status() {
    let mut v = MockValidator::new(100);
    assert!(!v.is_slashed(), "precondition: unslashed");
    v.slash_absolute(10, 5);
    assert!(v.is_slashed(), "post: slashed flag set");
    assert_eq!(v.slashed_at_epoch, Some(5), "epoch captured");

    // Zero-amount slash still flips status — the call is a
    // PROTOCOL-OBSERVABLE event even when the debit is zero
    // (DSL-162 treats an already-slashed validator as having
    // slash_absolute called with amount=0; status must persist).
    let mut v = MockValidator::new(100);
    v.slash_absolute(0, 7);
    assert!(v.is_slashed(), "zero-amount slash still flips status");
    assert_eq!(v.slashed_at_epoch, Some(7));
}

/// DSL-131 bonus: repeated debits compose. Second call sees the
/// post-first-debit stake, not the original.
#[test]
fn test_dsl_131_repeated_debits() {
    let mut v = MockValidator::new(100);
    assert_eq!(v.slash_absolute(30, 5), 30);
    assert_eq!(v.effective_balance(), 70);
    // Second debit saturates at remaining stake.
    assert_eq!(
        v.slash_absolute(200, 6),
        70,
        "second debit saturates at remaining stake",
    );
    assert_eq!(v.effective_balance(), 0);
    // Third debit on zero stake is a no-op on balance but still
    // observable — returns 0, status stays slashed, epoch
    // advances to the latest call.
    assert_eq!(v.slash_absolute(1, 7), 0);
    assert_eq!(v.slashed_at_epoch, Some(7));
}
