//! Requirement DSL-133: `ValidatorEntry::restore_status()`
//! clears a Slashed state back to Active. Return value:
//!
//!   - `true` iff the call actually changed state
//!     (Slashed → Active).
//!   - `false` when the validator was already Active (idempotent
//!     no-op).
//!
//! Traces to: docs/resources/SPEC.md §15.1.
//!
//! # Role
//!
//! DSL-066 (sustained-appeal revert) calls this AFTER
//! credit_stake to restore the validator's active status so
//! attestation participation resumes. Idempotence is important
//! because DSL-129 reorg rewind may call restore_status on an
//! already-restored validator without harm.
//!
//! # Test matrix (maps to DSL-133 Test Plan + acceptance)
//!
//!   1. `test_dsl_133_slashed_to_active_true` — slash + restore
//!      returns true + is_slashed() == false
//!   2. `test_dsl_133_active_noop_false` — restore on fresh
//!      (never-slashed) returns false, still Active
//!   3. `test_dsl_133_idempotent` — first restore true, second
//!      restore false (same state)
//!   4. `test_dsl_133_re_slash_after_restore` — after
//!      slash → restore → slash, the second slash still takes
//!      effect (restore doesn't permanently immunize)

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::ValidatorEntry;

/// Reference impl matching SPEC §15.1.
struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    stake: u64,
    is_slashed: bool,
}

impl MockValidator {
    fn new(stake: u64) -> Self {
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
        let room = u64::MAX - self.stake;
        let delta = amount.min(room);
        self.stake += delta;
        delta
    }
    fn restore_status(&mut self) -> bool {
        // SPEC §15.1: return `true` iff state actually flips.
        let changed = self.is_slashed;
        self.is_slashed = false;
        changed
    }
    fn schedule_exit(&mut self, _: u64) {}
}

/// DSL-133 row 1: slash + restore flips Slashed → Active and
/// returns true.
#[test]
fn test_dsl_133_slashed_to_active_true() {
    let mut v = MockValidator::new(100);
    v.slash_absolute(10, 5);
    assert!(v.is_slashed(), "precondition: slashed");

    let changed = v.restore_status();
    assert!(changed, "state flip returns true");
    assert!(!v.is_slashed(), "post: active");
}

/// DSL-133 row 2: restore on fresh (never-slashed) returns
/// false, state unchanged.
#[test]
fn test_dsl_133_active_noop_false() {
    let mut v = MockValidator::new(100);
    assert!(!v.is_slashed(), "precondition: never slashed");

    let changed = v.restore_status();
    assert!(!changed, "no-op returns false");
    assert!(!v.is_slashed(), "still active");
}

/// DSL-133 row 3: repeated restore — first call returns true
/// (actual flip), subsequent calls return false (no-op).
#[test]
fn test_dsl_133_idempotent() {
    let mut v = MockValidator::new(100);
    v.slash_absolute(10, 5);

    assert!(v.restore_status(), "first restore flips state");
    assert!(!v.restore_status(), "second restore is no-op");
    assert!(!v.restore_status(), "third restore is no-op");
    assert!(!v.is_slashed());
}

/// DSL-133 bonus: restore does NOT permanently immunize. A
/// validator that was slashed, restored, and slashed AGAIN
/// should end up slashed. Prevents a buggy impl from latching
/// Active once set.
#[test]
fn test_dsl_133_re_slash_after_restore() {
    let mut v = MockValidator::new(100);
    v.slash_absolute(10, 5);
    v.restore_status();
    assert!(!v.is_slashed());

    v.slash_absolute(5, 6);
    assert!(v.is_slashed(), "re-slash after restore must take effect");
}
