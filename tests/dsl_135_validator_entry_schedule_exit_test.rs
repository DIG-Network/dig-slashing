//! Requirement DSL-135: `ValidatorEntry::schedule_exit(epoch)`
//! persists `epoch` as the validator's new `exit_epoch`.
//! Overwritable — the last call wins.
//!
//! Traces to: docs/resources/SPEC.md §15.1.
//!
//! # Role
//!
//! DSL-032 `finalise_expired_slashes` calls this with
//! `current_epoch + SLASH_LOCK_EPOCHS` (100) to enforce the
//! post-slash exit lock. After the call, the validator is
//! frozen in the validator set until `exit_lock_until_epoch`
//! via DSL-134's `is_active_at_epoch` check (right-exclusive).
//!
//! Overwritability matters because subsequent sustained appeals
//! could rewind the exit lock (DSL-064 / DSL-066); without
//! overwrite semantics a buggy impl would leave the original
//! lock in place even after revert.
//!
//! # Test matrix (maps to DSL-135 Test Plan + acceptance)
//!
//!   1. `test_dsl_135_persists_epoch` — schedule_exit(110) →
//!      exit_epoch == 110
//!   2. `test_dsl_135_overwritable` — two consecutive calls →
//!      second value wins
//!   3. `test_dsl_135_downstream_observes_new_exit` — after
//!      schedule_exit(110), `is_active_at_epoch(110) == false`
//!      and `is_active_at_epoch(109) == true` — the new exit
//!      epoch propagates through to the lifecycle check
//!   4. `test_dsl_135_overwrite_backwards` — schedule_exit can
//!      move the exit epoch EARLIER as well as later (e.g.,
//!      DSL-064 revert rewinding a finalised slash's lock)

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::ValidatorEntry;

struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    activation_epoch: u64,
    exit_epoch: u64,
}

impl MockValidator {
    fn new() -> Self {
        Self {
            pk: PublicKey::default(),
            ph: Bytes32::new([0u8; 32]),
            activation_epoch: 0,
            exit_epoch: u64::MAX,
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
        32_000_000_000
    }
    fn is_slashed(&self) -> bool {
        false
    }
    fn activation_epoch(&self) -> u64 {
        self.activation_epoch
    }
    fn exit_epoch(&self) -> u64 {
        self.exit_epoch
    }
    fn is_active_at_epoch(&self, epoch: u64) -> bool {
        self.activation_epoch <= epoch && epoch < self.exit_epoch
    }
    fn slash_absolute(&mut self, _: u64, _: u64) -> u64 {
        0
    }
    fn credit_stake(&mut self, _: u64) -> u64 {
        0
    }
    fn restore_status(&mut self) -> bool {
        false
    }
    fn schedule_exit(&mut self, exit_lock_until_epoch: u64) {
        // SPEC §15.1: unconditional overwrite. Last call wins so
        // DSL-064 / DSL-066 can rewind a finalised slash's lock.
        self.exit_epoch = exit_lock_until_epoch;
    }
}

/// DSL-135 row 1: persistent write.
#[test]
fn test_dsl_135_persists_epoch() {
    let mut v = MockValidator::new();
    v.schedule_exit(110);
    assert_eq!(v.exit_epoch(), 110);
}

/// DSL-135 row 2: last call wins.
#[test]
fn test_dsl_135_overwritable() {
    let mut v = MockValidator::new();
    v.schedule_exit(110);
    v.schedule_exit(200);
    assert_eq!(v.exit_epoch(), 200, "last call wins");

    // Third call also wins.
    v.schedule_exit(50);
    assert_eq!(v.exit_epoch(), 50);
}

/// DSL-135 row 3: downstream `is_active_at_epoch` observes the
/// new exit epoch. This is the PROTOCOL invariant — schedule_exit
/// isn't just a getter setter; its side effect drives the
/// validator-set membership check.
#[test]
fn test_dsl_135_downstream_observes_new_exit() {
    let mut v = MockValidator::new();
    // Pre-schedule: always active because exit_epoch = u64::MAX.
    assert!(v.is_active_at_epoch(109));
    assert!(v.is_active_at_epoch(110));

    v.schedule_exit(110);

    // Post-schedule: exit_epoch == 110 means epoch 110 is
    // exclusive.
    assert!(v.is_active_at_epoch(109), "epoch 109 still active");
    assert!(!v.is_active_at_epoch(110), "epoch 110 no longer active");
    assert!(!v.is_active_at_epoch(200));
}

/// DSL-135 bonus: schedule_exit can move exit_epoch BACKWARDS.
/// A sustained appeal unwinding a finalised slash may rewind
/// the exit lock to u64::MAX (no lock). Pin that the write is
/// unconditional, NOT monotonic.
#[test]
fn test_dsl_135_overwrite_backwards() {
    let mut v = MockValidator::new();
    v.schedule_exit(200);
    assert_eq!(v.exit_epoch(), 200);

    // Move backwards.
    v.schedule_exit(100);
    assert_eq!(v.exit_epoch(), 100, "backward move allowed");

    // Rewind to u64::MAX (no lock).
    v.schedule_exit(u64::MAX);
    assert_eq!(v.exit_epoch(), u64::MAX);
}
