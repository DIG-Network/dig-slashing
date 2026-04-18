//! Requirement DSL-134: `ValidatorEntry::is_active_at_epoch(e)`
//! returns `true` iff `activation_epoch <= e < exit_epoch`.
//! Left-inclusive, right-exclusive boundary — matches Ethereum
//! validator-lifecycle semantics exactly.
//!
//! Traces to: docs/resources/SPEC.md §15.1.
//!
//! # Role
//!
//! Consumers:
//!   - DSL-013 / DSL-018 validator-registered-and-active check
//!     inside verify_proposer_slashing / verify_invalid_block.
//!   - DSL-039 ProposerAppealGround::ValidatorNotActiveAtEpoch
//!     ground — validates that the accused validator WAS
//!     inactive at the offense epoch.
//!
//! Both callers depend on the exact boundary semantics so a
//! validator attesting on their activation epoch is valid and
//! a validator whose exit epoch has arrived is NOT.
//!
//! # Test matrix (maps to DSL-134 Test Plan + acceptance)
//!
//!   1. `test_dsl_134_at_activation_active` — epoch == activation
//!      → true (inclusive lower bound)
//!   2. `test_dsl_134_pre_activation_inactive` — epoch ==
//!      activation - 1 → false
//!   3. `test_dsl_134_last_epoch_active` — epoch == exit - 1 →
//!      true
//!   4. `test_dsl_134_at_exit_inactive` — epoch == exit → false
//!      (exclusive upper bound)
//!   5. `test_dsl_134_interior_active` — well-inside epoch
//!      returns true (guards against off-by-one inversion)
//!   6. `test_dsl_134_never_exited` — exit_epoch == u64::MAX
//!      means always active after activation

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::ValidatorEntry;

/// Reference impl parameterised over activation + exit.
struct MockValidator {
    pk: PublicKey,
    ph: Bytes32,
    activation_epoch: u64,
    exit_epoch: u64,
}

impl MockValidator {
    fn with_lifecycle(activation: u64, exit: u64) -> Self {
        Self {
            pk: PublicKey::default(),
            ph: Bytes32::new([0u8; 32]),
            activation_epoch: activation,
            exit_epoch: exit,
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
        // SPEC §15.1: activation_epoch <= epoch < exit_epoch.
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
    fn schedule_exit(&mut self, _: u64) {}
}

/// DSL-134 row 1: activation boundary is INCLUSIVE. A validator
/// whose activation_epoch == 5 IS active at epoch 5.
#[test]
fn test_dsl_134_at_activation_active() {
    let v = MockValidator::with_lifecycle(5, 10);
    assert!(v.is_active_at_epoch(5), "activation boundary is inclusive");
}

/// DSL-134 row 2: one epoch before activation is inactive.
#[test]
fn test_dsl_134_pre_activation_inactive() {
    let v = MockValidator::with_lifecycle(5, 10);
    assert!(!v.is_active_at_epoch(4), "pre-activation is inactive");
    // Also check epoch 0.
    assert!(!v.is_active_at_epoch(0));
}

/// DSL-134 row 3: `exit - 1` is still active (right-exclusive
/// means the last active epoch is `exit - 1`).
#[test]
fn test_dsl_134_last_epoch_active() {
    let v = MockValidator::with_lifecycle(5, 10);
    assert!(v.is_active_at_epoch(9), "exit - 1 is still active");
}

/// DSL-134 row 4: exit boundary is EXCLUSIVE. A validator whose
/// exit_epoch == 10 is NOT active at epoch 10.
#[test]
fn test_dsl_134_at_exit_inactive() {
    let v = MockValidator::with_lifecycle(5, 10);
    assert!(!v.is_active_at_epoch(10), "exit boundary is exclusive");
    // And anything past exit.
    assert!(!v.is_active_at_epoch(11));
    assert!(!v.is_active_at_epoch(1_000_000));
}

/// DSL-134 bonus: interior epochs are active. Guards against an
/// off-by-one inversion where both boundaries get flipped and
/// interior still passes accidentally.
#[test]
fn test_dsl_134_interior_active() {
    let v = MockValidator::with_lifecycle(5, 10);
    for e in [6, 7, 8] {
        assert!(v.is_active_at_epoch(e), "interior epoch {e} must be active");
    }
}

/// DSL-134 bonus: a validator with `exit_epoch == u64::MAX`
/// (never exited) stays active indefinitely after activation.
/// This is the common case for active validators — schedule_exit
/// is the only path that moves exit_epoch below u64::MAX.
#[test]
fn test_dsl_134_never_exited() {
    let v = MockValidator::with_lifecycle(5, u64::MAX);
    assert!(v.is_active_at_epoch(5));
    assert!(v.is_active_at_epoch(1_000_000));
    assert!(v.is_active_at_epoch(u64::MAX - 1));
    // Only u64::MAX itself fails (strict `<` against u64::MAX).
    assert!(!v.is_active_at_epoch(u64::MAX));
}
