//! Requirement DSL-039: `ProposerAppealGround::ValidatorNotActiveAtEpoch`
//! sustains when the accused was outside their active window at
//! `header.epoch`.
//!
//! Traces to: docs/resources/SPEC.md §6.2, §15.1, §22.4.
//!
//! # Role
//!
//! DSL-013 precondition 5 requires the proposer to be active at
//! `header.epoch`. Verifier bug admitting pre-activation / post-exit
//! evidence MUST be reversible.
//!
//! # Test matrix (maps to DSL-039 Test Plan)
//!
//!   1. `test_dsl_039_pre_activation_sustained`
//!   2. `test_dsl_039_post_exit_sustained`
//!   3. `test_dsl_039_active_rejected`
//!   4. `test_dsl_039_boundary_activation` — `epoch == activation_epoch` → active
//!   5. `test_dsl_039_boundary_exit_exclusive` — `epoch == exit_epoch` → inactive
//!   6. `test_dsl_039_unknown_validator_sustained`

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, ProposerSlashing,
    SignedBlockHeader, ValidatorEntry, ValidatorView,
    verify_proposer_appeal_validator_not_active_at_epoch,
};

struct TestValidator {
    pk: PublicKey,
    activation_epoch: u64,
    exit_epoch: u64,
}

impl ValidatorEntry for TestValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        Bytes32::new([0u8; 32])
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
        epoch >= self.activation_epoch && epoch < self.exit_epoch
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

struct MapView(HashMap<u32, TestValidator>);
impl ValidatorView for MapView {
    fn get(&self, index: u32) -> Option<&dyn ValidatorEntry> {
        self.0.get(&index).map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, index: u32) -> Option<&mut dyn ValidatorEntry> {
        self.0.get_mut(&index).map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

fn make_header(proposer_index: u32, epoch: u64) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        epoch,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        proposer_index,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn signed(proposer_index: u32, epoch: u64) -> SignedBlockHeader {
    SignedBlockHeader {
        message: make_header(proposer_index, epoch),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

fn view_with(activation: u64, exit: u64) -> MapView {
    let sk = SecretKey::from_seed(&[0x11u8; 32]);
    let mut map = HashMap::new();
    map.insert(
        9,
        TestValidator {
            pk: sk.public_key(),
            activation_epoch: activation,
            exit_epoch: exit,
        },
    );
    MapView(map)
}

fn evidence_at_epoch(epoch: u64) -> ProposerSlashing {
    ProposerSlashing {
        signed_header_a: signed(9, epoch),
        signed_header_b: signed(9, epoch),
    }
}

/// DSL-039 row 1: header.epoch = 0, activation_epoch = 5 → Sustained.
#[test]
fn test_dsl_039_pre_activation_sustained() {
    let view = view_with(5, 1000);
    let ev = evidence_at_epoch(0);
    assert_eq!(
        verify_proposer_appeal_validator_not_active_at_epoch(&ev, &view),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ValidatorNotActiveAtEpoch,
        },
    );
}

/// DSL-039 row 2: header.epoch = 100, exit_epoch = 50 → Sustained.
#[test]
fn test_dsl_039_post_exit_sustained() {
    let view = view_with(0, 50);
    let ev = evidence_at_epoch(100);
    assert_eq!(
        verify_proposer_appeal_validator_not_active_at_epoch(&ev, &view),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ValidatorNotActiveAtEpoch,
        },
    );
}

/// DSL-039 row 3: active at epoch → Rejected.
#[test]
fn test_dsl_039_active_rejected() {
    let view = view_with(5, 100);
    let ev = evidence_at_epoch(50);
    assert_eq!(
        verify_proposer_appeal_validator_not_active_at_epoch(&ev, &view),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-039 row 4: boundary — `epoch == activation_epoch` → active (Rejected).
#[test]
fn test_dsl_039_boundary_activation() {
    let view = view_with(10, 100);
    let ev = evidence_at_epoch(10);
    assert_eq!(
        verify_proposer_appeal_validator_not_active_at_epoch(&ev, &view),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-039 row 5: boundary — `epoch == exit_epoch` → inactive (Sustained).
#[test]
fn test_dsl_039_boundary_exit_exclusive() {
    let view = view_with(0, 100);
    let ev = evidence_at_epoch(100);
    assert_eq!(
        verify_proposer_appeal_validator_not_active_at_epoch(&ev, &view),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ValidatorNotActiveAtEpoch,
        },
    );
}

/// DSL-039 row 6: unknown validator → Sustained (no active status).
#[test]
fn test_dsl_039_unknown_validator_sustained() {
    let view = MapView(HashMap::new());
    let ev = evidence_at_epoch(50);
    assert_eq!(
        verify_proposer_appeal_validator_not_active_at_epoch(&ev, &view),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ValidatorNotActiveAtEpoch,
        },
    );
}
