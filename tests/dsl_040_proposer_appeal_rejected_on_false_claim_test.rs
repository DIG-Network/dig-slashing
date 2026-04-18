//! Requirement DSL-040: every proposer-appeal ground rejects with
//! `AppealRejectReason::GroundDoesNotHold` when the predicate
//! evaluates `false` on honest evidence.
//!
//! Traces to: docs/resources/SPEC.md §6.2, §22.4.
//!
//! # Role
//!
//! Closes the six-ground proposer appeal surface (DSL-034..039) with
//! a symmetric rejection test matrix. Rejected appeals forfeit the
//! appellant bond (DSL-071); catching false claims at the predicate
//! layer keeps that mechanism sound.
//!
//! # Test matrix (maps to DSL-040 Test Plan)
//!
//!   1. `test_dsl_040_headers_identical_false_claim_rejected`
//!   2. `test_dsl_040_proposer_index_mismatch_false`
//!   3. `test_dsl_040_sig_a_invalid_false`
//!   4. `test_dsl_040_sig_b_invalid_false`
//!   5. `test_dsl_040_slot_mismatch_false`
//!   6. `test_dsl_040_validator_active_false`

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealVerdict, ProposerSlashing, SignedBlockHeader, ValidatorEntry,
    ValidatorView, block_signing_message, verify_proposer_appeal_headers_identical,
    verify_proposer_appeal_proposer_index_mismatch, verify_proposer_appeal_signature_a_invalid,
    verify_proposer_appeal_signature_b_invalid, verify_proposer_appeal_slot_mismatch,
    verify_proposer_appeal_validator_not_active_at_epoch,
};

struct TestValidator {
    pk: PublicKey,
    activation: u64,
    exit: u64,
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
        self.activation
    }
    fn exit_epoch(&self) -> u64 {
        self.exit
    }
    fn is_active_at_epoch(&self, epoch: u64) -> bool {
        epoch >= self.activation && epoch < self.exit
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

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn make_header(height: u64, proposer_index: u32, state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        height,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_byte; 32]),
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

fn sign_header(sk: &SecretKey, header: &L2BlockHeader, nid: &Bytes32) -> Vec<u8> {
    let msg = block_signing_message(nid, header.epoch, &header.hash(), header.proposer_index);
    chia_bls::sign(sk, msg).to_bytes().to_vec()
}

/// Genuine proposer-equivocation evidence: same slot, same proposer,
/// different content, valid signatures. View has proposer active at
/// header.epoch=3.
fn genuine() -> (ProposerSlashing, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = make_header(100, 9, 0xA1);
    let header_b = make_header(100, 9, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(
        9,
        TestValidator {
            pk,
            activation: 0,
            exit: u64::MAX,
        },
    );

    let ev = ProposerSlashing {
        signed_header_a: SignedBlockHeader {
            message: header_a,
            signature: sig_a,
        },
        signed_header_b: SignedBlockHeader {
            message: header_b,
            signature: sig_b,
        },
    };
    (ev, MapView(map))
}

fn assert_rejected(verdict: AppealVerdict) {
    assert_eq!(
        verdict,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-040 row 1: HeadersIdentical ground on distinct headers →
/// Rejected.
#[test]
fn test_dsl_040_headers_identical_false_claim_rejected() {
    let (ev, _view) = genuine();
    assert_rejected(verify_proposer_appeal_headers_identical(&ev));
}

/// DSL-040 row 2: ProposerIndexMismatch ground with matching
/// indices → Rejected.
#[test]
fn test_dsl_040_proposer_index_mismatch_false() {
    let (ev, _view) = genuine();
    assert_rejected(verify_proposer_appeal_proposer_index_mismatch(&ev));
}

/// DSL-040 row 3: SignatureAInvalid ground with genuine sig_a →
/// Rejected.
#[test]
fn test_dsl_040_sig_a_invalid_false() {
    let (ev, view) = genuine();
    assert_rejected(verify_proposer_appeal_signature_a_invalid(
        &ev,
        &view,
        &network_id(),
    ));
}

/// DSL-040 row 4: SignatureBInvalid ground with genuine sig_b →
/// Rejected.
#[test]
fn test_dsl_040_sig_b_invalid_false() {
    let (ev, view) = genuine();
    assert_rejected(verify_proposer_appeal_signature_b_invalid(
        &ev,
        &view,
        &network_id(),
    ));
}

/// DSL-040 row 5: SlotMismatch ground with same slot → Rejected.
#[test]
fn test_dsl_040_slot_mismatch_false() {
    let (ev, _view) = genuine();
    assert_rejected(verify_proposer_appeal_slot_mismatch(&ev));
}

/// DSL-040 row 6: ValidatorNotActiveAtEpoch with active validator →
/// Rejected.
#[test]
fn test_dsl_040_validator_active_false() {
    let (ev, view) = genuine();
    assert_rejected(verify_proposer_appeal_validator_not_active_at_epoch(
        &ev, &view,
    ));
}
