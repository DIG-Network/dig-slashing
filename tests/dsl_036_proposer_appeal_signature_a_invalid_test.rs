//! Requirement DSL-036: `ProposerAppealGround::SignatureAInvalid`
//! sustains when header A's BLS signature fails to verify under the
//! proposer's pubkey against `block_signing_message`.
//!
//! Traces to: docs/resources/SPEC.md §6.2, §22.4.
//!
//! # Role
//!
//! DSL-013 precondition 6 (both sigs verify) is the invariant this
//! ground inverts. A verifier bug admitting evidence with a bad
//! signature MUST be reversible.
//!
//! # Test matrix (maps to DSL-036 Test Plan)
//!
//!   1. `test_dsl_036_corrupted_sig_a_sustained`
//!   2. `test_dsl_036_valid_sig_a_rejected`
//!   3. `test_dsl_036_wrong_key_sustained`
//!   4. `test_dsl_036_network_id_binding`
//!   5. `test_dsl_036_unknown_validator_sustained`
//!   6. `test_dsl_036_bad_sig_width_sustained`

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, ProposerSlashing,
    SignedBlockHeader, ValidatorEntry, ValidatorView, block_signing_message,
    verify_proposer_appeal_signature_a_invalid,
};

struct TestValidator {
    pk: PublicKey,
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
        0
    }
    fn exit_epoch(&self) -> u64 {
        u64::MAX
    }
    fn is_active_at_epoch(&self, _: u64) -> bool {
        true
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

fn make_header(proposer_index: u32, state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
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

/// Build valid evidence + view where the accused pubkey matches the
/// signing key.
fn valid(proposer_index: u32) -> (ProposerSlashing, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = make_header(proposer_index, 0xA1);
    let header_b = make_header(proposer_index, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(proposer_index, TestValidator { pk });

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

/// DSL-036 row 1: corrupted sig_a → Sustained.
#[test]
fn test_dsl_036_corrupted_sig_a_sustained() {
    let (mut ev, view) = valid(9);
    ev.signed_header_a.signature[0] ^= 0xFF;
    let verdict = verify_proposer_appeal_signature_a_invalid(&ev, &view, &network_id());
    assert_eq!(
        verdict,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SignatureAInvalid,
        },
    );
}

/// DSL-036 row 2: valid sig_a → Rejected (ground does not hold).
#[test]
fn test_dsl_036_valid_sig_a_rejected() {
    let (ev, view) = valid(9);
    let verdict = verify_proposer_appeal_signature_a_invalid(&ev, &view, &network_id());
    assert_eq!(
        verdict,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-036 row 3: sig_a signed by wrong key → Sustained.
#[test]
fn test_dsl_036_wrong_key_sustained() {
    let (mut ev, view) = valid(9);
    let wrong_sk = make_sk(0xEE);
    ev.signed_header_a.signature =
        sign_header(&wrong_sk, &ev.signed_header_a.message, &network_id());
    let verdict = verify_proposer_appeal_signature_a_invalid(&ev, &view, &network_id());
    assert!(matches!(
        verdict,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SignatureAInvalid
        },
    ));
}

/// DSL-036 row 4: network_id domain binding — sig signed under
/// testnet does NOT verify under mainnet id.
#[test]
fn test_dsl_036_network_id_binding() {
    let (ev, view) = valid(9);
    let other_nid = Bytes32::new([0xBBu8; 32]);
    let verdict = verify_proposer_appeal_signature_a_invalid(&ev, &view, &other_nid);
    assert!(matches!(
        verdict,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SignatureAInvalid
        },
    ));
}

/// DSL-036: unknown validator → Sustained (no pubkey to verify against).
#[test]
fn test_dsl_036_unknown_validator_sustained() {
    let (ev, _) = valid(9);
    let empty = MapView(HashMap::new());
    let verdict = verify_proposer_appeal_signature_a_invalid(&ev, &empty, &network_id());
    assert!(matches!(
        verdict,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SignatureAInvalid
        },
    ));
}

/// DSL-036: signature with bad width → Sustained.
#[test]
fn test_dsl_036_bad_sig_width_sustained() {
    let (mut ev, view) = valid(9);
    ev.signed_header_a
        .signature
        .truncate(BLS_SIGNATURE_SIZE - 1);
    let verdict = verify_proposer_appeal_signature_a_invalid(&ev, &view, &network_id());
    assert!(matches!(
        verdict,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SignatureAInvalid
        },
    ));
}
