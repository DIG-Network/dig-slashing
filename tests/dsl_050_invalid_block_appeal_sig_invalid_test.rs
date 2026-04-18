//! Requirement DSL-050: `InvalidBlockAppealGround::ProposerSignatureInvalid`
//! sustains when the signed header's BLS signature does NOT verify
//! over `dig_block::block_signing_message`.
//!
//! Traces to: docs/resources/SPEC.md §6.4, §22.6.
//!
//! # Role
//!
//! Pure-BLS appeal ground for the InvalidBlock offense — no oracle
//! required. The slasher claimed an invalid-block offense against
//! `signed_header.message`, but if the header's signature doesn't
//! verify then the accused validator could not have produced it;
//! the slash is reverted. Mirrors DSL-018 (evidence admission sig
//! check) inverted into an appeal.
//!
//! Under the hood, the verifier reuses the shared helper
//! `verify_proposer_appeal_signature_side` — same contract as
//! DSL-036/037/044/045 sig-check appeals, just a different sustain
//! reason tag (`ProposerSignatureInvalid`).
//!
//! # Test matrix (maps to DSL-050 Test Plan)
//!
//!   1. `test_dsl_050_corrupted_sig_sustained` — bit flip on sig
//!   2. `test_dsl_050_valid_sig_rejected` — honest sig → Rejected
//!   3. `test_dsl_050_cross_network_sustained` — sig bound to a
//!      different network_id → fails verify under canonical nid →
//!      Sustained (proves `block_signing_message` includes the
//!      network id).

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, InvalidBlockProof,
    InvalidBlockReason, SignedBlockHeader, ValidatorEntry, ValidatorView, block_signing_message,
    verify_invalid_block_appeal_proposer_signature_invalid,
};

/// Minimal validator fixture — only `public_key()` matters for the
/// BLS re-verify path; the rest are stub returns.
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
    fn is_active_at_epoch(&self, _epoch: u64) -> bool {
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

fn canonical_network() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn other_network() -> Bytes32 {
    Bytes32::new([0xBBu8; 32])
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn sample_header(proposer_index: u32, epoch: u64) -> L2BlockHeader {
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

/// Sign `header` honestly under `network_id`. Returns
/// `(evidence, view)` — view registers the signer's pubkey at
/// `proposer_index`.
fn signed_evidence(
    header: L2BlockHeader,
    network_id: &Bytes32,
    sk: &SecretKey,
) -> (InvalidBlockProof, MapView) {
    let pk = sk.public_key();
    let msg = block_signing_message(
        network_id,
        header.epoch,
        &header.hash(),
        header.proposer_index,
    );
    let sig = chia_bls::sign(sk, &msg);

    let proposer_index = header.proposer_index;
    let evidence = InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: header,
            signature: sig.to_bytes().to_vec(),
        },
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    };

    let mut map = HashMap::new();
    map.insert(proposer_index, TestValidator { pk });
    (evidence, MapView(map))
}

/// DSL-050 row 1: bit-flip the signature on an otherwise-honest
/// evidence → sig no longer verifies → Sustained.
#[test]
fn test_dsl_050_corrupted_sig_sustained() {
    let sk = make_sk(0x01);
    let (mut evidence, view) = signed_evidence(sample_header(7, 5), &canonical_network(), &sk);

    // Corrupt one byte. BLS verify may still decode the G2 point but
    // the pairing equality fails; helper sustains on any verify
    // failure.
    evidence.signed_header.signature[0] ^= 0xFF;
    assert_eq!(evidence.signed_header.signature.len(), BLS_SIGNATURE_SIZE);

    let v = verify_invalid_block_appeal_proposer_signature_invalid(
        &evidence,
        &view,
        &canonical_network(),
    );
    assert_eq!(
        v,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ProposerSignatureInvalid,
        },
    );
}

/// DSL-050 row 2: honest sig under canonical network → verifies →
/// Rejected. Determinism guard — verifier is not constant Sustained.
#[test]
fn test_dsl_050_valid_sig_rejected() {
    let sk = make_sk(0x02);
    let (evidence, view) = signed_evidence(sample_header(7, 5), &canonical_network(), &sk);

    let v = verify_invalid_block_appeal_proposer_signature_invalid(
        &evidence,
        &view,
        &canonical_network(),
    );
    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-050 row 3: header signed under `other_network()` but
/// re-checked against `canonical_network()` — the `network_id` is
/// baked into `block_signing_message`, so the pairing fails →
/// Sustained. Proves domain-separation is load-bearing in the
/// signing input and prevents cross-network replay.
#[test]
fn test_dsl_050_cross_network_sustained() {
    let sk = make_sk(0x03);
    let (evidence, view) = signed_evidence(sample_header(7, 5), &other_network(), &sk);

    // Re-verify under a DIFFERENT network id — sig was honest under
    // other_network, so the canonical-network check MUST fail.
    let v = verify_invalid_block_appeal_proposer_signature_invalid(
        &evidence,
        &view,
        &canonical_network(),
    );
    assert_eq!(
        v,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ProposerSignatureInvalid,
        },
    );
}
