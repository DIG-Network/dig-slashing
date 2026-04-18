//! Requirement DSL-034: `ProposerAppealGround::HeadersIdentical`
//! sustains an appeal iff the two `SignedBlockHeader.message`
//! structs are byte-equal.
//!
//! Traces to: docs/resources/SPEC.md §3.6.1, §6.2, §22.4.
//!
//! # Role
//!
//! DSL-013 rejects identical headers at admission, so a
//! `PendingSlash` carrying byte-equal headers is a verifier bug.
//! The appeal ground proves the mistake and forces a reversal
//! (DSL-070).
//!
//! # Test matrix (maps to DSL-034 Test Plan)
//!
//!   1. `test_dsl_034_identical_headers_sustained`
//!   2. `test_dsl_034_distinct_headers_rejected`
//!   3. `test_dsl_034_witness_ignored`
//!   4. `test_dsl_034_deterministic`

use chia_bls::SecretKey;
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, ProposerSlashing,
    SignedBlockHeader, block_signing_message, verify_proposer_appeal_headers_identical,
};

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn sample_header(proposer_index: u32, state_byte: u8) -> L2BlockHeader {
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

fn sign_header(sk: &SecretKey, header: &L2BlockHeader) -> Vec<u8> {
    let msg = block_signing_message(
        &network_id(),
        header.epoch,
        &header.hash(),
        header.proposer_index,
    );
    chia_bls::sign(sk, msg).to_bytes().to_vec()
}

fn signed_header(proposer_index: u32, state_byte: u8) -> SignedBlockHeader {
    let sk = SecretKey::from_seed(&[0x11u8; 32]);
    let header = sample_header(proposer_index, state_byte);
    SignedBlockHeader {
        message: header.clone(),
        signature: sign_header(&sk, &header),
    }
}

/// DSL-034 row 1: byte-equal headers → `Sustained { HeadersIdentical }`.
#[test]
fn test_dsl_034_identical_headers_sustained() {
    // Same proposer, same state byte → equal message. Different
    // signatures OK — the ground only looks at `.message`.
    let sh_a = signed_header(9, 0xA1);
    let sh_b = SignedBlockHeader {
        message: sh_a.message.clone(),
        signature: vec![0xFFu8; BLS_SIGNATURE_SIZE],
    };
    let ev = ProposerSlashing {
        signed_header_a: sh_a,
        signed_header_b: sh_b,
    };

    let verdict = verify_proposer_appeal_headers_identical(&ev);
    assert_eq!(
        verdict,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::HeadersIdentical,
        },
    );
}

/// DSL-034 row 2: distinct headers → `Rejected { GroundDoesNotHold }`.
#[test]
fn test_dsl_034_distinct_headers_rejected() {
    let sh_a = signed_header(9, 0xA1);
    let sh_b = signed_header(9, 0xB2); // different state byte → distinct header
    assert_ne!(sh_a.message, sh_b.message);
    let ev = ProposerSlashing {
        signed_header_a: sh_a,
        signed_header_b: sh_b,
    };

    let verdict = verify_proposer_appeal_headers_identical(&ev);
    assert_eq!(
        verdict,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-034 row 3: signature mutation alone does NOT change the
/// verdict — the predicate is over `.message` only.
///
/// Two versions of the same evidence: in one the signatures are
/// identical, in the other they differ. Verdict MUST match (both
/// `Sustained` because messages are equal).
#[test]
fn test_dsl_034_witness_ignored() {
    let msg = sample_header(9, 0xA1);

    let ev_same_sig = ProposerSlashing {
        signed_header_a: SignedBlockHeader {
            message: msg.clone(),
            signature: vec![0x01u8; BLS_SIGNATURE_SIZE],
        },
        signed_header_b: SignedBlockHeader {
            message: msg.clone(),
            signature: vec![0x01u8; BLS_SIGNATURE_SIZE],
        },
    };
    let ev_diff_sig = ProposerSlashing {
        signed_header_a: SignedBlockHeader {
            message: msg.clone(),
            signature: vec![0x01u8; BLS_SIGNATURE_SIZE],
        },
        signed_header_b: SignedBlockHeader {
            message: msg,
            signature: vec![0xFFu8; BLS_SIGNATURE_SIZE],
        },
    };

    assert_eq!(
        verify_proposer_appeal_headers_identical(&ev_same_sig),
        verify_proposer_appeal_headers_identical(&ev_diff_sig),
    );
}

/// DSL-034 row 4: deterministic — two calls, same verdict.
#[test]
fn test_dsl_034_deterministic() {
    let sh_a = signed_header(9, 0xA1);
    let sh_b = SignedBlockHeader {
        message: sh_a.message.clone(),
        signature: vec![0xFFu8; BLS_SIGNATURE_SIZE],
    };
    let ev = ProposerSlashing {
        signed_header_a: sh_a,
        signed_header_b: sh_b,
    };

    let v1 = verify_proposer_appeal_headers_identical(&ev);
    let v2 = verify_proposer_appeal_headers_identical(&ev);
    assert_eq!(v1, v2);
}
