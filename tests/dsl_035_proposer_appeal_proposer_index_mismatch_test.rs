//! Requirement DSL-035: `ProposerAppealGround::ProposerIndexMismatch`
//! sustains an appeal when `header_a.proposer_index !=
//! header_b.proposer_index`.
//!
//! Traces to: docs/resources/SPEC.md §6.2, §22.4.
//!
//! # Role
//!
//! DSL-013 precondition 2 requires matching proposer indices; a
//! verifier bug that admits mismatched-proposer evidence MUST be
//! reversible via this appeal.
//!
//! # Test matrix (maps to DSL-035 Test Plan)
//!
//!   1. `test_dsl_035_different_proposer_sustained`
//!   2. `test_dsl_035_matching_proposer_rejected`
//!   3. `test_dsl_035_off_by_one`
//!   4. `test_dsl_035_deterministic`

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, ProposerSlashing,
    SignedBlockHeader, verify_proposer_appeal_proposer_index_mismatch,
};

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

fn signed(proposer_index: u32, state_byte: u8) -> SignedBlockHeader {
    SignedBlockHeader {
        message: make_header(proposer_index, state_byte),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

/// DSL-035 row 1: different indices → Sustained.
#[test]
fn test_dsl_035_different_proposer_sustained() {
    let ev = ProposerSlashing {
        signed_header_a: signed(9, 0xA1),
        signed_header_b: signed(10, 0xA1),
    };
    assert_eq!(
        verify_proposer_appeal_proposer_index_mismatch(&ev),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ProposerIndexMismatch,
        },
    );
}

/// DSL-035 row 2: matching indices → Rejected.
#[test]
fn test_dsl_035_matching_proposer_rejected() {
    let ev = ProposerSlashing {
        signed_header_a: signed(9, 0xA1),
        signed_header_b: signed(9, 0xB2), // same proposer, different content
    };
    assert_eq!(
        verify_proposer_appeal_proposer_index_mismatch(&ev),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-035 row 3: off-by-one mismatch → Sustained.
#[test]
fn test_dsl_035_off_by_one() {
    let ev = ProposerSlashing {
        signed_header_a: signed(42, 0xA1),
        signed_header_b: signed(43, 0xA1),
    };
    assert!(matches!(
        verify_proposer_appeal_proposer_index_mismatch(&ev),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ProposerIndexMismatch
        },
    ));
}

/// DSL-035 row 4: deterministic — two calls identical.
#[test]
fn test_dsl_035_deterministic() {
    let ev = ProposerSlashing {
        signed_header_a: signed(9, 0xA1),
        signed_header_b: signed(10, 0xB2),
    };
    let v1 = verify_proposer_appeal_proposer_index_mismatch(&ev);
    let v2 = verify_proposer_appeal_proposer_index_mismatch(&ev);
    assert_eq!(v1, v2);
}
