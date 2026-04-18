//! Requirement DSL-038: `ProposerAppealGround::SlotMismatch` sustains
//! when the two signed headers report different heights.
//!
//! Traces to: docs/resources/SPEC.md §6.2, §22.4.
//!
//! # Role
//!
//! DSL-013 precondition 1 requires the two signed headers to share a
//! slot. Slot is represented by `L2BlockHeader.height` in the L2
//! protocol. A verifier bug admitting evidence at different heights
//! MUST be reversible via this ground.
//!
//! # Test matrix (maps to DSL-038 Test Plan)
//!
//!   1. `test_dsl_038_different_heights_sustained`
//!   2. `test_dsl_038_same_height_rejected`
//!   3. `test_dsl_038_adjacent_heights`

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, ProposerSlashing,
    SignedBlockHeader, verify_proposer_appeal_slot_mismatch,
};

fn make_header(height: u64, state_byte: u8) -> L2BlockHeader {
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
        9,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn signed(height: u64, state_byte: u8) -> SignedBlockHeader {
    SignedBlockHeader {
        message: make_header(height, state_byte),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

/// DSL-038 row 1: different heights → Sustained.
#[test]
fn test_dsl_038_different_heights_sustained() {
    let ev = ProposerSlashing {
        signed_header_a: signed(100, 0xA1),
        signed_header_b: signed(101, 0xA1),
    };
    assert_eq!(
        verify_proposer_appeal_slot_mismatch(&ev),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SlotMismatch,
        },
    );
}

/// DSL-038 row 2: same height → Rejected.
#[test]
fn test_dsl_038_same_height_rejected() {
    let ev = ProposerSlashing {
        signed_header_a: signed(100, 0xA1),
        signed_header_b: signed(100, 0xB2), // different content, same height
    };
    assert_eq!(
        verify_proposer_appeal_slot_mismatch(&ev),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-038 row 3: adjacent heights (off-by-one) → Sustained.
#[test]
fn test_dsl_038_adjacent_heights() {
    let ev = ProposerSlashing {
        signed_header_a: signed(42, 0xA1),
        signed_header_b: signed(43, 0xB2),
    };
    assert!(matches!(
        verify_proposer_appeal_slot_mismatch(&ev),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SlotMismatch
        },
    ));
}
