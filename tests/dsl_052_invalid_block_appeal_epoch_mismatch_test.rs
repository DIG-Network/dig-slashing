//! Requirement DSL-052: `InvalidBlockAppealGround::EvidenceEpochMismatch`
//! sustains when `signed_header.message.epoch != SlashingEvidence::epoch`.
//!
//! Traces to: docs/resources/SPEC.md §6.4, §22.6.
//!
//! # Role
//!
//! Inverts DSL-019 (evidence admission epoch-mismatch rejection)
//! into an appeal ground. Pure local check — no oracle, no BLS.
//! If the envelope's claimed epoch disagrees with the header's
//! internal epoch, the evidence is inconsistent and the slash is
//! reverted.
//!
//! # Test matrix (maps to DSL-052 Test Plan)
//!
//!   1. `test_dsl_052_mismatch_sustained` — header=5, envelope=6
//!   2. `test_dsl_052_match_rejected` — equal epochs
//!   3. `test_dsl_052_off_by_one` — differ by 1 (boundary)

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, InvalidBlockProof,
    InvalidBlockReason, SignedBlockHeader, verify_invalid_block_appeal_evidence_epoch_mismatch,
};

fn header_with_epoch(epoch: u64) -> L2BlockHeader {
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
        1,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn evidence_with_header_epoch(epoch: u64) -> InvalidBlockProof {
    InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: header_with_epoch(epoch),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    }
}

/// DSL-052 row 1: header.epoch = 5, envelope.epoch = 6 → mismatch
/// → Sustained.
#[test]
fn test_dsl_052_mismatch_sustained() {
    let evidence = evidence_with_header_epoch(5);
    assert_eq!(
        verify_invalid_block_appeal_evidence_epoch_mismatch(&evidence, 6),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::EvidenceEpochMismatch,
        },
    );
}

/// DSL-052 row 2: equal epochs (both = 5) → Rejected. Determinism
/// guard — verifier is not constant Sustained.
#[test]
fn test_dsl_052_match_rejected() {
    let evidence = evidence_with_header_epoch(5);
    assert_eq!(
        verify_invalid_block_appeal_evidence_epoch_mismatch(&evidence, 5),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-052 row 3: off-by-one in EITHER direction → Sustained. The
/// predicate uses strict inequality so `5 vs 4` and `5 vs 6` both
/// trip. Proves the check is not accidentally `<` or `>`.
#[test]
fn test_dsl_052_off_by_one() {
    let evidence = evidence_with_header_epoch(5);
    let sustained = AppealVerdict::Sustained {
        reason: AppealSustainReason::EvidenceEpochMismatch,
    };
    assert_eq!(
        verify_invalid_block_appeal_evidence_epoch_mismatch(&evidence, 4),
        sustained
    );
    assert_eq!(
        verify_invalid_block_appeal_evidence_epoch_mismatch(&evidence, 6),
        sustained
    );
}
