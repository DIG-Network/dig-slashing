//! Requirement DSL-041: `AttesterAppealGround::AttestationsIdentical`
//! sustains when the two `IndexedAttestation` values are byte-equal.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! DSL-014 verifier rejects byte-identical attestations as
//! `InvalidAttesterSlashing("identical")`. A verifier bug admitting
//! such evidence MUST be reversible.
//!
//! # Test matrix (maps to DSL-041 Test Plan)
//!
//!   1. `test_dsl_041_identical_sustained`
//!   2. `test_dsl_041_distinct_rejected`
//!   3. `test_dsl_041_sig_only_difference_still_distinct`

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing,
    BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    verify_attester_appeal_attestations_identical,
};

fn data(target_epoch: u64, head_byte: u8) -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([head_byte; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: target_epoch,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}

fn attestation(
    indices: Vec<u32>,
    target_epoch: u64,
    head_byte: u8,
    sig_byte: u8,
) -> IndexedAttestation {
    IndexedAttestation {
        attesting_indices: indices,
        data: data(target_epoch, head_byte),
        signature: vec![sig_byte; BLS_SIGNATURE_SIZE],
    }
}

/// DSL-041 row 1: byte-equal attestations → Sustained.
#[test]
fn test_dsl_041_identical_sustained() {
    let att = attestation(vec![1, 2, 3], 3, 0xA1, 0x55);
    let ev = AttesterSlashing {
        attestation_a: att.clone(),
        attestation_b: att,
    };
    assert_eq!(
        verify_attester_appeal_attestations_identical(&ev),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::AttestationsIdentical,
        },
    );
}

/// DSL-041 row 2: distinct attestation data → Rejected.
#[test]
fn test_dsl_041_distinct_rejected() {
    let ev = AttesterSlashing {
        attestation_a: attestation(vec![1, 2, 3], 3, 0xA1, 0x55),
        attestation_b: attestation(vec![1, 2, 3], 3, 0xB2, 0x55),
    };
    assert_eq!(
        verify_attester_appeal_attestations_identical(&ev),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-041 row 3: same data but different signature bytes → still
/// Rejected. Byte-wise equality includes signature field.
#[test]
fn test_dsl_041_sig_only_difference_still_distinct() {
    let ev = AttesterSlashing {
        attestation_a: attestation(vec![1, 2, 3], 3, 0xA1, 0x55),
        attestation_b: attestation(vec![1, 2, 3], 3, 0xA1, 0xAA),
    };
    assert_eq!(
        verify_attester_appeal_attestations_identical(&ev),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}
