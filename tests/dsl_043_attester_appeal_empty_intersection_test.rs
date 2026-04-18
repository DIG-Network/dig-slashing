//! Requirement DSL-043: `AttesterAppealGround::EmptyIntersection`
//! sustains when the two attestations share no validator indices.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! DSL-016 rejection path (`EmptySlashableIntersection`) inverted
//! into an appeal ground.
//!
//! # Test matrix (maps to DSL-043 Test Plan)
//!
//!   1. `test_dsl_043_disjoint_sustained` — [1,2] ∩ [3,4] = ∅
//!   2. `test_dsl_043_overlap_rejected` — [1,2] ∩ [2,3] = {2}
//!   3. `test_dsl_043_identical_rejected` — same indices

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing,
    BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation, verify_attester_appeal_empty_intersection,
};

fn data() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x11u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}

fn att(indices: Vec<u32>) -> IndexedAttestation {
    IndexedAttestation {
        attesting_indices: indices,
        data: data(),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

fn ev(a: Vec<u32>, b: Vec<u32>) -> AttesterSlashing {
    AttesterSlashing {
        attestation_a: att(a),
        attestation_b: att(b),
    }
}

/// DSL-043 row 1: disjoint indices → Sustained.
#[test]
fn test_dsl_043_disjoint_sustained() {
    let evidence = ev(vec![1, 2], vec![3, 4]);
    assert_eq!(
        verify_attester_appeal_empty_intersection(&evidence),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::EmptyIntersection,
        },
    );
}

/// DSL-043 row 2: non-empty intersection → Rejected.
#[test]
fn test_dsl_043_overlap_rejected() {
    let evidence = ev(vec![1, 2], vec![2, 3]);
    assert_eq!(
        verify_attester_appeal_empty_intersection(&evidence),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-043 row 3: identical index sets → full overlap → Rejected.
#[test]
fn test_dsl_043_identical_rejected() {
    let evidence = ev(vec![1, 2, 3], vec![1, 2, 3]);
    assert_eq!(
        verify_attester_appeal_empty_intersection(&evidence),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}
