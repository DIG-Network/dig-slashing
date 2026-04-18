//! Requirement DSL-042: `AttesterAppealGround::NotSlashableByPredicate`
//! sustains when NEITHER double-vote NOR surround-vote holds.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! DSL-017 rejection path (`AttesterSlashingNotSlashable`) inverted
//! into an appeal ground. A verifier bug admitting non-slashable
//! attester evidence MUST be reversible here.
//!
//! # Test matrix (maps to DSL-042 Test Plan)
//!
//!   1. `test_dsl_042_no_predicate_sustained` — disjoint epochs
//!   2. `test_dsl_042_double_vote_rejected`
//!   3. `test_dsl_042_surround_rejected` — a surrounds b
//!   4. `test_dsl_042_mirror_surround_rejected` — b surrounds a

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing,
    BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    verify_attester_appeal_not_slashable_by_predicate,
};

fn data(source_epoch: u64, target_epoch: u64, head_byte: u8) -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([head_byte; 32]),
        source: Checkpoint {
            epoch: source_epoch,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: target_epoch,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}

fn att(indices: Vec<u32>, d: AttestationData) -> IndexedAttestation {
    IndexedAttestation {
        attesting_indices: indices,
        data: d,
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

fn ev(a: AttestationData, b: AttestationData) -> AttesterSlashing {
    AttesterSlashing {
        attestation_a: att(vec![1, 2, 3], a),
        attestation_b: att(vec![1, 2, 3], b),
    }
}

/// DSL-042 row 1: disjoint epoch windows + different targets → no
/// predicate holds → Sustained.
#[test]
fn test_dsl_042_no_predicate_sustained() {
    // a: src=1, tgt=2; b: src=3, tgt=4 — no overlap, different targets.
    let evidence = ev(data(1, 2, 0xA1), data(3, 4, 0xB2));
    assert_eq!(
        verify_attester_appeal_not_slashable_by_predicate(&evidence),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::NotSlashableByPredicate,
        },
    );
}

/// DSL-042 row 2: double-vote holds (same target, different data) →
/// Rejected.
#[test]
fn test_dsl_042_double_vote_rejected() {
    let evidence = ev(data(2, 3, 0xA1), data(2, 3, 0xB2));
    assert_eq!(
        verify_attester_appeal_not_slashable_by_predicate(&evidence),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-042 row 3: a surrounds b (src_a<src_b AND tgt_a>tgt_b) →
/// Rejected.
#[test]
fn test_dsl_042_surround_rejected() {
    let evidence = ev(data(1, 10, 0xA1), data(3, 7, 0xB2));
    assert_eq!(
        verify_attester_appeal_not_slashable_by_predicate(&evidence),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-042 row 4: mirror — b surrounds a.
#[test]
fn test_dsl_042_mirror_surround_rejected() {
    let evidence = ev(data(5, 7, 0xA1), data(1, 10, 0xB2));
    assert_eq!(
        verify_attester_appeal_not_slashable_by_predicate(&evidence),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}
