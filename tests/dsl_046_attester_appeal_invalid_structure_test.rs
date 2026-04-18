//! Requirement DSL-046: `AttesterAppealGround::InvalidIndexedAttestationStructure`
//! sustains when `validate_structure()` (DSL-005) fails on either
//! attestation.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! Inverts the DSL-005 rejection path into an appeal ground. A slash
//! landed despite the evidence carrying a structurally-invalid
//! `IndexedAttestation` — the manager should have rejected the
//! evidence at DSL-014/015 entry, so the slash is wrong.
//!
//! # Test matrix (maps to DSL-046 Test Plan — one row per DSL-005
//! failure leg, plus the well-formed negative control):
//!
//!   1. `test_dsl_046_non_ascending_sustained` — `[3, 2, 1]`
//!   2. `test_dsl_046_duplicate_sustained` — `[1, 1, 2]`
//!   3. `test_dsl_046_empty_sustained` — `[]`
//!   4. `test_dsl_046_over_cap_sustained` — 2049 indices
//!      (MAX_VALIDATORS_PER_COMMITTEE = 2048)
//!   5. `test_dsl_046_bad_sig_width_sustained` — 95-byte sig
//!   6. `test_dsl_046_well_formed_rejected` — determinism guard
//!
//! Each positive row plants the defect on side A with a well-formed
//! side B, so the OR-disjunction in the verifier is exercised from
//! the A leg; the well-formed row plants both sides clean.

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing,
    BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation, MAX_VALIDATORS_PER_COMMITTEE,
    verify_attester_appeal_invalid_indexed_attestation_structure,
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

/// Well-formed attestation with a 96-byte placeholder signature.
/// Signature bytes are NOT cryptographically valid — irrelevant for
/// DSL-046 since only structural validation is checked.
fn ok_att() -> IndexedAttestation {
    IndexedAttestation {
        attesting_indices: vec![1, 2, 3],
        data: data(),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

fn att_with(indices: Vec<u32>, sig_len: usize) -> IndexedAttestation {
    IndexedAttestation {
        attesting_indices: indices,
        data: data(),
        signature: vec![0xABu8; sig_len],
    }
}

fn ev(a: IndexedAttestation, b: IndexedAttestation) -> AttesterSlashing {
    AttesterSlashing {
        attestation_a: a,
        attestation_b: b,
    }
}

fn assert_sustained(evidence: &AttesterSlashing) {
    assert_eq!(
        verify_attester_appeal_invalid_indexed_attestation_structure(evidence),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::InvalidIndexedAttestationStructure,
        },
    );
}

/// DSL-046 row 1: `[3, 2, 1]` → non-ascending → Sustained.
#[test]
fn test_dsl_046_non_ascending_sustained() {
    assert_sustained(&ev(att_with(vec![3, 2, 1], BLS_SIGNATURE_SIZE), ok_att()));
}

/// DSL-046 row 2: `[1, 1, 2]` → duplicate → Sustained. Proves the
/// `w[0] >= w[1]` guard catches equality in addition to descent.
#[test]
fn test_dsl_046_duplicate_sustained() {
    assert_sustained(&ev(att_with(vec![1, 1, 2], BLS_SIGNATURE_SIZE), ok_att()));
}

/// DSL-046 row 3: `[]` → empty → Sustained.
#[test]
fn test_dsl_046_empty_sustained() {
    assert_sustained(&ev(att_with(vec![], BLS_SIGNATURE_SIZE), ok_att()));
}

/// DSL-046 row 4: 2049 indices → over cap → Sustained. Uses
/// `MAX_VALIDATORS_PER_COMMITTEE + 1` so the test auto-tracks any
/// future cap change.
#[test]
fn test_dsl_046_over_cap_sustained() {
    let over_cap: Vec<u32> = (0u32..=(MAX_VALIDATORS_PER_COMMITTEE as u32)).collect();
    assert_eq!(over_cap.len(), MAX_VALIDATORS_PER_COMMITTEE + 1);
    assert_sustained(&ev(att_with(over_cap, BLS_SIGNATURE_SIZE), ok_att()));
}

/// DSL-046 row 5: 95-byte signature → wrong sig width → Sustained.
/// DSL-005 rejects any `signature.len() != BLS_SIGNATURE_SIZE`.
#[test]
fn test_dsl_046_bad_sig_width_sustained() {
    assert_sustained(&ev(att_with(vec![1, 2, 3], 95), ok_att()));
}

/// DSL-046 row 6: both sides well-formed → Rejected. Determinism
/// guard — verifier is not a constant Sustained. Any non-equal
/// `attesting_indices` is fine since this ground does NOT care about
/// intersection or overlap; DSL-043 owns that.
#[test]
fn test_dsl_046_well_formed_rejected() {
    let evidence = ev(
        att_with(vec![1, 2, 3], BLS_SIGNATURE_SIZE),
        att_with(vec![4, 5, 6], BLS_SIGNATURE_SIZE),
    );
    assert_eq!(
        verify_attester_appeal_invalid_indexed_attestation_structure(&evidence),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}
