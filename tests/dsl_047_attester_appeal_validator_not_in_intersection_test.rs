//! Requirement DSL-047: `AttesterAppealGround::ValidatorNotInIntersection`
//! sustains when a named validator index is NOT in the DSL-007
//! sorted intersection of the two attestations.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! Per-validator appeal — unlike the other attester-appeal grounds
//! (DSL-041..046) which attack the evidence as a whole, this ground
//! attacks the verifier's choice to include a SPECIFIC index in the
//! slashable set. A sustain here rescues ONLY the named index; the
//! other originally-slashed indices retain their slash state
//! (DSL-064 adjudicator wiring).
//!
//! # Test matrix (maps to DSL-047 Test Plan)
//!
//!   1. `test_dsl_047_index_not_in_intersection_sustained`
//!      — intersection = {2, 3}, named = 5 → Sustained
//!   2. `test_dsl_047_index_in_intersection_rejected`
//!      — intersection = {2, 3}, named = 3 → Rejected
//!   3. `test_dsl_047_per_validator_revert_scope`
//!      — same evidence, three named indices: in/out/edge of
//!      intersection each produce the correct independent verdict.
//!      Proves the verifier is parameterised on `validator_index`
//!      rather than evidence alone — the per-validator adjudicator
//!      revert scope (DSL-064) gets this "for free".

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing,
    BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    verify_attester_appeal_validator_not_in_intersection,
};

fn data_a() -> AttestationData {
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

/// Distinct `beacon_block_root` so the envelope is a valid
/// double-vote shape. Structural validity only matters insofar as
/// `slashable_indices()` walks `attesting_indices` — DSL-007 does
/// not require DSL-005 to have passed, but we keep the fixture
/// honest.
fn data_b() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x99u8; 32]),
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

/// Build evidence whose `slashable_indices()` (DSL-007) is exactly
/// `{2, 3}`: side A covers `[1, 2, 3]`, side B covers `[2, 3, 4]`.
/// Only 2 and 3 appear on both sides.
fn evidence_intersection_2_3() -> AttesterSlashing {
    AttesterSlashing {
        attestation_a: IndexedAttestation {
            attesting_indices: vec![1, 2, 3],
            data: data_a(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        attestation_b: IndexedAttestation {
            attesting_indices: vec![2, 3, 4],
            data: data_b(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
    }
}

/// DSL-047 row 1: named = 5 ∉ {2, 3} → Sustained.
#[test]
fn test_dsl_047_index_not_in_intersection_sustained() {
    let evidence = evidence_intersection_2_3();
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 5),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ValidatorNotInIntersection,
        },
    );
}

/// DSL-047 row 2: named = 3 ∈ {2, 3} → Rejected. Determinism guard.
#[test]
fn test_dsl_047_index_in_intersection_rejected() {
    let evidence = evidence_intersection_2_3();
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 3),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-047 row 3: per-validator scope — single `evidence`, three
/// named indices. Validates independence of the verifier's decision
/// across named indices:
/// - 2 ∈ {2, 3} → Rejected
/// - 3 ∈ {2, 3} → Rejected (second inclusion leg)
/// - 1 ∉ {2, 3} → Sustained (side-A-only index)
/// - 4 ∉ {2, 3} → Sustained (side-B-only index)
/// - 99 ∉ anything → Sustained (out-of-band index)
///
/// Same-evidence invariance is the "per-validator revert" primitive
/// DSL-064 relies on: it can call this verifier once per named
/// index and get an independent verdict each time.
#[test]
fn test_dsl_047_per_validator_revert_scope() {
    let evidence = evidence_intersection_2_3();

    let rejected = AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    };
    let sustained = AppealVerdict::Sustained {
        reason: AppealSustainReason::ValidatorNotInIntersection,
    };

    // Both intersection members → Rejected.
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 2),
        rejected
    );
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 3),
        rejected
    );

    // Side-A-only, side-B-only, out-of-band → Sustained.
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 1),
        sustained
    );
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 4),
        sustained
    );
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 99),
        sustained
    );
}
