//! Requirement DSL-012: `verify_evidence` rejects with
//! `SlashingError::ReporterIsAccused(index)` when
//! `evidence.reporter_validator_index ∈ evidence.slashable_validators()`.
//!
//! Traces to: docs/resources/SPEC.md §5.1, §22.2.
//!
//! # Role
//!
//! Cheap precondition that runs AFTER OffenseTooOld (DSL-011) and BEFORE
//! any per-payload verifier. Blocks a validator from self-reporting as
//! the whistleblower to farm the reward (DSL-025 reward routing).
//!
//! Ordering matters: if this check ran after signature verification,
//! the self-accuse attack would still cost attackers no reward but
//! would cost the honest node full BLS work per envelope — cheap
//! denial-of-service. Putting it before BLS keeps the mempool bounded.
//!
//! # Payload coverage
//!
//! The check is payload-agnostic — it queries
//! `SlashingEvidence::slashable_validators()` (DSL-010), which handles
//! per-variant dispatch. Three scenarios must reject:
//!
//!   1. Proposer — reporter_index == proposer_index.
//!   2. InvalidBlock — reporter_index == proposer_index.
//!   3. Attester — reporter_index in the sorted intersection.
//!
//! # Test matrix (maps to DSL-012 Test Plan)
//!
//!   1. `test_dsl_012_reporter_self_accuse_rejected` — Proposer self-accuse
//!   2. `test_dsl_012_reporter_not_accused_passes` — distinct reporter
//!   3. `test_dsl_012_attester_slashing_with_reporter_in_intersection`
//!   4. `test_dsl_012_invalid_block_self_accuse_rejected` — InvalidBlock
//!   5. `test_dsl_012_error_carries_index` — variant payload check
//!   6. `test_dsl_012_runs_after_offense_too_old` — ordering invariant

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    InvalidBlockProof, InvalidBlockReason, OffenseType, ProposerSlashing, SLASH_LOOKBACK_EPOCHS,
    SignedBlockHeader, SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry,
    ValidatorView, verify_evidence,
};

struct EmptyValidators;

impl ValidatorView for EmptyValidators {
    fn get(&self, _index: u32) -> Option<&dyn ValidatorEntry> {
        None
    }
    fn get_mut(&mut self, _index: u32) -> Option<&mut dyn ValidatorEntry> {
        None
    }
    fn len(&self) -> usize {
        0
    }
}

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn sample_header(proposer_index: u32) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
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

fn sample_signed_header(proposer_index: u32) -> SignedBlockHeader {
    SignedBlockHeader {
        message: sample_header(proposer_index),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

fn sample_attestation_data() -> AttestationData {
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

fn proposer_envelope(reporter: u32, proposer: u32) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 50,
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: sample_signed_header(proposer),
            signed_header_b: sample_signed_header(proposer),
        }),
    }
}

fn invalid_block_envelope(reporter: u32, proposer: u32) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::InvalidBlock,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 50,
        payload: SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: sample_signed_header(proposer),
            failure_witness: vec![1, 2, 3],
            failure_reason: InvalidBlockReason::BadStateRoot,
        }),
    }
}

fn attester_envelope(reporter: u32, indices_a: Vec<u32>, indices_b: Vec<u32>) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 50,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: IndexedAttestation {
                attesting_indices: indices_a,
                data: sample_attestation_data(),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            attestation_b: IndexedAttestation {
                attesting_indices: indices_b,
                data: sample_attestation_data(),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
        }),
    }
}

/// DSL-012 row 1: reporter equals proposer → rejected.
#[test]
fn test_dsl_012_reporter_self_accuse_rejected() {
    let ev = proposer_envelope(9, 9);
    let vv = EmptyValidators;
    let err = verify_evidence(&ev, &vv, &network_id(), 50).expect_err("self-accuse must reject");
    assert_eq!(err, SlashingError::ReporterIsAccused(9));
}

/// DSL-012 row 2: reporter distinct from any accused index → passes
/// the reporter-self-accuse check. InvalidBlock payload is used because
/// its downstream verifier is still placeholder-accept (DSL-018..020
/// land later); Proposer / Attester would drive their real verifiers
/// (DSL-013 / DSL-014), which is out of scope for DSL-012.
#[test]
fn test_dsl_012_reporter_not_accused_passes() {
    let ev = invalid_block_envelope(100, 9); // reporter 100, accused 9
    let vv = EmptyValidators;
    let result = verify_evidence(&ev, &vv, &network_id(), 50);
    assert!(result.is_ok(), "disjoint reporter must pass: {result:?}");
}

/// DSL-012 row 3: AttesterSlashing where reporter appears in BOTH
/// attestations → reporter is in the slashable intersection → rejected.
///
/// Intersection of `{1, 3, 5, 7}` and `{3, 5, 7, 9}` is `{3, 5, 7}`.
/// Reporter = 5 is in that set.
#[test]
fn test_dsl_012_attester_slashing_with_reporter_in_intersection() {
    let ev = attester_envelope(5, vec![1, 3, 5, 7], vec![3, 5, 7, 9]);
    let vv = EmptyValidators;
    let err = verify_evidence(&ev, &vv, &network_id(), 50)
        .expect_err("reporter in intersection must reject");
    assert_eq!(err, SlashingError::ReporterIsAccused(5));
}

/// DSL-012 row 3b: AttesterSlashing where reporter is in ONE attestation
/// but not the intersection → passes the reporter-self-accuse check.
///
/// Example: reporter = 1 is in attestation_a but not attestation_b, so
/// not in the intersection. The verifier later rejects the payload for
/// an unrelated reason (identical attestation data → not slashable
/// under either predicate) — we only assert that ReporterIsAccused is
/// NOT the error, which proves DSL-012 passed.
#[test]
fn test_dsl_012_attester_reporter_only_in_one_attestation_passes() {
    let ev = attester_envelope(1, vec![1, 3, 5, 7], vec![3, 5, 7, 9]);
    let vv = EmptyValidators;
    let result = verify_evidence(&ev, &vv, &network_id(), 50);
    // DSL-012 passed iff the error is NOT ReporterIsAccused. The payload
    // still fails downstream predicate/BLS checks; that is out of scope
    // for this suite.
    match result {
        Ok(_) => {}
        Err(SlashingError::ReporterIsAccused(_)) => {
            panic!("DSL-012 must not reject: reporter not in intersection");
        }
        Err(_) => {}
    }
}

/// DSL-012 row 4: InvalidBlock self-accuse rejected.
#[test]
fn test_dsl_012_invalid_block_self_accuse_rejected() {
    let ev = invalid_block_envelope(13, 13);
    let vv = EmptyValidators;
    let err = verify_evidence(&ev, &vv, &network_id(), 50)
        .expect_err("InvalidBlock self-accuse must reject");
    assert_eq!(err, SlashingError::ReporterIsAccused(13));
}

/// DSL-012 row 5: error carries the exact reporter index.
#[test]
fn test_dsl_012_error_carries_index() {
    let ev = proposer_envelope(42, 42);
    let vv = EmptyValidators;
    let err = verify_evidence(&ev, &vv, &network_id(), 50).unwrap_err();
    match err {
        SlashingError::ReporterIsAccused(idx) => assert_eq!(idx, 42),
        other => panic!("wrong variant: {other:?}"),
    }
}

/// DSL-012 row 6: OffenseTooOld check runs BEFORE ReporterIsAccused.
///
/// Construct an envelope that violates BOTH: self-accuse AND older than
/// lookback. Must surface OffenseTooOld (cheap lookback filter runs first).
#[test]
fn test_dsl_012_runs_after_offense_too_old() {
    // Self-accuse + very old evidence.
    let ev = proposer_envelope(9, 9); // self-accuse
    let vv = EmptyValidators;
    let current_epoch = 10_000;
    // offense_epoch far older than lookback boundary: 10_000 - 1_000 = 9_000;
    // envelope.epoch = 50, so 50 + 1_000 = 1_050 < 10_000 → OffenseTooOld.
    let err = verify_evidence(&ev, &vv, &network_id(), current_epoch).unwrap_err();
    assert!(
        matches!(err, SlashingError::OffenseTooOld { .. }),
        "OffenseTooOld must surface first; got {err:?}",
    );

    // Sanity: with both checks in range (recent + self-accuse),
    // ReporterIsAccused surfaces.
    let ev_recent = proposer_envelope(9, 9);
    let err2 = verify_evidence(
        &ev_recent,
        &vv,
        &network_id(),
        ev_recent.epoch + SLASH_LOOKBACK_EPOCHS,
    )
    .unwrap_err();
    assert!(
        matches!(err2, SlashingError::ReporterIsAccused(9)),
        "recent self-accuse must hit DSL-012: {err2:?}",
    );
}
