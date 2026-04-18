//! Requirement DSL-072: on rejected appeal, `pending.status` MUST
//! transition to / through `ChallengeOpen { first_appeal_filed_epoch,
//! appeal_count }` with the counter incremented, and an
//! `AppealAttempt { outcome: Lost { reason_hash } }` appended to
//! `pending.appeal_history`.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Role
//!
//! Rejected appeals do NOT terminate the pending slash (unlike
//! DSL-070 sustained → Reverted). The slash persists; further
//! appeals are accepted up to `MAX_APPEAL_ATTEMPTS_PER_SLASH`.
//! Failing to bump the counter would let an appellant re-file
//! forever; failing to preserve `first_appeal_filed_epoch`
//! breaks challenge-timeline analytics.
//!
//! # Test matrix (maps to DSL-072 Test Plan)
//!
//!   1. `test_dsl_072_first_rejected_sets_open_count_1` —
//!      `Accepted` + reject → `ChallengeOpen { count: 1 }`
//!   2. `test_dsl_072_second_rejected_increments` — two rejects
//!      → count = 2
//!   3. `test_dsl_072_first_filed_epoch_preserved` — filed_epoch
//!      of FIRST appeal is retained after subsequent rejections
//!   4. `test_dsl_072_lost_attempt_appended` — last history
//!      entry is `AppealAttempt{outcome: Lost{reason_hash}}`

use dig_protocol::Bytes32;
use dig_slashing::{
    APPELLANT_BOND_MOJOS, AppealOutcome, AppealRejectReason, AppealVerdict, AttestationData,
    AttesterAppealGround, AttesterSlashing, AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, Checkpoint,
    IndexedAttestation, OffenseType, PendingSlash, PendingSlashStatus, PerValidatorSlash,
    SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal, SlashAppealPayload, SlashingEvidence,
    SlashingEvidencePayload, VerifiedEvidence, adjudicate_rejected_challenge_open,
};

fn attester_evidence() -> SlashingEvidence {
    let data = AttestationData {
        slot: 0,
        index: 0,
        beacon_block_root: Bytes32::new([0u8; 32]),
        source: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
        target: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
    };
    let att = IndexedAttestation {
        attesting_indices: vec![1],
        data,
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0u8; 32]),
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

fn fresh_pending() -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([0xA1u8; 32]),
        evidence: attester_evidence(),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![PerValidatorSlash {
            validator_index: 1,
            base_slash_amount: 1_000_000_000,
            effective_balance_at_slash: 32_000_000_000,
            collateral_slashed: 0,
        }],
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    }
}

fn sample_appeal(appellant_index: u32, filed_epoch: u64, witness_byte: u8) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: Bytes32::new([0xA1u8; 32]),
        appellant_index,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![witness_byte],
        }),
    }
}

fn rejected() -> AppealVerdict {
    AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    }
}

/// DSL-072 row 1: first rejection on `Accepted` → `ChallengeOpen
/// { first_appeal_filed_epoch: appeal.filed_epoch, appeal_count: 1 }`.
#[test]
fn test_dsl_072_first_rejected_sets_open_count_1() {
    let mut pending = fresh_pending();
    let appeal = sample_appeal(42, 11, 0xAA);
    let reason = Bytes32::new([0xDDu8; 32]);

    adjudicate_rejected_challenge_open(&mut pending, &appeal, &rejected(), reason);

    match pending.status {
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch,
            appeal_count,
        } => {
            assert_eq!(first_appeal_filed_epoch, 11);
            assert_eq!(appeal_count, 1);
        }
        other => panic!("expected ChallengeOpen, got {other:?}"),
    }
}

/// DSL-072 row 2: second rejection increments `appeal_count`.
#[test]
fn test_dsl_072_second_rejected_increments() {
    let mut pending = fresh_pending();
    let first = sample_appeal(42, 11, 0xAA);
    let second = sample_appeal(43, 13, 0xBB);
    let reason = Bytes32::new([0xDDu8; 32]);

    adjudicate_rejected_challenge_open(&mut pending, &first, &rejected(), reason);
    adjudicate_rejected_challenge_open(&mut pending, &second, &rejected(), reason);

    match pending.status {
        PendingSlashStatus::ChallengeOpen { appeal_count, .. } => {
            assert_eq!(appeal_count, 2);
        }
        other => panic!("expected ChallengeOpen, got {other:?}"),
    }
    assert_eq!(pending.appeal_history.len(), 2);
}

/// DSL-072 row 3: `first_appeal_filed_epoch` is the FIRST
/// appeal's epoch, preserved across subsequent rejections.
#[test]
fn test_dsl_072_first_filed_epoch_preserved() {
    let mut pending = fresh_pending();
    let first = sample_appeal(42, 10, 0xAA);
    let second = sample_appeal(43, 11, 0xBB);
    let third = sample_appeal(44, 15, 0xCC);
    let reason = Bytes32::new([0xDDu8; 32]);

    adjudicate_rejected_challenge_open(&mut pending, &first, &rejected(), reason);
    adjudicate_rejected_challenge_open(&mut pending, &second, &rejected(), reason);
    adjudicate_rejected_challenge_open(&mut pending, &third, &rejected(), reason);

    match pending.status {
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch,
            appeal_count,
        } => {
            assert_eq!(
                first_appeal_filed_epoch, 10,
                "first-filed epoch pinned to FIRST appeal",
            );
            assert_eq!(appeal_count, 3);
        }
        other => panic!("expected ChallengeOpen, got {other:?}"),
    }
}

/// DSL-072 row 4: last `appeal_history` entry is
/// `AppealAttempt { outcome: Lost { reason_hash } }`.
#[test]
fn test_dsl_072_lost_attempt_appended() {
    let mut pending = fresh_pending();
    let appeal = sample_appeal(77, 12, 0xAA);
    let expected_reason = Bytes32::new([0x77u8; 32]);
    let expected_hash = appeal.hash();

    adjudicate_rejected_challenge_open(&mut pending, &appeal, &rejected(), expected_reason);

    assert_eq!(pending.appeal_history.len(), 1);
    let last = &pending.appeal_history[0];
    assert_eq!(last.appeal_hash, expected_hash);
    assert_eq!(last.appellant_index, 77);
    assert_eq!(last.filed_epoch, 12);
    assert_eq!(last.bond_mojos, APPELLANT_BOND_MOJOS);
    match last.outcome {
        AppealOutcome::Lost { reason_hash } => {
            assert_eq!(reason_hash, expected_reason);
        }
        other => panic!("expected Lost, got {other:?}"),
    }
}
