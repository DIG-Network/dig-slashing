//! Requirement DSL-070: after every other sustained-adjudication
//! side-effect lands, the adjudicator MUST transition the pending
//! slash's `status` to `Reverted { winning_appeal_hash,
//! reverted_at_epoch }` and append `AppealAttempt { outcome:
//! Won }` to `pending.appeal_history`.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Role
//!
//! Terminal state for a sustained appeal. Gatekeeper for DSL-060
//! (`SlashAlreadyReverted` rejection on subsequent submit_appeal)
//! and DSL-033 (finalisation skip-path). Once set, the pending
//! slash is non-reversible.
//!
//! # Test matrix (maps to DSL-070 Test Plan)
//!
//!   1. `test_dsl_070_status_reverted` — post-call status matches
//!      `Reverted { .. }` pattern
//!   2. `test_dsl_070_winning_hash_set` — `winning_appeal_hash ==
//!      appeal.hash()`, `reverted_at_epoch == current_epoch`
//!   3. `test_dsl_070_history_appended` — last
//!      `pending.appeal_history` entry is
//!      `AppealAttempt { outcome: Won, .. }`
//!   4. `test_dsl_070_subsequent_appeal_rejected` — after the
//!      transition, `SlashingManager::submit_appeal` on a fresh
//!      appeal against the same evidence returns
//!      `SlashAlreadyReverted`

use dig_protocol::Bytes32;
use dig_slashing::{
    APPELLANT_BOND_MOJOS, AppealOutcome, AppealSustainReason, AppealVerdict, AttestationData,
    AttesterAppealGround, AttesterSlashing, AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError,
    BondEscrow, BondTag, Checkpoint, IndexedAttestation, OffenseType, PendingSlash,
    PendingSlashStatus, PerValidatorSlash, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal,
    SlashAppealPayload, SlashingError, SlashingEvidence, SlashingEvidencePayload, SlashingManager,
    VerifiedEvidence, adjudicate_sustained_status_reverted,
};

struct TrackingBond;
impl BondEscrow for TrackingBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn forfeit(&mut self, _: u32, amount: u64, _: BondTag) -> Result<u64, BondError> {
        Ok(amount)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

fn attester_evidence(hash: Bytes32) -> SlashingEvidence {
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
        reporter_puzzle_hash: hash,
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

fn fresh_pending(hash: Bytes32) -> PendingSlash {
    PendingSlash {
        evidence_hash: hash,
        evidence: attester_evidence(hash),
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

fn sample_appeal(hash: Bytes32, appellant_index: u32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: hash,
        appellant_index,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![0xEE],
        }),
    }
}

fn sustained() -> AppealVerdict {
    AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    }
}

/// DSL-070 row 1: post-call status matches `Reverted { .. }`.
#[test]
fn test_dsl_070_status_reverted() {
    let hash = Bytes32::new([0xA1u8; 32]);
    let mut pending = fresh_pending(hash);
    let appeal = sample_appeal(hash, 42);

    adjudicate_sustained_status_reverted(&mut pending, &appeal, &sustained(), 15);

    assert!(
        matches!(pending.status, PendingSlashStatus::Reverted { .. }),
        "status must be Reverted, got {:?}",
        pending.status,
    );
}

/// DSL-070 row 2: `winning_appeal_hash == appeal.hash()` and
/// `reverted_at_epoch == current_epoch`.
#[test]
fn test_dsl_070_winning_hash_set() {
    let hash = Bytes32::new([0xA2u8; 32]);
    let mut pending = fresh_pending(hash);
    let appeal = sample_appeal(hash, 42);
    let expected_hash = appeal.hash();
    let current_epoch = 16;

    adjudicate_sustained_status_reverted(&mut pending, &appeal, &sustained(), current_epoch);

    match pending.status {
        PendingSlashStatus::Reverted {
            winning_appeal_hash,
            reverted_at_epoch,
        } => {
            assert_eq!(winning_appeal_hash, expected_hash);
            assert_eq!(reverted_at_epoch, current_epoch);
        }
        other => panic!("expected Reverted, got {other:?}"),
    }
}

/// DSL-070 row 3: last `appeal_history` entry has `outcome: Won`
/// with the appeal's full identity fields populated.
#[test]
fn test_dsl_070_history_appended() {
    let hash = Bytes32::new([0xA3u8; 32]);
    let mut pending = fresh_pending(hash);
    let appeal = sample_appeal(hash, 77);
    let expected_hash = appeal.hash();

    adjudicate_sustained_status_reverted(&mut pending, &appeal, &sustained(), 20);

    assert_eq!(pending.appeal_history.len(), 1);
    let last = &pending.appeal_history[0];
    assert_eq!(last.appeal_hash, expected_hash);
    assert_eq!(last.appellant_index, 77);
    assert_eq!(last.filed_epoch, appeal.filed_epoch);
    assert_eq!(last.outcome, AppealOutcome::Won);
    assert_eq!(last.bond_mojos, APPELLANT_BOND_MOJOS);
}

/// DSL-070 row 4: after the transition, `submit_appeal` on a
/// FRESH appeal against the same evidence returns
/// `SlashAlreadyReverted` (DSL-060 guard). End-to-end proves the
/// terminal state is observable through the public manager API.
#[test]
fn test_dsl_070_subsequent_appeal_rejected() {
    let hash = Bytes32::new([0xA4u8; 32]);
    let mut mgr = SlashingManager::new(20);
    let mut bond = TrackingBond;

    // Insert a pending record directly.
    mgr.book_mut().insert(fresh_pending(hash)).unwrap();

    // Apply the DSL-070 transition through the mutable book.
    {
        let pending = mgr.book_mut().get_mut(&hash).unwrap();
        let first_appeal = sample_appeal(hash, 42);
        adjudicate_sustained_status_reverted(pending, &first_appeal, &sustained(), 15);
    }

    // Now a FRESH appeal against the same hash must reject.
    let second_appeal = SlashAppeal {
        evidence_hash: hash,
        appellant_index: 43,
        appellant_puzzle_hash: Bytes32::new([0xDDu8; 32]),
        filed_epoch: 16,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::EmptyIntersection,
            witness: vec![0xFF],
        }),
    };
    let err = mgr.submit_appeal(&second_appeal, &mut bond).unwrap_err();
    assert!(
        matches!(err, SlashingError::SlashAlreadyReverted),
        "expected SlashAlreadyReverted, got {err:?}",
    );
}
