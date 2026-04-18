//! Requirement DSL-058: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::DuplicateAppeal` when a byte-equal
//! appeal already exists in `pending.appeal_history`. Bond MUST
//! NOT be locked.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §22.7.
//!
//! # Role
//!
//! Prevents spamming the adjudicator with identical rejected
//! appeals. Distinction is byte-equal on the content-addressed
//! `SlashAppeal::hash` — near-duplicates (different witness bytes,
//! different ground) produce distinct hashes and are accepted.
//!
//! # Test matrix (maps to DSL-058 Test Plan)
//!
//!   1. `test_dsl_058_byte_equal_duplicate_rejected`
//!      — same appeal seeded into history → second submit rejects
//!   2. `test_dsl_058_near_duplicate_accepted`
//!      — same ground, different witness bytes → accepted
//!   3. `test_dsl_058_different_ground_accepted`
//!      — same evidence, different ground → accepted

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealAttempt, AppealOutcome, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint,
    IndexedAttestation, OffenseType, PendingSlash, PendingSlashStatus, SLASH_APPEAL_WINDOW_EPOCHS,
    SlashAppeal, SlashAppealPayload, SlashingError, SlashingEvidence, SlashingEvidencePayload,
    SlashingManager, VerifiedEvidence,
};

struct TrackingBond {
    lock_calls: u32,
}
impl TrackingBond {
    fn new() -> Self {
        Self { lock_calls: 0 }
    }
}
impl BondEscrow for TrackingBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        self.lock_calls += 1;
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

fn stub_attester_evidence(hash: Bytes32) -> SlashingEvidence {
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

/// Insert a PendingSlash with the caller-supplied `appeal_history`.
/// Allows tests to seed a prior byte-equal appeal without running
/// `submit_appeal` end-to-end (bond lock + dispatcher are not yet
/// implemented).
fn insert_with_history(
    mgr: &mut SlashingManager,
    evidence_hash: Bytes32,
    history: Vec<AppealAttempt>,
) {
    let pending = PendingSlash {
        evidence_hash,
        evidence: stub_attester_evidence(evidence_hash),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![],
        reporter_bond_mojos: 0,
        appeal_history: history,
    };
    mgr.book_mut()
        .insert(pending)
        .expect("fixture insert must succeed");
}

fn attester_appeal(
    evidence_hash: Bytes32,
    ground: AttesterAppealGround,
    witness: Vec<u8>,
) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal { ground, witness }),
    }
}

/// DSL-058 row 1: a byte-equal prior attempt in history →
/// `DuplicateAppeal`. Prior attempt's `appeal_hash` must equal
/// the new appeal's computed hash.
#[test]
fn test_dsl_058_byte_equal_duplicate_rejected() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA1u8; 32]);

    // Build the appeal FIRST so we can seed history with its hash.
    let appeal = attester_appeal(
        hash,
        AttesterAppealGround::AttestationsIdentical,
        b"same-witness".to_vec(),
    );
    let prior = AppealAttempt {
        appeal_hash: appeal.hash(),
        appellant_index: 42,
        filed_epoch: 11,
        outcome: AppealOutcome::Lost {
            reason_hash: Bytes32::new([0xDDu8; 32]),
        },
        bond_mojos: 1_000,
    };
    insert_with_history(&mut mgr, hash, vec![prior]);

    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    assert!(
        matches!(err, SlashingError::DuplicateAppeal),
        "expected DuplicateAppeal, got {err:?}"
    );
    assert_eq!(
        bond.lock_calls, 0,
        "DuplicateAppeal path must not touch bond escrow"
    );
}

/// DSL-058 row 2: same ground, different witness bytes → distinct
/// hash → accepted. Witness content participates in the
/// SlashAppeal::hash digest.
#[test]
fn test_dsl_058_near_duplicate_accepted() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA2u8; 32]);

    // Seed history with the OTHER witness so the incoming appeal
    // has a DIFFERENT hash from the seeded one.
    let seeded = attester_appeal(
        hash,
        AttesterAppealGround::AttestationsIdentical,
        b"witness-v1".to_vec(),
    );
    let prior = AppealAttempt {
        appeal_hash: seeded.hash(),
        appellant_index: 42,
        filed_epoch: 11,
        outcome: AppealOutcome::Lost {
            reason_hash: Bytes32::new([0xDDu8; 32]),
        },
        bond_mojos: 1_000,
    };
    insert_with_history(&mut mgr, hash, vec![prior]);

    let fresh = attester_appeal(
        hash,
        AttesterAppealGround::AttestationsIdentical,
        b"witness-v2-different".to_vec(),
    );
    assert_ne!(seeded.hash(), fresh.hash(), "witness diff → hash diff");

    assert!(mgr.submit_appeal(&fresh, &mut bond).is_ok());
}

/// DSL-058 row 3: same evidence + same witness but DIFFERENT
/// ground → distinct hash → accepted. Ground participates in the
/// digest via the enum discriminant.
#[test]
fn test_dsl_058_different_ground_accepted() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA3u8; 32]);

    let seeded = attester_appeal(
        hash,
        AttesterAppealGround::AttestationsIdentical,
        b"ws".to_vec(),
    );
    let prior = AppealAttempt {
        appeal_hash: seeded.hash(),
        appellant_index: 42,
        filed_epoch: 11,
        outcome: AppealOutcome::Lost {
            reason_hash: Bytes32::new([0xDDu8; 32]),
        },
        bond_mojos: 1_000,
    };
    insert_with_history(&mut mgr, hash, vec![prior]);

    let fresh = attester_appeal(
        hash,
        AttesterAppealGround::EmptyIntersection, // different ground
        b"ws".to_vec(),
    );
    assert_ne!(seeded.hash(), fresh.hash(), "ground diff → hash diff");

    assert!(mgr.submit_appeal(&fresh, &mut bond).is_ok());
}
