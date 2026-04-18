//! Requirement DSL-059: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::TooManyAttempts{count,limit}` when
//! `pending.appeal_history.len() >= MAX_APPEAL_ATTEMPTS_PER_SLASH`
//! (4). Bond MUST NOT be locked.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §2.6, §22.7.
//!
//! # Role
//!
//! Caps adjudication cost per pending slash. Sustained attempts
//! drain the book entry (DSL-070) and therefore can never
//! contribute to the count that tests observe here — every entry
//! in `appeal_history` at evaluation time is a REJECTED attempt.
//!
//! # Test matrix (maps to DSL-059 Test Plan)
//!
//!   1. `test_dsl_059_four_rejected_then_fifth_denied`
//!      — seed 4 distinct rejected attempts → 5th → `TooManyAttempts`
//!   2. `test_dsl_059_third_accepted`
//!      — seed 3 distinct rejected attempts → 4th accepted
//!      (`appeal_history.len() == 3 < MAX_APPEAL_ATTEMPTS_PER_SLASH`)

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealAttempt, AppealOutcome, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint,
    IndexedAttestation, MAX_APPEAL_ATTEMPTS_PER_SLASH, OffenseType, PendingSlash,
    PendingSlashStatus, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal, SlashAppealPayload, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, SlashingManager, VerifiedEvidence,
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

/// Seed a PendingSlash with `n` distinct prior rejected attempts.
/// Each attempt carries a distinct `appeal_hash` (just a byte
/// pattern) so DSL-058 DuplicateAppeal does not fire for the
/// incoming fresh appeal.
fn seed_pending_with_attempts(mgr: &mut SlashingManager, evidence_hash: Bytes32, n: usize) {
    let attempts: Vec<AppealAttempt> = (0..n)
        .map(|i| AppealAttempt {
            appeal_hash: Bytes32::new([i as u8 ^ 0xF0; 32]),
            appellant_index: 42,
            filed_epoch: 11 + i as u64,
            outcome: AppealOutcome::Lost {
                reason_hash: Bytes32::new([0xDDu8; 32]),
            },
            bond_mojos: 1_000,
        })
        .collect();
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
        appeal_history: attempts,
    };
    mgr.book_mut()
        .insert(pending)
        .expect("fixture insert must succeed");
}

fn fresh_appeal(evidence_hash: Bytes32, witness_byte: u8) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 15,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            // Unique witness so the hash is distinct from any
            // seeded appeal_hash (avoid DSL-058 collision).
            witness: vec![witness_byte; 4],
        }),
    }
}

/// DSL-059 row 1: 4 prior rejected attempts → 5th submission
/// returns `TooManyAttempts { count: 4, limit: 4 }` with zero
/// bond-lock calls.
#[test]
fn test_dsl_059_four_rejected_then_fifth_denied() {
    assert_eq!(MAX_APPEAL_ATTEMPTS_PER_SLASH, 4, "cap per SPEC §2.6");

    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xAAu8; 32]);
    seed_pending_with_attempts(&mut mgr, hash, MAX_APPEAL_ATTEMPTS_PER_SLASH);

    let appeal = fresh_appeal(hash, 0x5A);
    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    match err {
        SlashingError::TooManyAttempts { count, limit } => {
            assert_eq!(count, MAX_APPEAL_ATTEMPTS_PER_SLASH);
            assert_eq!(limit, MAX_APPEAL_ATTEMPTS_PER_SLASH);
        }
        other => panic!("expected TooManyAttempts, got {other:?}"),
    }
    assert_eq!(
        bond.lock_calls, 0,
        "TooManyAttempts path must not touch the bond escrow"
    );
}

/// DSL-059 row 2: 3 prior rejected attempts → 4th submission
/// passes this check (pipeline returns Ok). `3 < 4 = cap`.
#[test]
fn test_dsl_059_third_accepted() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xBBu8; 32]);
    seed_pending_with_attempts(&mut mgr, hash, MAX_APPEAL_ATTEMPTS_PER_SLASH - 1);

    let appeal = fresh_appeal(hash, 0x5B);
    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
}
