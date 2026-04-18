//! Requirement DSL-057: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::AppealVariantMismatch` when
//! `appeal.payload` variant does not match
//! `pending.evidence.payload` variant. Bond MUST NOT be locked.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §22.7.
//!
//! # Role
//!
//! Prevents an appellant from filing a `ProposerSlashingAppeal`
//! against attester evidence (or any other cross-variant combo).
//! Cheap structural check — compares enum tags only. Runs AFTER
//! DSL-055 (UnknownEvidence) + DSL-056 (WindowExpired), BEFORE
//! DSL-062 bond lock.
//!
//! # Test matrix (maps to DSL-057 Test Plan)
//!
//!   1. `test_dsl_057_proposer_vs_attester_mismatch`
//!   2. `test_dsl_057_attester_vs_invalid_block_mismatch`
//!   3. `test_dsl_057_invalid_block_vs_proposer_mismatch`
//!   4. `test_dsl_057_all_matches_accepted` — each variant paired
//!      with its own evidence → no error (pipeline continues)

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterAppealGround, AttesterSlashing, AttesterSlashingAppeal,
    BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint, IndexedAttestation,
    InvalidBlockAppeal, InvalidBlockAppealGround, InvalidBlockProof, InvalidBlockReason,
    OffenseType, PendingSlash, PendingSlashStatus, ProposerAppealGround, ProposerSlashing,
    ProposerSlashingAppeal, SLASH_APPEAL_WINDOW_EPOCHS, SignedBlockHeader, SlashAppeal,
    SlashAppealPayload, SlashingError, SlashingEvidence, SlashingEvidencePayload, SlashingManager,
    VerifiedEvidence,
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

// ── Evidence-payload builders ──────────────────────────────────────────

fn sample_header() -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        5,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        1,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn proposer_payload() -> SlashingEvidencePayload {
    let signed = SignedBlockHeader {
        message: sample_header(),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidencePayload::Proposer(ProposerSlashing {
        signed_header_a: signed.clone(),
        signed_header_b: signed,
    })
}

fn attester_payload() -> SlashingEvidencePayload {
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
    SlashingEvidencePayload::Attester(AttesterSlashing {
        attestation_a: att.clone(),
        attestation_b: att,
    })
}

fn invalid_block_payload() -> SlashingEvidencePayload {
    SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: sample_header(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    })
}

fn offense_of(payload: &SlashingEvidencePayload) -> OffenseType {
    match payload {
        SlashingEvidencePayload::Proposer(_) => OffenseType::ProposerEquivocation,
        SlashingEvidencePayload::Attester(_) => OffenseType::AttesterDoubleVote,
        SlashingEvidencePayload::InvalidBlock(_) => OffenseType::InvalidBlock,
    }
}

fn insert_pending_with_payload(
    mgr: &mut SlashingManager,
    evidence_hash: Bytes32,
    payload: SlashingEvidencePayload,
) {
    let offense = offense_of(&payload);
    let evidence = SlashingEvidence {
        offense_type: offense,
        reporter_validator_index: 99,
        reporter_puzzle_hash: evidence_hash,
        epoch: 5,
        payload,
    };
    let pending = PendingSlash {
        evidence_hash,
        evidence,
        verified: VerifiedEvidence {
            offense_type: offense,
            slashable_validator_indices: vec![1],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![],
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    };
    mgr.book_mut()
        .insert(pending)
        .expect("fixture insert must succeed");
}

// ── Appeal-payload builders ────────────────────────────────────────────

fn proposer_appeal_payload() -> SlashAppealPayload {
    SlashAppealPayload::Proposer(ProposerSlashingAppeal {
        ground: ProposerAppealGround::HeadersIdentical,
        witness: vec![],
    })
}

fn attester_appeal_payload() -> SlashAppealPayload {
    SlashAppealPayload::Attester(AttesterSlashingAppeal {
        ground: AttesterAppealGround::AttestationsIdentical,
        witness: vec![],
    })
}

fn invalid_block_appeal_payload() -> SlashAppealPayload {
    SlashAppealPayload::InvalidBlock(InvalidBlockAppeal {
        ground: InvalidBlockAppealGround::EvidenceEpochMismatch,
        witness: vec![],
    })
}

fn appeal_with_payload(evidence_hash: Bytes32, payload: SlashAppealPayload) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload,
    }
}

// ── Cross-variant rejection tests ──────────────────────────────────────

/// DSL-057 row 1: ProposerAppeal vs AttesterSlashing → mismatch.
#[test]
fn test_dsl_057_proposer_vs_attester_mismatch() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA1u8; 32]);
    insert_pending_with_payload(&mut mgr, hash, attester_payload());

    let appeal = appeal_with_payload(hash, proposer_appeal_payload());
    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    assert!(
        matches!(err, SlashingError::AppealVariantMismatch),
        "expected VariantMismatch, got {err:?}"
    );
    assert_eq!(bond.lock_calls, 0);
}

/// DSL-057 row 2: AttesterAppeal vs InvalidBlockProof → mismatch.
#[test]
fn test_dsl_057_attester_vs_invalid_block_mismatch() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA2u8; 32]);
    insert_pending_with_payload(&mut mgr, hash, invalid_block_payload());

    let appeal = appeal_with_payload(hash, attester_appeal_payload());
    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    assert!(matches!(err, SlashingError::AppealVariantMismatch));
    assert_eq!(bond.lock_calls, 0);
}

/// DSL-057 row 3: InvalidBlockAppeal vs ProposerSlashing → mismatch.
#[test]
fn test_dsl_057_invalid_block_vs_proposer_mismatch() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA3u8; 32]);
    insert_pending_with_payload(&mut mgr, hash, proposer_payload());

    let appeal = appeal_with_payload(hash, invalid_block_appeal_payload());
    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    assert!(matches!(err, SlashingError::AppealVariantMismatch));
    assert_eq!(bond.lock_calls, 0);
}

/// DSL-057 row 4: each variant against its own evidence type →
/// no error. Exercises all three matching pairs; pipeline returns
/// `Ok(())` for the first-cut submit_appeal.
#[test]
fn test_dsl_057_all_matches_accepted() {
    // Proposer/Proposer
    {
        let mut mgr = SlashingManager::new(100);
        let mut bond = TrackingBond::new();
        let hash = Bytes32::new([0xB1u8; 32]);
        insert_pending_with_payload(&mut mgr, hash, proposer_payload());
        let appeal = appeal_with_payload(hash, proposer_appeal_payload());
        assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
    }
    // Attester/Attester
    {
        let mut mgr = SlashingManager::new(100);
        let mut bond = TrackingBond::new();
        let hash = Bytes32::new([0xB2u8; 32]);
        insert_pending_with_payload(&mut mgr, hash, attester_payload());
        let appeal = appeal_with_payload(hash, attester_appeal_payload());
        assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
    }
    // InvalidBlock/InvalidBlock
    {
        let mut mgr = SlashingManager::new(100);
        let mut bond = TrackingBond::new();
        let hash = Bytes32::new([0xB3u8; 32]);
        insert_pending_with_payload(&mut mgr, hash, invalid_block_payload());
        let appeal = appeal_with_payload(hash, invalid_block_appeal_payload());
        assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
    }
}
