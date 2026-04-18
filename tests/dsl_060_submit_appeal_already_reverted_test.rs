//! Requirement DSL-060: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::SlashAlreadyReverted` when the pending
//! slash's `status` is `PendingSlashStatus::Reverted { .. }`.
//! Bond MUST NOT be locked.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §22.7.
//!
//! # Role
//!
//! Once a sustained appeal drives the book entry to `Reverted`
//! (DSL-070), the slash is non-actionable. Subsequent appeals
//! must fail cheaply — there is nothing to revert.
//!
//! # Test matrix (maps to DSL-060 Test Plan)
//!
//!   1. `test_dsl_060_reverted_rejects_new_appeal`
//!      — status = `Reverted{..}` → `SlashAlreadyReverted` + zero
//!      bond lock_calls
//!   2. `test_dsl_060_accepted_status_passes`
//!      — status = `Accepted` → pipeline Ok (no status-guard trip)

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterAppealGround, AttesterSlashing, AttesterSlashingAppeal,
    BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint, IndexedAttestation,
    OffenseType, PendingSlash, PendingSlashStatus, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal,
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

fn insert_with_status(mgr: &mut SlashingManager, hash: Bytes32, status: PendingSlashStatus) {
    let pending = PendingSlash {
        evidence_hash: hash,
        evidence: stub_attester_evidence(hash),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1],
        },
        status,
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

fn appeal_for(hash: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-060 row 1: `Reverted` status → `SlashAlreadyReverted` +
/// zero bond lock_calls.
#[test]
fn test_dsl_060_reverted_rejects_new_appeal() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA1u8; 32]);
    insert_with_status(
        &mut mgr,
        hash,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0x77u8; 32]),
            reverted_at_epoch: 12,
        },
    );

    let appeal = appeal_for(hash);
    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    assert!(
        matches!(err, SlashingError::SlashAlreadyReverted),
        "expected SlashAlreadyReverted, got {err:?}"
    );
    assert_eq!(
        bond.lock_calls, 0,
        "SlashAlreadyReverted path must not touch the bond escrow"
    );
}

/// DSL-060 row 2: `Accepted` status → pipeline passes the
/// status-guard check. Ensures the new guard does not
/// false-positive on in-window slashes.
#[test]
fn test_dsl_060_accepted_status_passes() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA2u8; 32]);
    insert_with_status(&mut mgr, hash, PendingSlashStatus::Accepted);

    let appeal = appeal_for(hash);
    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
}
