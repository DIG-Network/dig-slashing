//! Requirement DSL-061: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::SlashAlreadyFinalised` when the pending
//! slash's `status` is `PendingSlashStatus::Finalised { .. }`.
//! Bond MUST NOT be locked.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §22.7.
//!
//! # Role
//!
//! `finalise_expired_slashes` (DSL-029) transitions window-expired
//! book entries to `Finalised{finalised_at_epoch, ..}`. At that
//! point the correlation penalty has been applied and the exit
//! lock started — the slash is terminal and non-reversible.
//! Additional appeals must fail cheaply.
//!
//! Implementation note: the error variant + status-match arm
//! already landed with DSL-060 (terminal-state guard). This suite
//! is test-only.
//!
//! # Test matrix (maps to DSL-061 Test Plan)
//!
//!   1. `test_dsl_061_finalised_rejects_appeal`
//!      — status = `Finalised{..}` → `SlashAlreadyFinalised`
//!      + zero bond lock_calls
//!   2. `test_dsl_061_accepted_passes`
//!      — status = `Accepted` → pipeline Ok (guard does not
//!      false-positive on in-window slashes)

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

/// DSL-061 row 1: `Finalised` status → `SlashAlreadyFinalised` +
/// zero bond lock_calls.
#[test]
fn test_dsl_061_finalised_rejects_appeal() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA1u8; 32]);
    insert_with_status(
        &mut mgr,
        hash,
        PendingSlashStatus::Finalised {
            finalised_at_epoch: 20,
        },
    );

    let appeal = appeal_for(hash);
    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    assert!(
        matches!(err, SlashingError::SlashAlreadyFinalised),
        "expected SlashAlreadyFinalised, got {err:?}"
    );
    assert_eq!(
        bond.lock_calls, 0,
        "SlashAlreadyFinalised path must not touch the bond escrow"
    );
}

/// DSL-061 row 2: `Accepted` status → pipeline passes the
/// status-guard check. Guards against the Finalised match arm
/// accidentally matching non-terminal statuses.
#[test]
fn test_dsl_061_accepted_passes() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA2u8; 32]);
    insert_with_status(&mut mgr, hash, PendingSlashStatus::Accepted);

    let appeal = appeal_for(hash);
    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
}
