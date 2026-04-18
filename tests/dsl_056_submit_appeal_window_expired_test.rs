//! Requirement DSL-056: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::AppealWindowExpired { .. }` when
//! `appeal.filed_epoch > pending.window_expires_at_epoch`. Bond
//! MUST NOT be locked on this failure path.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §22.7.
//!
//! # Boundary
//!
//! The window is closed-interval: `filed_epoch ==
//! window_expires_at_epoch` is STILL a valid filing. Only
//! `filed_epoch > expires_at` trips `AppealWindowExpired`.
//! Matches SPEC §6.1 text "appeals accepted through epoch E+8".
//!
//! # Test matrix (maps to DSL-056 Test Plan)
//!
//!   1. `test_dsl_056_at_boundary_accepted`
//!      — filed_epoch = submitted_at + SLASH_APPEAL_WINDOW_EPOCHS
//!   2. `test_dsl_056_past_boundary_rejected`
//!      — filed_epoch = submitted_at + SLASH_APPEAL_WINDOW_EPOCHS + 1
//!   3. `test_dsl_056_in_window_accepted`
//!      — filed_epoch well within window

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterAppealGround, AttesterSlashing, AttesterSlashingAppeal,
    BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint, IndexedAttestation,
    OffenseType, PendingSlash, PendingSlashStatus, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal,
    SlashAppealPayload, SlashingError, SlashingEvidence, SlashingEvidencePayload, SlashingManager,
    VerifiedEvidence,
};

/// Zero-lock bond escrow. Counts calls so tests can assert the
/// precondition check runs BEFORE any collateral touch.
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

/// Build a minimal `AttesterSlashing` envelope — content
/// irrelevant for DSL-056 (the check reads only the book's
/// `window_expires_at_epoch`, which we set explicitly when we
/// insert the `PendingSlash`).
fn stub_evidence(evidence_hash: Bytes32) -> SlashingEvidence {
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
        reporter_puzzle_hash: evidence_hash,
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

/// Insert a fabricated `PendingSlash` with a specific
/// `submitted_at_epoch`. `window_expires_at_epoch` is computed
/// as `submitted_at + SLASH_APPEAL_WINDOW_EPOCHS` per DSL-024.
fn insert_pending_at(mgr: &mut SlashingManager, evidence_hash: Bytes32, submitted_at: u64) {
    let pending = PendingSlash {
        evidence_hash,
        evidence: stub_evidence(evidence_hash),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: submitted_at,
        window_expires_at_epoch: submitted_at + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![],
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    };
    mgr.book_mut()
        .insert(pending)
        .expect("fixture insert must succeed");
}

fn appeal_at(evidence_hash: Bytes32, filed_epoch: u64) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-056 row 1: `filed_epoch == submitted_at + window` is the
/// LAST valid filing — no error. (Pipeline continues; for this
/// first-cut submit_appeal that is `Ok(())`.)
#[test]
fn test_dsl_056_at_boundary_accepted() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xAAu8; 32]);
    let submitted_at = 10u64;
    insert_pending_at(&mut mgr, hash, submitted_at);

    let appeal = appeal_at(hash, submitted_at + SLASH_APPEAL_WINDOW_EPOCHS);
    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
}

/// DSL-056 row 2: one epoch past the boundary → `AppealWindowExpired`.
/// Error carries `submitted_at`, `window`, `current` exactly.
#[test]
fn test_dsl_056_past_boundary_rejected() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xBBu8; 32]);
    let submitted_at = 10u64;
    insert_pending_at(&mut mgr, hash, submitted_at);

    let filed = submitted_at + SLASH_APPEAL_WINDOW_EPOCHS + 1;
    let appeal = appeal_at(hash, filed);

    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    match err {
        SlashingError::AppealWindowExpired {
            submitted_at: s,
            window,
            current,
        } => {
            assert_eq!(s, submitted_at);
            assert_eq!(window, SLASH_APPEAL_WINDOW_EPOCHS);
            assert_eq!(current, filed);
        }
        other => panic!("expected AppealWindowExpired, got {other:?}"),
    }
    assert_eq!(
        bond.lock_calls, 0,
        "WindowExpired path must not touch the bond escrow"
    );
}

/// DSL-056 row 3: well within window (filed_epoch = submitted_at + 4
/// of 8) → passes this check. Covers the common case.
#[test]
fn test_dsl_056_in_window_accepted() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xCCu8; 32]);
    let submitted_at = 20u64;
    insert_pending_at(&mut mgr, hash, submitted_at);

    let appeal = appeal_at(hash, submitted_at + 4);
    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
}
