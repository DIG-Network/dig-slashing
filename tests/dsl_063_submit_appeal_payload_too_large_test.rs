//! Requirement DSL-063: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::AppealPayloadTooLarge { actual, limit }`
//! when the bincode-serialized `SlashAppeal` exceeds
//! `MAX_APPEAL_PAYLOAD_BYTES` (131_072). Bond MUST NOT be locked.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §2.6, §22.7.
//!
//! # Role
//!
//! Caps memory + DoS cost of invalid-block witness storage. Runs
//! BEFORE the DSL-062 bond lock so oversized appeals never reach
//! collateral.
//!
//! # Size control via witness bytes
//!
//! The witness vec is the only part of a `SlashAppeal` whose
//! length is appellant-controlled — everything else (evidence
//! hash, appellant_index, puzzle_hash, filed_epoch, ground enum
//! tag) has fixed overhead. Each byte of witness produces one
//! byte of bincode encoding plus a fixed framing overhead.
//! The helper `make_witness_for_size` solves for the witness
//! length that produces a precise encoded envelope size.
//!
//! # Test matrix (maps to DSL-063 Test Plan)
//!
//!   1. `test_dsl_063_at_limit_accepted`
//!      — encoded length == MAX_APPEAL_PAYLOAD_BYTES → Ok
//!   2. `test_dsl_063_over_limit_rejected`
//!      — encoded length == MAX_APPEAL_PAYLOAD_BYTES + 1 →
//!      `AppealPayloadTooLarge{actual, limit}` + zero bond
//!      lock_calls
//!   3. `test_dsl_063_small_payload_accepted`
//!      — 1 KiB witness → Ok

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterAppealGround, AttesterSlashing, AttesterSlashingAppeal,
    BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint, IndexedAttestation,
    MAX_APPEAL_PAYLOAD_BYTES, OffenseType, PendingSlash, PendingSlashStatus,
    SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal, SlashAppealPayload, SlashingError, SlashingEvidence,
    SlashingEvidencePayload, SlashingManager, VerifiedEvidence,
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

fn insert_pending(mgr: &mut SlashingManager, hash: Bytes32) {
    let pending = PendingSlash {
        evidence_hash: hash,
        evidence: stub_attester_evidence(hash),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
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

/// Build an appeal with `witness_len` bytes. Fixed non-witness
/// fields hold so every byte of `witness_len` delta directly
/// shifts the bincode-encoded envelope size by 1.
fn appeal_with_witness(hash: Bytes32, witness_len: usize) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![0xEEu8; witness_len],
        }),
    }
}

/// Solve for the witness length that produces a bincode-encoded
/// envelope of exactly `target_encoded_len` bytes. Bincode
/// framing for a `Vec<u8>` is (8-byte length prefix + raw bytes),
/// so `witness_len = target - fixed_overhead` where
/// `fixed_overhead` is measured empirically against a known
/// baseline (witness_len = 0).
fn witness_len_for_encoded_size(hash: Bytes32, target: usize) -> usize {
    let baseline = bincode::serialize(&appeal_with_witness(hash, 0))
        .unwrap()
        .len();
    // Every extra witness byte adds exactly one bincode byte
    // (the `Vec<u8>` length prefix is already in the baseline).
    assert!(target >= baseline, "target below fixed overhead");
    target - baseline
}

/// DSL-063 row 1: encoded length exactly at the limit → Ok.
/// Boundary is closed on `==` (`len > cap` trips, `len == cap`
/// does not).
#[test]
fn test_dsl_063_at_limit_accepted() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA1u8; 32]);
    insert_pending(&mut mgr, hash);

    let wl = witness_len_for_encoded_size(hash, MAX_APPEAL_PAYLOAD_BYTES);
    let appeal = appeal_with_witness(hash, wl);
    assert_eq!(
        bincode::serialize(&appeal).unwrap().len(),
        MAX_APPEAL_PAYLOAD_BYTES,
        "fixture must land exactly on the cap"
    );
    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
}

/// DSL-063 row 2: cap + 1 → `AppealPayloadTooLarge{actual, limit}`
/// + zero bond lock_calls.
#[test]
fn test_dsl_063_over_limit_rejected() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA2u8; 32]);
    insert_pending(&mut mgr, hash);

    let wl = witness_len_for_encoded_size(hash, MAX_APPEAL_PAYLOAD_BYTES + 1);
    let appeal = appeal_with_witness(hash, wl);
    assert_eq!(
        bincode::serialize(&appeal).unwrap().len(),
        MAX_APPEAL_PAYLOAD_BYTES + 1
    );

    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    match err {
        SlashingError::AppealPayloadTooLarge { actual, limit } => {
            assert_eq!(actual, MAX_APPEAL_PAYLOAD_BYTES + 1);
            assert_eq!(limit, MAX_APPEAL_PAYLOAD_BYTES);
        }
        other => panic!("expected AppealPayloadTooLarge, got {other:?}"),
    }
    assert_eq!(
        bond.lock_calls, 0,
        "AppealPayloadTooLarge path must not touch the bond escrow"
    );
}

/// DSL-063 row 3: tiny payload (1 KiB witness) → Ok. Negative
/// control: ensures the check is not a constant reject.
#[test]
fn test_dsl_063_small_payload_accepted() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xA3u8; 32]);
    insert_pending(&mut mgr, hash);

    let appeal = appeal_with_witness(hash, 1024);
    assert!(bincode::serialize(&appeal).unwrap().len() < MAX_APPEAL_PAYLOAD_BYTES);
    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());
}
