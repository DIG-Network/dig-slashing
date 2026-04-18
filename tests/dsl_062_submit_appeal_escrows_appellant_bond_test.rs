//! Requirement DSL-062: `SlashingManager::submit_appeal` MUST
//! lock `APPELLANT_BOND_MOJOS` via `BondEscrow::lock(
//! appellant_index, APPELLANT_BOND_MOJOS,
//! BondTag::Appellant(appeal.hash()))` after all structural
//! rejections (DSL-055..061) pass. `BondError::InsufficientBalance`
//! surfaces as `SlashingError::AppellantBondLockFailed(..)`.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §2.6, §22.7.
//!
//! # Role
//!
//! LAST step of the admission pipeline — collateral is only
//! touched once every cheap precondition has passed. Pairs with
//! DSL-068 (sustained → reporter forfeits 50/50) and DSL-071
//! (rejected → appellant bond forfeited 50/50).
//!
//! # Test matrix (maps to DSL-062 Test Plan)
//!
//!   1. `test_dsl_062_lock_success` — lock call recorded with
//!      correct principal, amount, tag
//!   2. `test_dsl_062_insufficient_balance` — BondError propagates
//!      as `AppellantBondLockFailed`
//!   3. `test_dsl_062_tag_is_appellant_hash` — recorded tag is
//!      `Appellant(appeal.hash())` byte-for-byte

use std::cell::RefCell;

use dig_protocol::Bytes32;
use dig_slashing::{
    APPELLANT_BOND_MOJOS, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint,
    IndexedAttestation, OffenseType, PendingSlash, PendingSlashStatus, SLASH_APPEAL_WINDOW_EPOCHS,
    SlashAppeal, SlashAppealPayload, SlashingError, SlashingEvidence, SlashingEvidencePayload,
    SlashingManager, VerifiedEvidence,
};

/// Bond escrow that records every call + verdict knob.
struct RecordingBond {
    locks: RefCell<Vec<(u32, u64, BondTag)>>,
    lock_verdict: Result<(), BondError>,
}

impl RecordingBond {
    fn accepting() -> Self {
        Self {
            locks: RefCell::new(Vec::new()),
            lock_verdict: Ok(()),
        }
    }
    fn refusing(err: BondError) -> Self {
        Self {
            locks: RefCell::new(Vec::new()),
            lock_verdict: Err(err),
        }
    }
}

impl BondEscrow for RecordingBond {
    fn lock(&mut self, idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError> {
        self.locks.borrow_mut().push((idx, amount, tag));
        self.lock_verdict.clone()
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

fn sample_appeal(hash: Bytes32, appellant_index: u32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: hash,
        appellant_index,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![0xDEu8, 0xAD],
        }),
    }
}

/// DSL-062 row 1: accepting escrow + valid appeal → lock recorded
/// with `(appellant_index, APPELLANT_BOND_MOJOS,
/// Appellant(appeal.hash()))`. Pipeline returns `Ok(())`.
#[test]
fn test_dsl_062_lock_success() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = RecordingBond::accepting();
    let hash = Bytes32::new([0xA1u8; 32]);
    insert_pending(&mut mgr, hash);

    let appeal = sample_appeal(hash, 42);
    let expected_tag = BondTag::Appellant(appeal.hash());

    assert!(mgr.submit_appeal(&appeal, &mut bond).is_ok());

    let locks = bond.locks.borrow();
    assert_eq!(locks.len(), 1, "exactly one lock call on accepted path");
    assert_eq!(locks[0].0, 42, "principal = appellant_index");
    assert_eq!(
        locks[0].1, APPELLANT_BOND_MOJOS,
        "amount = APPELLANT_BOND_MOJOS"
    );
    assert_eq!(locks[0].2, expected_tag, "tag = Appellant(appeal.hash())");
}

/// DSL-062 row 2: escrow refuses the lock with `InsufficientBalance`
/// → `SlashingError::AppellantBondLockFailed(..)` bubbles up. The
/// lock call IS recorded (escrow was reached — proves the error
/// is surfaced from the escrow, not a short-circuit elsewhere).
#[test]
fn test_dsl_062_insufficient_balance() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = RecordingBond::refusing(BondError::InsufficientBalance {
        have: 0,
        need: APPELLANT_BOND_MOJOS,
    });
    let hash = Bytes32::new([0xA2u8; 32]);
    insert_pending(&mut mgr, hash);

    let appeal = sample_appeal(hash, 42);
    let err = mgr.submit_appeal(&appeal, &mut bond).unwrap_err();
    match err {
        SlashingError::AppellantBondLockFailed(msg) => {
            assert!(
                !msg.is_empty(),
                "BondError Display string must be carried through"
            );
        }
        other => panic!("expected AppellantBondLockFailed, got {other:?}"),
    }
    assert_eq!(
        bond.locks.borrow().len(),
        1,
        "escrow is reached even when it refuses"
    );
}

/// DSL-062 row 3: the recorded tag is byte-equal to
/// `BondTag::Appellant(appeal.hash())`. Mutating the appeal (new
/// witness bytes → different hash) produces a different tag —
/// enforced implicitly by DSL-058 SlashAppeal::hash sensitivity,
/// but the bond-lock path must not decouple from it.
#[test]
fn test_dsl_062_tag_is_appellant_hash() {
    let mut mgr = SlashingManager::new(100);
    let mut bond = RecordingBond::accepting();
    let hash = Bytes32::new([0xA3u8; 32]);
    insert_pending(&mut mgr, hash);

    let appeal = sample_appeal(hash, 7);
    let appeal_hash = appeal.hash();

    mgr.submit_appeal(&appeal, &mut bond).unwrap();

    let locks = bond.locks.borrow();
    match locks[0].2 {
        BondTag::Appellant(h) => assert_eq!(h, appeal_hash),
        BondTag::Reporter(_) => panic!("wrong tag variant — must be Appellant"),
    }
}
