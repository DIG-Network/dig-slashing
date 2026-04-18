//! Requirement DSL-071: on `AppealVerdict::Rejected` the
//! adjudicator MUST forfeit the appellant bond and split it
//! 50/50 between the reporter and the burn bucket.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Role
//!
//! Mirror of DSL-068 with losing/winning parties swapped. A
//! rejected appeal proves the appellant filed a bad challenge;
//! the reporter keeps the slash and earns 50% of the appellant's
//! forfeited bond.
//!
//! # Test matrix (maps to DSL-071 Test Plan)
//!
//!   1. `test_dsl_071_appellant_forfeit_called` — escrow records
//!      `(appellant_idx, APPELLANT_BOND_MOJOS,
//!      Appellant(appeal.hash()))`
//!   2. `test_dsl_071_50_50_split` — `forfeited = 1000` →
//!      `BondSplitResult{1000, 500, 500}`
//!   3. `test_dsl_071_reporter_paid` — reward payout records
//!      `(reporter_puzzle_hash, winner_award)`

use std::cell::RefCell;

use dig_protocol::Bytes32;
use dig_slashing::{
    APPELLANT_BOND_MOJOS, AppealRejectReason, AppealVerdict, AttestationData, AttesterAppealGround,
    AttesterSlashing, AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError, BondEscrow,
    BondSplitResult, BondTag, Checkpoint, IndexedAttestation, OffenseType, PendingSlash,
    PendingSlashStatus, PerValidatorSlash, RewardPayout, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal,
    SlashAppealPayload, SlashingEvidence, SlashingEvidencePayload, VerifiedEvidence,
    adjudicate_rejected_forfeit_appellant_bond,
};

struct RecBond {
    calls: RefCell<Vec<(u32, u64, BondTag)>>,
    forfeit_returns: u64,
}

impl RecBond {
    fn returning(amount: u64) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            forfeit_returns: amount,
        }
    }
}

impl BondEscrow for RecBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn forfeit(&mut self, idx: u32, amount: u64, tag: BondTag) -> Result<u64, BondError> {
        self.calls.borrow_mut().push((idx, amount, tag));
        Ok(self.forfeit_returns)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

struct RecReward {
    calls: RefCell<Vec<(Bytes32, u64)>>,
}

impl RecReward {
    fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl RewardPayout for RecReward {
    fn pay(&mut self, principal_ph: Bytes32, amount_mojos: u64) {
        self.calls.borrow_mut().push((principal_ph, amount_mojos));
    }
}

fn attester_evidence(reporter_ph: Bytes32) -> SlashingEvidence {
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
        reporter_puzzle_hash: reporter_ph,
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

fn pending_with(reporter_ph: Bytes32, evidence_hash: Bytes32) -> PendingSlash {
    PendingSlash {
        evidence_hash,
        evidence: attester_evidence(reporter_ph),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![PerValidatorSlash {
            validator_index: 1,
            base_slash_amount: 1_000,
            effective_balance_at_slash: 32_000_000_000,
            collateral_slashed: 0,
        }],
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    }
}

fn sample_appeal(evidence_hash: Bytes32, appellant_index: u32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index,
        appellant_puzzle_hash: Bytes32::new([0xDDu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![],
        }),
    }
}

fn rejected() -> AppealVerdict {
    AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    }
}

/// DSL-071 row 1: escrow forfeit recorded with
/// `(appellant_idx, APPELLANT_BOND_MOJOS, Appellant(hash))`.
#[test]
fn test_dsl_071_appellant_forfeit_called() {
    let hash = Bytes32::new([0xA1u8; 32]);
    let reporter_ph = Bytes32::new([0xAAu8; 32]);
    let pending = pending_with(reporter_ph, hash);
    let appeal = sample_appeal(hash, 77);
    let mut bond = RecBond::returning(APPELLANT_BOND_MOJOS);
    let mut reward = RecReward::new();

    let _ = adjudicate_rejected_forfeit_appellant_bond(
        &pending,
        &appeal,
        &rejected(),
        &mut bond,
        &mut reward,
    )
    .unwrap();

    let calls = bond.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, 77, "principal = appellant_index");
    assert_eq!(calls[0].1, APPELLANT_BOND_MOJOS);
    assert_eq!(calls[0].2, BondTag::Appellant(appeal.hash()));
}

/// DSL-071 row 2: forfeited=1000 → winner_award=500, burn=500.
#[test]
fn test_dsl_071_50_50_split() {
    let hash = Bytes32::new([0xA2u8; 32]);
    let reporter_ph = Bytes32::new([0xAAu8; 32]);
    let pending = pending_with(reporter_ph, hash);
    let appeal = sample_appeal(hash, 77);
    let mut bond = RecBond::returning(1_000);
    let mut reward = RecReward::new();

    let r = adjudicate_rejected_forfeit_appellant_bond(
        &pending,
        &appeal,
        &rejected(),
        &mut bond,
        &mut reward,
    )
    .unwrap();

    assert_eq!(
        r,
        BondSplitResult {
            forfeited: 1_000,
            winner_award: 500,
            burn: 500,
        },
    );
    assert_eq!(r.winner_award + r.burn, r.forfeited);
}

/// DSL-071 row 3: reward payout records
/// `(reporter_puzzle_hash, winner_award)`.
#[test]
fn test_dsl_071_reporter_paid() {
    let hash = Bytes32::new([0xA3u8; 32]);
    let reporter_ph = Bytes32::new([0xAAu8; 32]);
    let pending = pending_with(reporter_ph, hash);
    let appeal = sample_appeal(hash, 77);
    let mut bond = RecBond::returning(2_000);
    let mut reward = RecReward::new();

    let r = adjudicate_rejected_forfeit_appellant_bond(
        &pending,
        &appeal,
        &rejected(),
        &mut bond,
        &mut reward,
    )
    .unwrap();
    assert_eq!(r.winner_award, 1_000);

    let calls = reward.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, reporter_ph);
    assert_eq!(calls[0].1, r.winner_award);
}
