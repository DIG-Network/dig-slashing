//! Requirement DSL-068: on `AppealVerdict::Sustained` the
//! adjudicator MUST forfeit the reporter bond and split the
//! proceeds 50/50 between the appellant and the burn bucket.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §2.6, §22.8.
//!
//! # Role
//!
//! Fifth economic side-effect of a sustained appeal. Transfers
//! value from the losing reporter to the winning appellant and
//! the protocol burn bucket. Pairs with DSL-071 (rejected →
//! appellant bond forfeited via the mirror split).
//!
//! # Rounding
//!
//! Integer division truncates toward the appellant's award; any
//! odd mojo flows to burn. Conservation is by construction
//! (`burn = forfeited - winner_award`).
//!
//! # Test matrix (maps to DSL-068 Test Plan)
//!
//!   1. `test_dsl_068_forfeit_called` — escrow records
//!      `(reporter_idx, REPORTER_BOND_MOJOS, Reporter(hash))`
//!   2. `test_dsl_068_50_50_split` — `forfeited = 1000` →
//!      winner_award = 500, burn = 500
//!   3. `test_dsl_068_appellant_award_paid` — reward payout
//!      records `(appellant_ph, winner_award)`
//!   4. `test_dsl_068_rounding_odd_amount` — `forfeited = 3` →
//!      winner_award = 1, burn = 2

use std::cell::RefCell;

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealSustainReason, AppealVerdict, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondSplitResult, BondTag,
    Checkpoint, IndexedAttestation, OffenseType, PendingSlash, PendingSlashStatus,
    PerValidatorSlash, REPORTER_BOND_MOJOS, RewardPayout, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal,
    SlashAppealPayload, SlashingEvidence, SlashingEvidencePayload, VerifiedEvidence,
    adjudicate_sustained_forfeit_reporter_bond,
};

/// Bond escrow that records every forfeit call and returns a
/// caller-supplied amount (lets tests drive the rounding cases).
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

/// Reward payout that records every pay call for assertion.
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

fn attester_evidence(reporter_idx: u32) -> SlashingEvidence {
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
        reporter_validator_index: reporter_idx,
        reporter_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

fn pending_with_reporter(reporter_idx: u32, evidence_hash: Bytes32) -> PendingSlash {
    PendingSlash {
        evidence_hash,
        evidence: attester_evidence(reporter_idx),
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
        reporter_bond_mojos: REPORTER_BOND_MOJOS,
        appeal_history: vec![],
    }
}

fn appeal_for(evidence_hash: Bytes32, appellant_ph: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 77,
        appellant_puzzle_hash: appellant_ph,
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![],
        }),
    }
}

fn sustained() -> AppealVerdict {
    AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    }
}

/// DSL-068 row 1: escrow records forfeit with
/// `(reporter_idx, REPORTER_BOND_MOJOS, Reporter(evidence_hash))`.
#[test]
fn test_dsl_068_forfeit_called() {
    let hash = Bytes32::new([0xA1u8; 32]);
    let appellant_ph = Bytes32::new([0xCCu8; 32]);
    let pending = pending_with_reporter(42, hash);
    let appeal = appeal_for(hash, appellant_ph);
    let mut bond = RecBond::returning(REPORTER_BOND_MOJOS);
    let mut reward = RecReward::new();

    let _ = adjudicate_sustained_forfeit_reporter_bond(
        &pending,
        &appeal,
        &sustained(),
        &mut bond,
        &mut reward,
    )
    .unwrap();

    let calls = bond.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, 42, "principal = reporter_validator_index");
    assert_eq!(
        calls[0].1, REPORTER_BOND_MOJOS,
        "amount = REPORTER_BOND_MOJOS"
    );
    assert_eq!(calls[0].2, BondTag::Reporter(hash), "tag = Reporter(hash)");
}

/// DSL-068 row 2: forfeited=1000 → winner_award=500, burn=500.
#[test]
fn test_dsl_068_50_50_split() {
    let hash = Bytes32::new([0xA2u8; 32]);
    let appellant_ph = Bytes32::new([0xCCu8; 32]);
    let pending = pending_with_reporter(42, hash);
    let appeal = appeal_for(hash, appellant_ph);
    let mut bond = RecBond::returning(1_000);
    let mut reward = RecReward::new();

    let r = adjudicate_sustained_forfeit_reporter_bond(
        &pending,
        &appeal,
        &sustained(),
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
    assert_eq!(r.winner_award + r.burn, r.forfeited, "conservation");
}

/// DSL-068 row 3: RewardPayout::pay called on `appellant_ph`
/// with `winner_award`.
#[test]
fn test_dsl_068_appellant_award_paid() {
    let hash = Bytes32::new([0xA3u8; 32]);
    let appellant_ph = Bytes32::new([0xDDu8; 32]);
    let pending = pending_with_reporter(42, hash);
    let appeal = appeal_for(hash, appellant_ph);
    let mut bond = RecBond::returning(2_000);
    let mut reward = RecReward::new();

    let r = adjudicate_sustained_forfeit_reporter_bond(
        &pending,
        &appeal,
        &sustained(),
        &mut bond,
        &mut reward,
    )
    .unwrap();
    assert_eq!(r.winner_award, 1_000);

    let calls = reward.calls.borrow();
    assert_eq!(calls.len(), 1, "exactly one pay call");
    assert_eq!(calls[0].0, appellant_ph);
    assert_eq!(calls[0].1, r.winner_award);
}

/// DSL-068 row 4: odd forfeited=3 → winner_award=1, burn=2.
/// Integer-division rounding rolls the remainder into burn.
#[test]
fn test_dsl_068_rounding_odd_amount() {
    let hash = Bytes32::new([0xA4u8; 32]);
    let appellant_ph = Bytes32::new([0xCCu8; 32]);
    let pending = pending_with_reporter(42, hash);
    let appeal = appeal_for(hash, appellant_ph);
    let mut bond = RecBond::returning(3);
    let mut reward = RecReward::new();

    let r = adjudicate_sustained_forfeit_reporter_bond(
        &pending,
        &appeal,
        &sustained(),
        &mut bond,
        &mut reward,
    )
    .unwrap();

    assert_eq!(
        r,
        BondSplitResult {
            forfeited: 3,
            winner_award: 1,
            burn: 2,
        },
    );

    // `forfeited = 1` → (0, 1); `forfeited = 2` → (1, 1). Covered
    // by spot-checks so the rounding table is locked.
    let mut bond_one = RecBond::returning(1);
    let mut reward_one = RecReward::new();
    let r1 = adjudicate_sustained_forfeit_reporter_bond(
        &pending,
        &appeal,
        &sustained(),
        &mut bond_one,
        &mut reward_one,
    )
    .unwrap();
    assert_eq!(r1.winner_award, 0);
    assert_eq!(r1.burn, 1);

    let mut bond_two = RecBond::returning(2);
    let mut reward_two = RecReward::new();
    let r2 = adjudicate_sustained_forfeit_reporter_bond(
        &pending,
        &appeal,
        &sustained(),
        &mut bond_two,
        &mut reward_two,
    )
    .unwrap();
    assert_eq!(r2.winner_award, 1);
    assert_eq!(r2.burn, 1);
}
