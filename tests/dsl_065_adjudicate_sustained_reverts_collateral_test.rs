//! Requirement DSL-065: on `AppealVerdict::Sustained`, if a
//! `CollateralSlasher` is supplied the adjudicator MUST call
//! `credit(validator_index, collateral_slashed)` per reverted
//! validator with a non-zero `collateral_slashed`. No-op when
//! collateral is `None` or `collateral_slashed == 0`.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Role
//!
//! Second economic side-effect of a sustained appeal (after
//! DSL-064 stake revert). Reverses the consensus-layer
//! collateral debit that ran alongside the DSL-022
//! `slash_absolute` stake debit.
//!
//! Light-client wiring supplies `None` for the collateral slasher
//! — collateral bookkeeping is a full-node concern, so the
//! adjudicator no-ops there.
//!
//! # Test matrix (maps to DSL-065 Test Plan)
//!
//!   1. `test_dsl_065_collateral_credited` — recording slasher,
//!      3 indices with non-zero collateral → 3 credits
//!   2. `test_dsl_065_no_collateral_no_op` — `collateral: None`
//!      → empty credited vec, no panic, no calls
//!   3. `test_dsl_065_zero_collateral_skipped` — index with
//!      `collateral_slashed == 0` is not credited even when the
//!      slasher is present

use std::cell::RefCell;

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealSustainReason, AppealVerdict, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, Checkpoint, CollateralSlasher, IndexedAttestation,
    OffenseType, PendingSlash, PendingSlashStatus, PerValidatorSlash, SLASH_APPEAL_WINDOW_EPOCHS,
    SlashAppeal, SlashAppealPayload, SlashingEvidence, SlashingEvidencePayload, VerifiedEvidence,
    adjudicate_sustained_revert_collateral,
};

/// Recording collateral slasher — captures every `credit` call
/// as `(validator_index, amount)` so tests can assert shape +
/// order.
struct RecSlasher {
    credits: RefCell<Vec<(u32, u64)>>,
}

impl RecSlasher {
    fn new() -> Self {
        Self {
            credits: RefCell::new(Vec::new()),
        }
    }
}

impl CollateralSlasher for RecSlasher {
    fn credit(&mut self, validator_index: u32, amount_mojos: u64) {
        self.credits
            .borrow_mut()
            .push((validator_index, amount_mojos));
    }
}

fn attester_evidence(indices: Vec<u32>) -> SlashingEvidence {
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
        attesting_indices: indices,
        data,
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0u8; 32]),
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

/// Build a PendingSlash with per-validator `(idx, base_slash,
/// collateral_slashed)` tuples.
fn pending_with(per: Vec<(u32, u64, u64)>) -> PendingSlash {
    let indices: Vec<u32> = per.iter().map(|(i, _, _)| *i).collect();
    PendingSlash {
        evidence_hash: Bytes32::new([0xA1u8; 32]),
        evidence: attester_evidence(indices.clone()),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: indices,
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: per
            .iter()
            .map(|(i, b, c)| PerValidatorSlash {
                validator_index: *i,
                base_slash_amount: *b,
                effective_balance_at_slash: 32_000_000_000,
                collateral_slashed: *c,
            })
            .collect(),
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    }
}

fn attester_appeal(evidence_hash: Bytes32, ground: AttesterAppealGround) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground,
            witness: vec![],
        }),
    }
}

fn sustained_identical() -> AppealVerdict {
    AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    }
}

/// DSL-065 row 1: collateral supplied + 3 validators with
/// non-zero `collateral_slashed` → 3 credits recorded in scope
/// order.
#[test]
fn test_dsl_065_collateral_credited() {
    let pending = pending_with(vec![
        (2, 200_000_000, 50_000),
        (3, 300_000_000, 75_000),
        (4, 400_000_000, 100_000),
    ]);
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let mut slasher = RecSlasher::new();

    let credited = adjudicate_sustained_revert_collateral(
        &pending,
        &appeal,
        &sustained_identical(),
        Some(&mut slasher),
    );
    assert_eq!(credited, vec![2, 3, 4]);

    let calls = slasher.credits.borrow();
    assert_eq!(calls.as_slice(), &[(2, 50_000), (3, 75_000), (4, 100_000)],);
}

/// DSL-065 row 2: `collateral: None` → no credits, no panic.
/// Light-client path.
#[test]
fn test_dsl_065_no_collateral_no_op() {
    let pending = pending_with(vec![(2, 200_000_000, 50_000), (3, 300_000_000, 75_000)]);
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );

    let credited =
        adjudicate_sustained_revert_collateral(&pending, &appeal, &sustained_identical(), None);
    assert!(credited.is_empty());
}

/// DSL-065 row 3: validators with `collateral_slashed == 0` are
/// skipped even when the slasher is present. Mixes zero and
/// non-zero to prove the filter is per-entry, not global.
#[test]
fn test_dsl_065_zero_collateral_skipped() {
    let pending = pending_with(vec![
        (2, 200_000_000, 0),      // no collateral debit
        (3, 300_000_000, 75_000), // real collateral
        (4, 400_000_000, 0),      // no collateral debit
    ]);
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let mut slasher = RecSlasher::new();

    let credited = adjudicate_sustained_revert_collateral(
        &pending,
        &appeal,
        &sustained_identical(),
        Some(&mut slasher),
    );
    assert_eq!(credited, vec![3], "only index 3 has collateral > 0");

    let calls = slasher.credits.borrow();
    assert_eq!(calls.as_slice(), &[(3, 75_000)]);
}
