//! Requirement DSL-069: on `AppealVerdict::Sustained` the
//! adjudicator MUST slash the reporter using the InvalidBlock
//! base formula and record the debit into `slashed_in_window`
//! for DSL-030 correlation amplification.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Formula
//!
//! `penalty = max(eff_bal * INVALID_BLOCK_BASE_BPS / BPS_DENOMINATOR,
//!              eff_bal / MIN_SLASHING_PENALTY_QUOTIENT)`
//!
//! Identical to the DSL-022 InvalidBlock branch — auditors can
//! diff admission-path and adjudication-path penalties and see
//! identical arithmetic by construction.
//!
//! # Test matrix (maps to DSL-069 Test Plan)
//!
//!   1. `test_dsl_069_reporter_slashed` — sustained → reporter's
//!      `slash_absolute(penalty, current_epoch)` called
//!   2. `test_dsl_069_recorded_in_window` — post-call
//!      `slashed_in_window` contains `(current_epoch,
//!      reporter_idx) → eff_bal`
//!   3. `test_dsl_069_formula_matches_invalid_block` — penalty
//!      equals `max(bps_term, floor_term)` with the exact
//!      SPEC constants

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use chia_bls::{PublicKey, SecretKey};
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE,
    BPS_DENOMINATOR, Checkpoint, EffectiveBalanceView, INVALID_BLOCK_BASE_BPS, IndexedAttestation,
    MIN_EFFECTIVE_BALANCE, MIN_SLASHING_PENALTY_QUOTIENT, OffenseType, PendingSlash,
    PendingSlashStatus, PerValidatorSlash, ReporterPenalty, SLASH_APPEAL_WINDOW_EPOCHS,
    SlashingEvidence, SlashingEvidencePayload, ValidatorEntry, ValidatorView, VerifiedEvidence,
    adjudicate_sustained_reporter_penalty,
};

struct RecValidator {
    pk: PublicKey,
    slash_calls: RefCell<Vec<(u64, u64)>>,
}

impl RecValidator {
    fn new(seed: u8) -> Self {
        Self {
            pk: SecretKey::from_seed(&[seed; 32]).public_key(),
            slash_calls: RefCell::new(Vec::new()),
        }
    }
}

impl ValidatorEntry for RecValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        Bytes32::new([0u8; 32])
    }
    fn effective_balance(&self) -> u64 {
        32_000_000_000
    }
    fn is_slashed(&self) -> bool {
        false
    }
    fn activation_epoch(&self) -> u64 {
        0
    }
    fn exit_epoch(&self) -> u64 {
        u64::MAX
    }
    fn is_active_at_epoch(&self, _: u64) -> bool {
        true
    }
    fn slash_absolute(&mut self, amount: u64, epoch: u64) -> u64 {
        self.slash_calls.borrow_mut().push((amount, epoch));
        amount
    }
    fn credit_stake(&mut self, _: u64) -> u64 {
        0
    }
    fn restore_status(&mut self) -> bool {
        false
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct MapView(HashMap<u32, RecValidator>);

impl ValidatorView for MapView {
    fn get(&self, idx: u32) -> Option<&dyn ValidatorEntry> {
        self.0.get(&idx).map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, idx: u32) -> Option<&mut dyn ValidatorEntry> {
        self.0.get_mut(&idx).map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Flat-balance view: every validator reports `MIN_EFFECTIVE_BALANCE`.
struct FlatBalances;
impl EffectiveBalanceView for FlatBalances {
    fn get(&self, _: u32) -> u64 {
        MIN_EFFECTIVE_BALANCE
    }
    fn total_active(&self) -> u64 {
        MIN_EFFECTIVE_BALANCE * 100
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

fn pending_with(reporter_idx: u32) -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([0xA1u8; 32]),
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
            base_slash_amount: 1_000_000_000,
            effective_balance_at_slash: MIN_EFFECTIVE_BALANCE,
            collateral_slashed: 0,
        }],
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    }
}

fn sustained() -> AppealVerdict {
    AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    }
}

fn view_with_reporter(reporter_idx: u32) -> MapView {
    let mut m = HashMap::new();
    m.insert(reporter_idx, RecValidator::new(0x01));
    MapView(m)
}

fn expected_penalty(eff_bal: u64) -> u64 {
    let bps = eff_bal * u64::from(INVALID_BLOCK_BASE_BPS) / BPS_DENOMINATOR;
    let floor = eff_bal / MIN_SLASHING_PENALTY_QUOTIENT;
    std::cmp::max(bps, floor)
}

/// DSL-069 row 1: sustained appeal → reporter's `slash_absolute`
/// called with the InvalidBlock penalty + current_epoch.
#[test]
fn test_dsl_069_reporter_slashed() {
    let pending = pending_with(42);
    let mut view = view_with_reporter(42);
    let balances = FlatBalances;
    let mut window: BTreeMap<(u64, u32), u64> = BTreeMap::new();
    let current_epoch = 20;

    let penalty = adjudicate_sustained_reporter_penalty(
        &pending,
        &sustained(),
        &mut view,
        &balances,
        &mut window,
        current_epoch,
    )
    .unwrap();

    let expected = expected_penalty(MIN_EFFECTIVE_BALANCE);
    assert_eq!(
        penalty,
        ReporterPenalty {
            reporter_index: 42,
            effective_balance_at_slash: MIN_EFFECTIVE_BALANCE,
            penalty_mojos: expected,
        },
    );

    let calls = view.0.get(&42).unwrap().slash_calls.borrow();
    assert_eq!(calls.as_slice(), &[(expected, current_epoch)]);
}

/// DSL-069 row 2: post-adjudicate the correlation-window map
/// contains `(current_epoch, reporter_idx) → eff_bal`.
#[test]
fn test_dsl_069_recorded_in_window() {
    let pending = pending_with(42);
    let mut view = view_with_reporter(42);
    let balances = FlatBalances;
    let mut window: BTreeMap<(u64, u32), u64> = BTreeMap::new();
    let current_epoch = 25;

    let _ = adjudicate_sustained_reporter_penalty(
        &pending,
        &sustained(),
        &mut view,
        &balances,
        &mut window,
        current_epoch,
    )
    .unwrap();

    assert_eq!(window.len(), 1);
    assert_eq!(
        window.get(&(current_epoch, 42)),
        Some(&MIN_EFFECTIVE_BALANCE)
    );
}

/// DSL-069 row 3: the computed penalty equals the InvalidBlock
/// admission-path formula byte-for-byte. Uses
/// `MIN_EFFECTIVE_BALANCE` where the floor term
/// (`eff_bal / MIN_SLASHING_PENALTY_QUOTIENT = eff_bal / 32`)
/// dominates the bps term (0.03%).
#[test]
fn test_dsl_069_formula_matches_invalid_block() {
    let pending = pending_with(42);
    let mut view = view_with_reporter(42);
    let balances = FlatBalances;
    let mut window: BTreeMap<(u64, u32), u64> = BTreeMap::new();

    let penalty = adjudicate_sustained_reporter_penalty(
        &pending,
        &sustained(),
        &mut view,
        &balances,
        &mut window,
        30,
    )
    .unwrap();

    let bps_term = MIN_EFFECTIVE_BALANCE * u64::from(INVALID_BLOCK_BASE_BPS) / BPS_DENOMINATOR;
    let floor_term = MIN_EFFECTIVE_BALANCE / MIN_SLASHING_PENALTY_QUOTIENT;
    assert_eq!(penalty.penalty_mojos, std::cmp::max(bps_term, floor_term));
    assert!(
        penalty.penalty_mojos >= floor_term,
        "penalty at least floor term",
    );
    assert!(
        penalty.penalty_mojos >= bps_term,
        "penalty at least bps term",
    );
}
