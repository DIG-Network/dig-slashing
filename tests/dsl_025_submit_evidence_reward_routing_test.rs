//! Requirement DSL-025: `SlashingManager::submit_evidence` routes two
//! optimistic rewards on admission.
//!
//! Traces to: docs/resources/SPEC.md §4, §7.3 steps 7–11, §12.1, §22.3.
//!
//! # Formula
//!
//!   wb_reward   = total_eff_bal / WHISTLEBLOWER_REWARD_QUOTIENT (512)
//!   prop_reward = wb_reward     / PROPOSER_REWARD_QUOTIENT       (8)
//!   burn_amount = total_base_slash - wb_reward - prop_reward
//!
//! # Payout order
//!
//! 1. `reward_payout.pay(evidence.reporter_puzzle_hash, wb_reward)`
//! 2. `reward_payout.pay(block_proposer_puzzle_hash, prop_reward)`
//!
//! Both calls fire unconditionally — even on zero amounts — so the
//! audit call-pattern is deterministic per admission.
//!
//! # Test matrix (maps to DSL-025 Test Plan)
//!
//!   1. `test_dsl_025_reward_routing_happy_path`
//!   2. `test_dsl_025_reward_to_reporter_puzzle_hash`
//!   3. `test_dsl_025_reward_to_proposer_puzzle_hash`
//!   4. `test_dsl_025_burn_amount_accounting`
//!   5. `test_dsl_025_multi_validator_totals`
//!   6. `test_dsl_025_zero_rewards_when_eff_bal_tiny`
//!   7. `test_dsl_025_proposer_lookup_uses_current_slot`
//!   8. `test_dsl_025_reward_routing_determinism`
//!   9. `test_dsl_025_proposer_unavailable_errors`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    PROPOSER_REWARD_QUOTIENT, ProposerSlashing, ProposerView, RewardPayout, SignedBlockHeader,
    SlashingError, SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry,
    ValidatorView, WHISTLEBLOWER_REWARD_QUOTIENT, block_signing_message,
};

// ── Reward payout mock with call recording ─────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
struct PayRecord {
    ph: Bytes32,
    amount: u64,
}

struct RecordingReward {
    calls: RefCell<Vec<PayRecord>>,
}

impl RecordingReward {
    fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
        }
    }
}

impl RewardPayout for RecordingReward {
    fn pay(&mut self, principal_ph: Bytes32, amount_mojos: u64) {
        self.calls.borrow_mut().push(PayRecord {
            ph: principal_ph,
            amount: amount_mojos,
        });
    }
}

/// Proposer mock — records `(slot_queried, proposer_idx_returned)`
/// and can be configured to return `None`.
struct RecordingProposer {
    current_slot_value: u64,
    verdict: Option<u32>,
    slots_queried: RefCell<Vec<u64>>,
}

impl RecordingProposer {
    fn returning(idx: u32, current_slot: u64) -> Self {
        Self {
            current_slot_value: current_slot,
            verdict: Some(idx),
            slots_queried: RefCell::new(Vec::new()),
        }
    }
    fn unavailable(current_slot: u64) -> Self {
        Self {
            current_slot_value: current_slot,
            verdict: None,
            slots_queried: RefCell::new(Vec::new()),
        }
    }
}

impl ProposerView for RecordingProposer {
    fn proposer_at_slot(&self, slot: u64) -> Option<u32> {
        self.slots_queried.borrow_mut().push(slot);
        self.verdict
    }
    fn current_slot(&self) -> u64 {
        self.current_slot_value
    }
}

struct AcceptingBondEscrow;

impl BondEscrow for AcceptingBondEscrow {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn forfeit(&mut self, _: u32, _: u64, _: BondTag) -> Result<u64, BondError> {
        Ok(0)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

// ── Validator fixtures ──────────────────────────────────────────────────

struct TestValidator {
    pk: PublicKey,
    ph: Bytes32,
}

impl ValidatorEntry for TestValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        self.ph
    }
    fn effective_balance(&self) -> u64 {
        MIN_EFFECTIVE_BALANCE
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
    fn slash_absolute(&mut self, _: u64, _: u64) -> u64 {
        0
    }
    fn credit_stake(&mut self, _: u64) -> u64 {
        0
    }
    fn restore_status(&mut self) -> bool {
        false
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct MapView(HashMap<u32, TestValidator>);

impl ValidatorView for MapView {
    fn get(&self, index: u32) -> Option<&dyn ValidatorEntry> {
        self.0.get(&index).map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, index: u32) -> Option<&mut dyn ValidatorEntry> {
        self.0.get_mut(&index).map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

struct MapBalances(HashMap<u32, u64>);

impl EffectiveBalanceView for MapBalances {
    fn get(&self, index: u32) -> u64 {
        self.0.get(&index).copied().unwrap_or(0)
    }
    fn total_active(&self) -> u64 {
        self.0.values().sum()
    }
}

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn sample_header(proposer_index: u32, epoch: u64, state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        epoch,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_byte; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        proposer_index,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn sign_header(sk: &SecretKey, header: &L2BlockHeader, nid: &Bytes32) -> Vec<u8> {
    let msg = block_signing_message(nid, header.epoch, &header.hash(), header.proposer_index);
    chia_bls::sign(sk, msg).to_bytes().to_vec()
}

const REPORTER_PH: Bytes32 = Bytes32::new([0xCCu8; 32]);
const BLOCK_PROPOSER_PH: Bytes32 = Bytes32::new([0xDDu8; 32]);
const REPORTER_IDX: u32 = 42;
const BLOCK_PROPOSER_IDX: u32 = 77;

/// Build a proposer-equivocation envelope. Validator view includes
/// BOTH the accused and the distinct block-proposer (to receive the
/// inclusion reward) — they have distinct puzzle hashes.
fn proposer_fixture(accused_idx: u32, epoch: u64) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk_accused = make_sk(0x11);
    let pk_accused = sk_accused.public_key();
    let header_a = sample_header(accused_idx, epoch, 0xA1);
    let header_b = sample_header(accused_idx, epoch, 0xB2);
    let sig_a = sign_header(&sk_accused, &header_a, &nid);
    let sig_b = sign_header(&sk_accused, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(
        accused_idx,
        TestValidator {
            pk: pk_accused,
            ph: Bytes32::new([0xEEu8; 32]), // accused: not the proposer of the block
        },
    );
    // Block proposer (distinct from accused) — receives prop_reward.
    let sk_proposer = make_sk(0x22);
    map.insert(
        BLOCK_PROPOSER_IDX,
        TestValidator {
            pk: sk_proposer.public_key(),
            ph: BLOCK_PROPOSER_PH,
        },
    );

    let ev = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: REPORTER_IDX,
        reporter_puzzle_hash: REPORTER_PH,
        epoch,
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: SignedBlockHeader {
                message: header_a,
                signature: sig_a,
            },
            signed_header_b: SignedBlockHeader {
                message: header_b,
                signature: sig_b,
            },
        }),
    };
    (ev, MapView(map))
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-025 row 1: happy path — two payouts, one per principal,
/// correct amounts, `SlashingResult` fields populated.
#[test]
fn test_dsl_025_reward_routing_happy_path() {
    let (ev, mut view) = proposer_fixture(9, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &proposer,
            &network_id(),
        )
        .expect("submit");

    let expected_wb = MIN_EFFECTIVE_BALANCE / WHISTLEBLOWER_REWARD_QUOTIENT;
    let expected_prop = expected_wb / PROPOSER_REWARD_QUOTIENT;
    assert_eq!(result.whistleblower_reward, expected_wb);
    assert_eq!(result.proposer_reward, expected_prop);

    let calls = reward.calls.borrow();
    assert_eq!(calls.len(), 2, "exactly two pay() calls");
    assert_eq!(calls[0].amount, expected_wb);
    assert_eq!(calls[1].amount, expected_prop);
}

/// DSL-025 row 2: first call targets the reporter's puzzle hash.
#[test]
fn test_dsl_025_reward_to_reporter_puzzle_hash() {
    let (ev, mut view) = proposer_fixture(9, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let mut mgr = SlashingManager::new(3);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("submit");
    assert_eq!(reward.calls.borrow()[0].ph, REPORTER_PH);
}

/// DSL-025 row 3: second call targets the block-proposer's puzzle hash.
#[test]
fn test_dsl_025_reward_to_proposer_puzzle_hash() {
    let (ev, mut view) = proposer_fixture(9, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let mut mgr = SlashingManager::new(3);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("submit");
    assert_eq!(reward.calls.borrow()[1].ph, BLOCK_PROPOSER_PH);
}

/// DSL-025 row 4: `whistleblower_reward + proposer_reward + burn_amount
/// == total_base_slash` across every per-validator entry.
#[test]
fn test_dsl_025_burn_amount_accounting() {
    let (ev, mut view) = proposer_fixture(9, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &proposer,
            &network_id(),
        )
        .expect("submit");

    let total_base: u64 = result
        .per_validator
        .iter()
        .map(|p| p.base_slash_amount)
        .sum();
    assert_eq!(
        result.whistleblower_reward + result.proposer_reward + result.burn_amount,
        total_base,
        "rewards + burn must equal total base slash",
    );
}

/// DSL-025 row 5: multi-validator — `total_eff_bal` summed across
/// slashed validators drives `wb_reward`. Build attester evidence
/// with 3 signers.
#[test]
fn test_dsl_025_multi_validator_totals() {
    use dig_slashing::{AttestationData, AttesterSlashing, Checkpoint, IndexedAttestation};

    let nid = network_id();
    let indices = vec![3u32, 5, 7];
    let data_a = AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0xA1u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    };
    let data_b = AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0xB2u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    };
    let sr_a = data_a.signing_root(&nid);
    let sr_b = data_b.signing_root(&nid);
    let mut sigs_a = Vec::new();
    let mut sigs_b = Vec::new();
    let mut map = HashMap::new();
    for idx in &indices {
        let sk = make_sk(*idx as u8);
        let pk = sk.public_key();
        map.insert(
            *idx,
            TestValidator {
                pk,
                ph: Bytes32::new([0xEEu8; 32]),
            },
        );
        sigs_a.push(chia_bls::sign(&sk, sr_a.as_ref()));
        sigs_b.push(chia_bls::sign(&sk, sr_b.as_ref()));
    }
    // Block proposer.
    let sk_prop = make_sk(0xF0);
    map.insert(
        BLOCK_PROPOSER_IDX,
        TestValidator {
            pk: sk_prop.public_key(),
            ph: BLOCK_PROPOSER_PH,
        },
    );
    let agg_a = chia_bls::aggregate(&sigs_a);
    let agg_b = chia_bls::aggregate(&sigs_b);
    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: REPORTER_IDX,
        reporter_puzzle_hash: REPORTER_PH,
        epoch: 3,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: IndexedAttestation {
                attesting_indices: indices.clone(),
                data: data_a,
                signature: agg_a.to_bytes().to_vec(),
            },
            attestation_b: IndexedAttestation {
                attesting_indices: indices,
                data: data_b,
                signature: agg_b.to_bytes().to_vec(),
            },
        }),
    };
    let balances = MapBalances(HashMap::from([
        (3u32, MIN_EFFECTIVE_BALANCE),
        (5, MIN_EFFECTIVE_BALANCE),
        (7, MIN_EFFECTIVE_BALANCE),
    ]));
    let mut view = MapView(map);
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &proposer,
            &network_id(),
        )
        .expect("submit");

    let total_eff = 3 * MIN_EFFECTIVE_BALANCE;
    let expected_wb = total_eff / WHISTLEBLOWER_REWARD_QUOTIENT;
    assert_eq!(result.whistleblower_reward, expected_wb);
    assert_eq!(
        result.proposer_reward,
        expected_wb / PROPOSER_REWARD_QUOTIENT
    );
}

/// DSL-025 row 6: `eff_bal < WHISTLEBLOWER_REWARD_QUOTIENT` → rewards
/// round to zero; both `pay(..., 0)` calls still fire.
#[test]
fn test_dsl_025_zero_rewards_when_eff_bal_tiny() {
    let (ev, mut view) = proposer_fixture(9, 3);
    // eff_bal = 100 (< 512) → wb_reward = 0 → prop_reward = 0.
    let balances = MapBalances(HashMap::from([(9u32, 100u64)]));
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &proposer,
            &network_id(),
        )
        .expect("submit");
    assert_eq!(result.whistleblower_reward, 0);
    assert_eq!(result.proposer_reward, 0);

    let calls = reward.calls.borrow();
    assert_eq!(calls.len(), 2, "both pay() calls must fire even on zero");
    assert_eq!(calls[0].amount, 0);
    assert_eq!(calls[1].amount, 0);
}

/// DSL-025 row 7: `proposer_at_slot(current_slot())` queried exactly
/// once with the `current_slot` value.
#[test]
fn test_dsl_025_proposer_lookup_uses_current_slot() {
    let (ev, mut view) = proposer_fixture(9, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 1234);
    let mut mgr = SlashingManager::new(3);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("submit");

    let slots = proposer.slots_queried.borrow();
    assert_eq!(slots.as_slice(), &[1234u64]);
}

/// DSL-025 row 8: determinism — two managers, same inputs, same
/// `pay()` call sequence + amounts.
#[test]
fn test_dsl_025_reward_routing_determinism() {
    let (ev1, mut view1) = proposer_fixture(9, 3);
    let (ev2, mut view2) = proposer_fixture(9, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut b1 = AcceptingBondEscrow;
    let mut b2 = AcceptingBondEscrow;
    let mut r1 = RecordingReward::new();
    let mut r2 = RecordingReward::new();
    let p1 = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let p2 = RecordingProposer::returning(BLOCK_PROPOSER_IDX, 100);
    let mut m1 = SlashingManager::new(3);
    let mut m2 = SlashingManager::new(3);

    m1.submit_evidence(
        ev1,
        &mut view1,
        &balances,
        &mut b1,
        &mut r1,
        &p1,
        &network_id(),
    )
    .unwrap();
    m2.submit_evidence(
        ev2,
        &mut view2,
        &balances,
        &mut b2,
        &mut r2,
        &p2,
        &network_id(),
    )
    .unwrap();

    assert_eq!(*r1.calls.borrow(), *r2.calls.borrow());
}

/// DSL-025 row 9: `ProposerView::proposer_at_slot` returning `None`
/// surfaces as `SlashingError::ProposerUnavailable`. Reporter payout
/// already fired; validator state was mutated — this is a
/// consensus-layer bug surface, not a user-visible failure path.
#[test]
fn test_dsl_025_proposer_unavailable_errors() {
    let (ev, mut view) = proposer_fixture(9, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = AcceptingBondEscrow;
    let mut reward = RecordingReward::new();
    let proposer = RecordingProposer::unavailable(100);
    let mut mgr = SlashingManager::new(3);

    let err = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &proposer,
            &network_id(),
        )
        .expect_err("proposer=None must surface");
    assert_eq!(err, SlashingError::ProposerUnavailable);
    // Reporter reward HAS been paid (it runs before the proposer
    // lookup) — confirms the pipeline ordering.
    assert_eq!(reward.calls.borrow().len(), 1);
    assert_eq!(reward.calls.borrow()[0].ph, REPORTER_PH);
}
