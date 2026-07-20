//! Requirement DSL-025 (atomicity guard, sibling branch): when the
//! proposer reward target resolves to an index that is ABSENT from the
//! validator set (`ProposerView::proposer_at_slot` returns `Some(idx)`
//! but `ValidatorView::get(idx)` is `None`),
//! `SlashingManager::submit_evidence` MUST reject with
//! `ValidatorNotRegistered(idx)` WITHOUT any validator-side mutation —
//! no bond lock, no `slash_absolute`, no reward payout, no pending-book
//! insert, no `processed` entry.
//!
//! This is the companion to
//! `dsl_025_submit_evidence_proposer_unavailable_atomicity_test`, which
//! covers the `proposer_at_slot → None` (`ProposerUnavailable`) branch.
//! Both branches are the fallible, read-only proposer-resolution guard
//! hoisted ABOVE the bond lock by dig_ecosystem #346 finding-B; this
//! file proves the SAME no-mutation invariant for the second, sibling
//! error path — the resolved index not being a registered validator.
//!
//! Traces to: docs/resources/SPEC.md §7.3, §22.3.
//!
//! # Test matrix
//!
//!   1. `test_dsl_025_unregistered_proposer_returns_validator_not_registered`
//!   2. `test_dsl_025_unregistered_proposer_no_bond_lock`
//!   3. `test_dsl_025_unregistered_proposer_no_validator_mutation`
//!   4. `test_dsl_025_unregistered_proposer_no_reward_payout`
//!   5. `test_dsl_025_unregistered_proposer_no_pending_insert_or_processed`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    ProposerSlashing, ProposerView, RewardPayout, SignedBlockHeader, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry, ValidatorView,
    block_signing_message,
};

/// Index the proposer view resolves to but which is deliberately never
/// inserted into the `MapView` validator set — the trigger for the
/// `ValidatorNotRegistered` branch.
const UNREGISTERED_PROPOSER_INDEX: u32 = 777;

// ── Bond escrow mock counting lock calls ──────────────────────────────

struct ToggleBond {
    calls: RefCell<u32>,
    verdict: RefCell<Result<(), BondError>>,
}

impl ToggleBond {
    fn accepting() -> Self {
        Self {
            calls: RefCell::new(0),
            verdict: RefCell::new(Ok(())),
        }
    }
}

impl BondEscrow for ToggleBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        *self.calls.borrow_mut() += 1;
        self.verdict.borrow().clone()
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

#[derive(Default)]
struct RecordingReward(RefCell<u32>);
impl RewardPayout for RecordingReward {
    fn pay(&mut self, _: Bytes32, _: u64) {
        *self.0.borrow_mut() += 1;
    }
}

/// The reward proposer resolves to a concrete index that is NOT a
/// registered validator. Drives the `ValidatorNotRegistered` path:
/// `proposer_at_slot` returns `Some(idx)`, but the validator set has no
/// entry at `idx`.
struct UnregisteredProposer;
impl ProposerView for UnregisteredProposer {
    fn proposer_at_slot(&self, _: u64) -> Option<u32> {
        Some(UNREGISTERED_PROPOSER_INDEX)
    }
    fn current_slot(&self) -> u64 {
        0
    }
}

struct TestValidator {
    pk: PublicKey,
    slash_calls: RefCell<u32>,
}

impl ValidatorEntry for TestValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        Bytes32::new([0u8; 32])
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
        *self.slash_calls.borrow_mut() += 1;
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

/// Build valid proposer-equivocation evidence + a validator set that
/// registers the slashed proposer (at `proposer_index`) but NOT the
/// reward-proposer index the `UnregisteredProposer` view resolves to.
fn proposer_evidence(
    proposer_index: u32,
    reporter: u32,
    epoch: u64,
) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = sample_header(proposer_index, epoch, 0xA1);
    let header_b = sample_header(proposer_index, epoch, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    // Only the slashed validator is registered. Index
    // `UNREGISTERED_PROPOSER_INDEX` is intentionally absent so the reward
    // proposer resolves to a `None` validator-set entry.
    let mut map = HashMap::new();
    map.insert(
        proposer_index,
        TestValidator {
            pk,
            slash_calls: RefCell::new(0),
        },
    );

    let ev = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
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

/// The resolved-but-unregistered proposer surfaces as
/// `ValidatorNotRegistered(idx)` carrying the offending index.
#[test]
fn test_dsl_025_unregistered_proposer_returns_validator_not_registered() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = UnregisteredProposer;
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
        .expect_err("unregistered reward proposer must reject");
    assert_eq!(
        err,
        SlashingError::ValidatorNotRegistered(UNREGISTERED_PROPOSER_INDEX),
    );
}

/// Atomicity: the bond is NOT locked — proposer resolution precedes the
/// lock, so the fallible precondition fails before any mutation.
#[test]
fn test_dsl_025_unregistered_proposer_no_bond_lock() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = UnregisteredProposer;
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
    .expect_err("reject");
    assert_eq!(
        *bond.calls.borrow(),
        0,
        "bond.lock MUST NOT run when the reward proposer is unregistered",
    );
}

/// Atomicity: no `slash_absolute` on any validator.
#[test]
fn test_dsl_025_unregistered_proposer_no_validator_mutation() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = UnregisteredProposer;
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
    .expect_err("reject");
    assert_eq!(
        *view.0.get(&9).unwrap().slash_calls.borrow(),
        0,
        "no slash_absolute on the ValidatorNotRegistered path",
    );
}

/// Atomicity: no reward payout (neither whistleblower nor proposer).
#[test]
fn test_dsl_025_unregistered_proposer_no_reward_payout() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = UnregisteredProposer;
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
    .expect_err("reject");
    assert_eq!(
        *reward.0.borrow(),
        0,
        "no reward.pay on the ValidatorNotRegistered path",
    );
}

/// Atomicity: no pending-book record and no `processed` entry, so the
/// evidence can be re-submitted once the reward proposer is registered.
#[test]
fn test_dsl_025_unregistered_proposer_no_pending_insert_or_processed() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let hash = ev.hash();
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = UnregisteredProposer;
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
    .expect_err("reject");
    assert_eq!(mgr.book().len(), 0, "no pending record inserted");
    assert!(!mgr.is_processed(&hash), "processed must NOT be set");
}
