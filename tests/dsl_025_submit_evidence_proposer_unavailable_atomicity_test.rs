//! Requirement DSL-025 (atomicity guard): when the proposer reward
//! target cannot be resolved (`ProposerView::proposer_at_slot` returns
//! `None`, or the resolved index is absent from the validator set),
//! `SlashingManager::submit_evidence` MUST reject WITHOUT any
//! validator-side mutation — no bond lock, no `slash_absolute`, no
//! reward payout, no pending-book insert, no `processed` entry.
//!
//! This is the regression suite for dig_ecosystem #346 finding-B: the
//! proposer-target resolution was fallible AND ran AFTER the bond lock,
//! the slash loop, and the whistleblower payout, so a
//! `ProposerUnavailable` return irreversibly slashed validators and
//! locked the reporter bond with no record to appeal or finalise —
//! contradicting the DSL-023 invariant ("lock BEFORE any validator-side
//! mutation; failure → no validator-side mutation"). The fix hoists the
//! read-only proposer resolution ABOVE the bond lock, so an
//! unresolvable proposer mutates nothing.
//!
//! Traces to: docs/resources/SPEC.md §7.3, §22.3.
//!
//! # Test matrix
//!
//!   1. `test_dsl_025_no_proposer_returns_proposer_unavailable`
//!   2. `test_dsl_025_no_proposer_no_bond_lock`
//!   3. `test_dsl_025_no_proposer_no_validator_mutation`
//!   4. `test_dsl_025_no_proposer_no_reward_payout`
//!   5. `test_dsl_025_no_proposer_no_pending_insert_or_processed`

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

// ── Bond escrow mock with runtime-configurable verdict ─────────────────

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

/// The reward proposer cannot be resolved: `proposer_at_slot` always
/// returns `None`. This drives the `ProposerUnavailable` rejection path.
struct NoProposer;
impl ProposerView for NoProposer {
    fn proposer_at_slot(&self, _: u64) -> Option<u32> {
        None
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

    let mut map = HashMap::new();
    map.insert(
        proposer_index,
        TestValidator {
            pk,
            slash_calls: RefCell::new(0),
        },
    );
    let sk_prop = make_sk(0xFE);
    map.insert(
        0u32,
        TestValidator {
            pk: sk_prop.public_key(),
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

/// The unresolvable proposer surfaces as `ProposerUnavailable`.
#[test]
fn test_dsl_025_no_proposer_returns_proposer_unavailable() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = NoProposer;
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
        .expect_err("unresolvable proposer must reject");
    assert_eq!(err, SlashingError::ProposerUnavailable);
}

/// Atomicity: the bond is NOT locked — proposer resolution now precedes
/// the lock, so the fallible precondition fails before any mutation.
#[test]
fn test_dsl_025_no_proposer_no_bond_lock() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = NoProposer;
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
        "bond.lock MUST NOT run when the proposer target is unresolvable",
    );
}

/// Atomicity: no `slash_absolute` on any validator.
#[test]
fn test_dsl_025_no_proposer_no_validator_mutation() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = NoProposer;
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
        "no slash_absolute on the ProposerUnavailable path",
    );
}

/// Atomicity: no reward payout (neither whistleblower nor proposer).
#[test]
fn test_dsl_025_no_proposer_no_reward_payout() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = NoProposer;
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
        "no reward.pay on the ProposerUnavailable path",
    );
}

/// Atomicity: no pending-book record and no `processed` entry, so the
/// evidence can be re-submitted once the proposer view recovers.
#[test]
fn test_dsl_025_no_proposer_no_pending_insert_or_processed() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let hash = ev.hash();
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::accepting();
    let mut reward = RecordingReward::default();
    let proposer = NoProposer;
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
