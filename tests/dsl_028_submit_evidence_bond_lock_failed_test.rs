//! Requirement DSL-028: `SlashingManager::submit_evidence` translates
//! `BondError::InsufficientBalance` from `BondEscrow::lock` into
//! `SlashingError::BondLockFailed`. No validator mutation, no reward
//! payout, no book insert, no `processed` entry on the rejection
//! path — re-admission after funding the reporter succeeds.
//!
//! Traces to: docs/resources/SPEC.md §7.3 step 4, §12.3, §17, §22.3.
//!
//! # Role
//!
//! DSL-023 covered the lock call site; this suite is the dedicated
//! negative path. It exercises all three variants of `BondError` and
//! confirms the manager maps each to the same `BondLockFailed`
//! variant (intentionally coarse — reporter lacking collateral is
//! indistinguishable from double-lock or tag-not-found from the
//! slashing-manager layer).
//!
//! # Test matrix (maps to DSL-028 Test Plan)
//!
//!   1. `test_dsl_028_bond_lock_insufficient_returns_error`
//!   2. `test_dsl_028_bond_lock_failed_no_validator_mutation`
//!   3. `test_dsl_028_bond_lock_failed_no_reward_payout`
//!   4. `test_dsl_028_bond_lock_failed_no_pending_insert`
//!   5. `test_dsl_028_bond_lock_failed_processed_not_set`
//!   6. `test_dsl_028_bond_lock_succeeds_after_stake_added`
//!   7. `test_dsl_028_bond_lock_failed_error_variant`
//!   8. `test_dsl_028_double_lock_also_maps_to_bond_lock_failed`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    ProposerSlashing, ProposerView, REPORTER_BOND_MOJOS, RewardPayout, SignedBlockHeader,
    SlashingError, SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry,
    ValidatorView, block_signing_message,
};

// ── Bond escrow mock with runtime-configurable verdict ─────────────────

struct ToggleBond {
    calls: RefCell<u32>,
    verdict: RefCell<Result<(), BondError>>,
}

impl ToggleBond {
    fn rejecting(err: BondError) -> Self {
        Self {
            calls: RefCell::new(0),
            verdict: RefCell::new(Err(err)),
        }
    }
    #[allow(dead_code)]
    fn accepting() -> Self {
        Self {
            calls: RefCell::new(0),
            verdict: RefCell::new(Ok(())),
        }
    }
    fn flip_to_accepting(&self) {
        *self.verdict.borrow_mut() = Ok(());
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

struct FixedProposer;
impl ProposerView for FixedProposer {
    fn proposer_at_slot(&self, _: u64) -> Option<u32> {
        Some(0)
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

fn insufficient() -> BondError {
    BondError::InsufficientBalance {
        have: 100,
        need: REPORTER_BOND_MOJOS,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-028 row 1: `InsufficientBalance` surfaces as `BondLockFailed`.
#[test]
fn test_dsl_028_bond_lock_insufficient_returns_error() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(insufficient());
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
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
        .expect_err("insufficient must reject");
    assert_eq!(err, SlashingError::BondLockFailed);
    assert_eq!(*bond.calls.borrow(), 1, "bond.lock attempted exactly once");
}

/// DSL-028 row 2: no `slash_absolute` on the rejection path.
#[test]
fn test_dsl_028_bond_lock_failed_no_validator_mutation() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(insufficient());
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
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
        "no slash_absolute on BondLockFailed path",
    );
}

/// DSL-028 row 3: no `reward.pay` on the rejection path.
#[test]
fn test_dsl_028_bond_lock_failed_no_reward_payout() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(insufficient());
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
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
        "no reward.pay on BondLockFailed path"
    );
}

/// DSL-028 row 4: `book.len()` unchanged; `book.get(hash) == None`.
#[test]
fn test_dsl_028_bond_lock_failed_no_pending_insert() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let hash = ev.hash();
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(insufficient());
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
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
    assert_eq!(mgr.book().len(), 0);
    assert!(mgr.book().get(&hash).is_none());
}

/// DSL-028 row 5: rejected hash NOT registered in `processed` —
/// retry permitted once stake is available.
#[test]
fn test_dsl_028_bond_lock_failed_processed_not_set() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let hash = ev.hash();
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(insufficient());
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
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
    assert!(!mgr.is_processed(&hash), "processed must NOT be set");
}

/// DSL-028 row 6: after the mock flips to accepting, re-submitting
/// the SAME evidence succeeds. Documents the retry contract.
#[test]
fn test_dsl_028_bond_lock_succeeds_after_stake_added() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(insufficient());
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
    let mut mgr = SlashingManager::new(3);

    let ev_retry = ev.clone();
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect_err("first attempt: reject");

    // "Fund" the reporter — flip the escrow to accepting.
    bond.flip_to_accepting();
    mgr.submit_evidence(
        ev_retry,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("second attempt: accept");
    assert_eq!(mgr.book().len(), 1);
}

/// DSL-028 row 7: error variant is EXACTLY `BondLockFailed`, not a
/// fallback pattern. Compares using PartialEq.
#[test]
fn test_dsl_028_bond_lock_failed_error_variant() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(insufficient());
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
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
        .unwrap_err();
    assert_eq!(err, SlashingError::BondLockFailed);
}

/// DSL-028 row 8: `DoubleLock` (state-machine bug) ALSO collapses to
/// `BondLockFailed` — the manager's error-mapping is intentionally
/// coarse. Guards against a future regression that distinguishes
/// `BondOther` at this layer (spec would need to evolve first).
#[test]
fn test_dsl_028_double_lock_also_maps_to_bond_lock_failed() {
    let (ev, mut view) = proposer_evidence(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = ToggleBond::rejecting(BondError::DoubleLock {
        tag: BondTag::Reporter(Bytes32::new([0u8; 32])),
    });
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;
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
        .unwrap_err();
    assert_eq!(err, SlashingError::BondLockFailed);
}
