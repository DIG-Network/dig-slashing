//! Requirement DSL-027: `SlashingManager::submit_evidence` rejects with
//! `SlashingError::PendingBookFull` when `book.len() >= capacity`. No
//! bond lock, no validator mutation, no reward payout on the
//! rejection path.
//!
//! Traces to: docs/resources/SPEC.md §2.6, §7.1, §7.3 step 3, §17, §22.3.
//!
//! # Ordering
//!
//! Capacity check runs AFTER `verify_evidence` + dedup but BEFORE
//! bond lock. The order ensures only valid, non-duplicate evidence
//! can trigger capacity exhaustion — no reporter bond gets locked
//! for a slash that can't be admitted.
//!
//! # Strategy
//!
//! Tests use `SlashingManager::with_book_capacity(current_epoch, n)`
//! to construct managers with tiny capacities (1, 2) so the
//! capacity-exhaustion path is reachable in constant test time.
//! Full production capacity (`MAX_PENDING_SLASHES = 4_096`) is
//! validated indirectly via the constant-value check in DSL-024.
//!
//! # Test matrix (maps to DSL-027 Test Plan)
//!
//!   1. `test_dsl_027_submit_succeeds_at_capacity_minus_one`
//!   2. `test_dsl_027_submit_rejected_at_capacity`
//!   3. `test_dsl_027_book_full_no_bond_lock`
//!   4. `test_dsl_027_book_full_no_validator_mutation`
//!   5. `test_dsl_027_book_full_no_processed_entry`
//!   6. `test_dsl_027_book_full_no_reward_payout`
//!   7. `test_dsl_027_book_full_check_after_verify`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    ProposerSlashing, ProposerView, RewardPayout, SLASH_LOOKBACK_EPOCHS, SignedBlockHeader,
    SlashingError, SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry,
    ValidatorView, block_signing_message,
};

// ── Recording mocks ────────────────────────────────────────────────────

#[derive(Default)]
struct RecordingBond(RefCell<u32>);
impl BondEscrow for RecordingBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        *self.0.borrow_mut() += 1;
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

/// Build evidence with distinct `variant_byte` → distinct hash so
/// multiple admissions can fill the book.
fn proposer_evidence(
    proposer_index: u32,
    reporter: u32,
    epoch: u64,
    variant_byte: u8,
) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = sample_header(proposer_index, epoch, 0xA1 ^ variant_byte);
    let header_b = sample_header(proposer_index, epoch, 0xB2 ^ variant_byte);
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
    // Block proposer for DSL-025 reward path.
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

/// Merge `view2` into `view` (add all validator entries). Used to
/// share a single `MapView` across multiple admissions.
fn merge_view(dst: &mut MapView, src: MapView) {
    for (k, v) in src.0 {
        dst.0.entry(k).or_insert(v);
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-027 row 1: at `book.len() == capacity - 1`, submit still
/// succeeds and brings the book to exactly `capacity`.
#[test]
fn test_dsl_027_submit_succeeds_at_capacity_minus_one() {
    // Capacity = 2 → first admit leaves len=1, second admit len=2, third rejects.
    let mut mgr = SlashingManager::with_book_capacity(3, 2);
    let (ev1, view1) = proposer_evidence(9, 42, 3, 0x00);
    let (ev2, view2) = proposer_evidence(9, 42, 3, 0x10);
    let mut view = view1;
    merge_view(&mut view, view2);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;

    mgr.submit_evidence(
        ev1,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("1st admit");
    assert_eq!(mgr.book().len(), 1);
    // At capacity-1 = 1; submit_evidence still succeeds → len = 2 == capacity.
    mgr.submit_evidence(
        ev2,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("2nd admit at capacity-1 must succeed");
    assert_eq!(mgr.book().len(), 2);
}

/// DSL-027 row 2: at `book.len() == capacity`, next submit rejected
/// with `PendingBookFull`.
#[test]
fn test_dsl_027_submit_rejected_at_capacity() {
    let mut mgr = SlashingManager::with_book_capacity(3, 2);
    let (ev1, view1) = proposer_evidence(9, 42, 3, 0x00);
    let (ev2, view2) = proposer_evidence(9, 42, 3, 0x10);
    let (ev3, view3) = proposer_evidence(9, 42, 3, 0x20);
    let mut view = view1;
    merge_view(&mut view, view2);
    merge_view(&mut view, view3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;

    mgr.submit_evidence(
        ev1,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("1st");
    mgr.submit_evidence(
        ev2,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("2nd");
    assert_eq!(mgr.book().len(), 2);

    let err = mgr
        .submit_evidence(
            ev3,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &proposer,
            &network_id(),
        )
        .expect_err("3rd must reject");
    assert_eq!(err, SlashingError::PendingBookFull);
    assert_eq!(mgr.book().len(), 2, "book unchanged on rejection");
}

/// DSL-027 row 3: rejection path does NOT call `bond.lock`.
#[test]
fn test_dsl_027_book_full_no_bond_lock() {
    let mut mgr = SlashingManager::with_book_capacity(3, 1);
    let (ev1, view1) = proposer_evidence(9, 42, 3, 0x00);
    let (ev2, view2) = proposer_evidence(9, 42, 3, 0x10);
    let mut view = view1;
    merge_view(&mut view, view2);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;

    mgr.submit_evidence(
        ev1,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("1st");
    assert_eq!(*bond.0.borrow(), 1, "1st admit locked once");

    mgr.submit_evidence(
        ev2,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect_err("2nd must reject");
    assert_eq!(
        *bond.0.borrow(),
        1,
        "PendingBookFull path must not invoke bond.lock",
    );
}

/// DSL-027 row 4: rejection path does NOT call `slash_absolute` on
/// any validator.
#[test]
fn test_dsl_027_book_full_no_validator_mutation() {
    let mut mgr = SlashingManager::with_book_capacity(3, 1);
    let (ev1, view1) = proposer_evidence(9, 42, 3, 0x00);
    let (ev2, view2) = proposer_evidence(9, 42, 3, 0x10);
    let mut view = view1;
    merge_view(&mut view, view2);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;

    mgr.submit_evidence(
        ev1,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("1st");
    let slash_before = *view.0.get(&9).unwrap().slash_calls.borrow();

    mgr.submit_evidence(
        ev2,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect_err("2nd reject");
    assert_eq!(
        *view.0.get(&9).unwrap().slash_calls.borrow(),
        slash_before,
        "rejected admit must not call slash_absolute",
    );
}

/// DSL-027 row 5: rejection path does NOT register the hash in
/// `processed`. Retry is allowed once capacity frees.
#[test]
fn test_dsl_027_book_full_no_processed_entry() {
    let mut mgr = SlashingManager::with_book_capacity(3, 1);
    let (ev1, view1) = proposer_evidence(9, 42, 3, 0x00);
    let (ev2, view2) = proposer_evidence(9, 42, 3, 0x10);
    let hash2 = ev2.hash();
    let mut view = view1;
    merge_view(&mut view, view2);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;

    mgr.submit_evidence(
        ev1,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("1st");
    mgr.submit_evidence(
        ev2,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect_err("2nd reject");

    assert!(
        !mgr.is_processed(&hash2),
        "rejected hash must not be in processed — retry permitted",
    );
}

/// DSL-027 row 6: rejection path does NOT call `reward.pay`.
#[test]
fn test_dsl_027_book_full_no_reward_payout() {
    let mut mgr = SlashingManager::with_book_capacity(3, 1);
    let (ev1, view1) = proposer_evidence(9, 42, 3, 0x00);
    let (ev2, view2) = proposer_evidence(9, 42, 3, 0x10);
    let mut view = view1;
    merge_view(&mut view, view2);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;

    mgr.submit_evidence(
        ev1,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("1st");
    assert_eq!(*reward.0.borrow(), 2, "1st admit paid wb + prop");

    mgr.submit_evidence(
        ev2,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect_err("2nd reject");
    assert_eq!(
        *reward.0.borrow(),
        2,
        "PendingBookFull must not invoke reward.pay",
    );
}

/// DSL-027 row 7: verify runs BEFORE capacity check. At full capacity,
/// invalid evidence (OffenseTooOld) surfaces as OffenseTooOld — NOT
/// PendingBookFull.
#[test]
fn test_dsl_027_book_full_check_after_verify() {
    let mut mgr = SlashingManager::with_book_capacity(3, 1);
    let (ev1, view1) = proposer_evidence(9, 42, 3, 0x00);
    // Fill to capacity = 1.
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();
    let proposer = FixedProposer;

    let mut view = view1;
    mgr.submit_evidence(
        ev1,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &proposer,
        &network_id(),
    )
    .expect("1st");
    assert_eq!(mgr.book().len(), 1);

    // Now advance mgr's current_epoch so a NEW evidence with tiny
    // epoch is too old. Reuse with_book_capacity to produce a new mgr
    // at an epoch past lookback, with the SAME book state (can't —
    // book is per-manager). Instead construct a new manager at
    // distant epoch with a tight book.
    let mut mgr2 = SlashingManager::with_book_capacity(SLASH_LOOKBACK_EPOCHS + 100, 1);
    let (ev_fill, view_fill) = proposer_evidence(9, 42, SLASH_LOOKBACK_EPOCHS + 100, 0x30);
    let (ev_old, view_old) = proposer_evidence(9, 42, 0, 0x40); // epoch 0 → too old
    let mut view2 = view_fill;
    merge_view(&mut view2, view_old);
    let balances2 = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond2 = RecordingBond::default();
    let mut reward2 = RecordingReward::default();

    mgr2.submit_evidence(
        ev_fill,
        &mut view2,
        &balances2,
        &mut bond2,
        &mut reward2,
        &proposer,
        &network_id(),
    )
    .expect("fill");
    // Book now at capacity; ev_old is too-old.
    let err = mgr2
        .submit_evidence(
            ev_old,
            &mut view2,
            &balances2,
            &mut bond2,
            &mut reward2,
            &proposer,
            &network_id(),
        )
        .expect_err("must reject");
    assert!(
        matches!(err, SlashingError::OffenseTooOld { .. }),
        "verify must run before capacity check; got {err:?}",
    );
}
