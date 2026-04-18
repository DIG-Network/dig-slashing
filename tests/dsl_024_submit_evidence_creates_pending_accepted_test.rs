//! Requirement DSL-024: `SlashingManager::submit_evidence` inserts a
//! `PendingSlash { status: Accepted, submitted_at_epoch, window_expires_at_epoch
//! = submitted_at_epoch + SLASH_APPEAL_WINDOW_EPOCHS, base_slash_per_validator,
//! reporter_bond_mojos = REPORTER_BOND_MOJOS, appeal_history = [] }` into
//! the manager's `PendingSlashBook` and registers the evidence hash in
//! the `processed` dedup map.
//!
//! Traces to: docs/resources/SPEC.md §3.8, §7.1, §7.3 steps 12–13, §22.3.
//!
//! # Ordering invariant
//!
//! Pending insert runs AFTER all economic side effects (bond lock
//! DSL-023, per-validator slashes DSL-022). Book insert failure
//! (`PendingBookFull`, DSL-027) surfaces only once capacity is
//! exceeded — here we test the happy path.
//!
//! # Test matrix (maps to DSL-024 Test Plan)
//!
//!   1. `test_dsl_024_pending_status_accepted_on_insert`
//!   2. `test_dsl_024_pending_window_epochs`
//!   3. `test_dsl_024_pending_per_validator_vec`
//!   4. `test_dsl_024_pending_reporter_bond_mojos`
//!   5. `test_dsl_024_pending_appeal_history_empty`
//!   6. `test_dsl_024_processed_map_updated`
//!   7. `test_dsl_024_result_pending_slash_hash`
//!   8. `test_dsl_024_pending_insert_deterministic`
//!   9. `test_dsl_024_book_len_grows_by_one`

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    PendingSlashStatus, ProposerSlashing, ProposerView, REPORTER_BOND_MOJOS, RewardPayout,
    SLASH_APPEAL_WINDOW_EPOCHS, SignedBlockHeader, SlashingEvidence, SlashingEvidencePayload,
    SlashingManager, ValidatorEntry, ValidatorView, block_signing_message,
};

/// Reward-payout stub.
struct NullReward;
impl RewardPayout for NullReward {
    fn pay(&mut self, _: Bytes32, _: u64) {}
}

/// Proposer stub — returns index 0.
const PROPOSER_IDX: u32 = 0;
struct FixedProposer;
impl ProposerView for FixedProposer {
    fn proposer_at_slot(&self, _: u64) -> Option<u32> {
        Some(PROPOSER_IDX)
    }
    fn current_slot(&self) -> u64 {
        0
    }
}

fn inject_proposer(map: &mut HashMap<u32, TestValidator>) {
    let sk = SecretKey::from_seed(&[0xFEu8; 32]);
    map.insert(
        PROPOSER_IDX,
        TestValidator {
            pk: sk.public_key(),
        },
    );
}

// ── Fixtures (simplified; no per-call recording needed) ────────────────

struct TestValidator {
    pk: PublicKey,
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

#[derive(Default)]
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

fn proposer_fixture(proposer_index: u32, reporter: u32, epoch: u64) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = sample_header(proposer_index, epoch, 0xA1);
    let header_b = sample_header(proposer_index, epoch, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(proposer_index, TestValidator { pk });

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
    inject_proposer(&mut map);
    (ev, MapView(map))
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-024 row 1: inserted record has `status == Accepted`.
#[test]
fn test_dsl_024_pending_status_accepted_on_insert() {
    let (ev, mut view) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev.hash();
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(3);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut escrow,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .expect("submit");

    let record = mgr.book().get(&hash).expect("inserted");
    assert_eq!(record.status, PendingSlashStatus::Accepted);
}

/// DSL-024 row 2: `submitted_at_epoch == current_epoch` and
/// `window_expires_at_epoch == current_epoch + SLASH_APPEAL_WINDOW_EPOCHS`.
#[test]
fn test_dsl_024_pending_window_epochs() {
    let current_epoch = 100u64;
    let (ev, mut view) = proposer_fixture(9, 42, current_epoch);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev.hash();
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(current_epoch);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut escrow,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .expect("submit");

    let record = mgr.book().get(&hash).unwrap();
    assert_eq!(record.submitted_at_epoch, current_epoch);
    assert_eq!(
        record.window_expires_at_epoch,
        current_epoch + SLASH_APPEAL_WINDOW_EPOCHS
    );
    // Sanity: default window is 8 per SPEC §2.6.
    assert_eq!(SLASH_APPEAL_WINDOW_EPOCHS, 8);
}

/// DSL-024 row 3: `base_slash_per_validator.len()` equals the number
/// of validators actually slashed (one for Proposer).
#[test]
fn test_dsl_024_pending_per_validator_vec() {
    let (ev, mut view) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev.hash();
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut escrow,
            &mut NullReward,
            &FixedProposer,
            &network_id(),
        )
        .expect("submit");
    let record = mgr.book().get(&hash).unwrap();
    assert_eq!(record.base_slash_per_validator.len(), 1);
    assert_eq!(record.base_slash_per_validator[0].validator_index, 9);
    // Record mirrors the returned result.
    assert_eq!(record.base_slash_per_validator, result.per_validator);
}

/// DSL-024 row 4: `reporter_bond_mojos == REPORTER_BOND_MOJOS`.
#[test]
fn test_dsl_024_pending_reporter_bond_mojos() {
    let (ev, mut view) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev.hash();
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(3);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut escrow,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .expect("submit");
    let record = mgr.book().get(&hash).unwrap();
    assert_eq!(record.reporter_bond_mojos, REPORTER_BOND_MOJOS);
}

/// DSL-024 row 5: `appeal_history.is_empty()` on admission.
#[test]
fn test_dsl_024_pending_appeal_history_empty() {
    let (ev, mut view) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev.hash();
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(3);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut escrow,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .expect("submit");
    let record = mgr.book().get(&hash).unwrap();
    assert!(record.appeal_history.is_empty());
}

/// DSL-024 row 6: `processed[hash] == current_epoch`. Queried via
/// `manager.is_processed(hash)` + `processed_epoch(hash)` accessors.
#[test]
fn test_dsl_024_processed_map_updated() {
    let (ev, mut view) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev.hash();
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(3);
    // Pre-submit: hash NOT processed.
    assert!(!mgr.is_processed(&hash));

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut escrow,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .expect("submit");

    assert!(mgr.is_processed(&hash));
    assert_eq!(mgr.processed_epoch(&hash), Some(3));
}

/// DSL-024 row 7: `SlashingResult::pending_slash_hash == evidence.hash()`.
#[test]
fn test_dsl_024_result_pending_slash_hash() {
    let (ev, mut view) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev.hash();
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut escrow,
            &mut NullReward,
            &FixedProposer,
            &network_id(),
        )
        .expect("submit");
    assert_eq!(result.pending_slash_hash, hash);
}

/// DSL-024 row 8: determinism across two managers — inserted
/// `PendingSlash` records byte-equal.
#[test]
fn test_dsl_024_pending_insert_deterministic() {
    let (ev1, mut view1) = proposer_fixture(9, 42, 3);
    let (ev2, mut view2) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let hash = ev1.hash();
    let mut e1 = AcceptingBondEscrow;
    let mut e2 = AcceptingBondEscrow;
    let mut m1 = SlashingManager::new(3);
    let mut m2 = SlashingManager::new(3);

    m1.submit_evidence(
        ev1,
        &mut view1,
        &balances,
        &mut e1,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .unwrap();
    m2.submit_evidence(
        ev2,
        &mut view2,
        &balances,
        &mut e2,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .unwrap();

    let a = m1.book().get(&hash).unwrap();
    let b = m2.book().get(&hash).unwrap();
    assert_eq!(a, b, "inserted records must be byte-equal");
}

/// DSL-024 row 9: `book.len()` grows by exactly 1 per successful
/// submit. Starts empty, ends at 1.
#[test]
fn test_dsl_024_book_len_grows_by_one() {
    let (ev, mut view) = proposer_fixture(9, 42, 3);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut escrow = AcceptingBondEscrow;
    let mut mgr = SlashingManager::new(3);
    assert_eq!(mgr.book().len(), 0);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut escrow,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .expect("submit");
    assert_eq!(mgr.book().len(), 1);
}
