//! Requirement DSL-033: `finalise_expired_slashes` skips pendings
//! whose status is `Reverted` or `Finalised`. NO validator mutation,
//! NO bond release, NO exit lock, NO `FinalisationResult` emission
//! for skipped entries. Retains pending in book.
//!
//! Traces to: docs/resources/SPEC.md §3.8, §7.4 step 2, §22.3.
//!
//! # Role
//!
//! Defensive idempotency + correctness guard:
//!
//!   - `Reverted` — sustained appeal (DSL-068..070) already credited
//!     the base slash back and forfeited the reporter bond. Re-running
//!     the finalise side-effects would double-apply.
//!   - `Finalised` — a previous call already handled this entry;
//!     `expired_by` still returns it so idempotency depends on the
//!     skip.
//!
//! # Test matrix (maps to DSL-033 Test Plan)
//!
//!   1. `test_dsl_033_reverted_pending_skipped`
//!   2. `test_dsl_033_reverted_no_validator_mutation`
//!   3. `test_dsl_033_reverted_no_bond_release`
//!   4. `test_dsl_033_reverted_no_exit_lock`
//!   5. `test_dsl_033_finalised_pending_skipped_idempotent`
//!   6. `test_dsl_033_accepted_alongside_reverted_mixed_batch`
//!   7. `test_dsl_033_reverted_pending_retained_in_book`
//!   8. `test_dsl_033_skip_determinism`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    PendingSlashStatus, ProposerSlashing, ProposerView, RewardPayout, SLASH_APPEAL_WINDOW_EPOCHS,
    SignedBlockHeader, SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry,
    ValidatorView, block_signing_message,
};

// ── Recording fixtures ────────────────────────────────────────────────

#[derive(Default)]
struct RecordingBond {
    release_calls: RefCell<u32>,
}
impl BondEscrow for RecordingBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        *self.release_calls.borrow_mut() += 1;
        Ok(())
    }
    fn forfeit(&mut self, _: u32, _: u64, _: BondTag) -> Result<u64, BondError> {
        Ok(0)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

struct NullReward;
impl RewardPayout for NullReward {
    fn pay(&mut self, _: Bytes32, _: u64) {}
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
    exit_calls: RefCell<u32>,
}

impl TestValidator {
    fn new(pk: PublicKey) -> Self {
        Self {
            pk,
            slash_calls: RefCell::new(0),
            exit_calls: RefCell::new(0),
        }
    }
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
    fn schedule_exit(&mut self, _: u64) {
        *self.exit_calls.borrow_mut() += 1;
    }
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
    map.insert(proposer_index, TestValidator::new(pk));
    let sk_prop = make_sk(0xFE);
    map.insert(0u32, TestValidator::new(sk_prop.public_key()));

    let ev = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: 42,
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

fn merge_view(dst: &mut MapView, src: MapView) {
    for (k, v) in src.0 {
        dst.0.entry(k).or_insert(v);
    }
}

fn balances() -> MapBalances {
    MapBalances(HashMap::from([
        (9u32, MIN_EFFECTIVE_BALANCE),
        (0u32, MIN_EFFECTIVE_BALANCE),
    ]))
}

/// Admit evidence + advance mgr to expiry; return evidence hash.
fn admit_and_expire(mgr: &mut SlashingManager, view: &mut MapView, variant_byte: u8) -> Bytes32 {
    let (ev, view_new) = proposer_evidence(9, mgr.current_epoch(), variant_byte);
    merge_view(view, view_new);
    let hash = ev.hash();
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        view,
        &balances(),
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");
    hash
}

/// Overwrite the pending's status directly via `book_mut()`.
fn force_status(mgr: &mut SlashingManager, hash: Bytes32, status: PendingSlashStatus) {
    let pending = mgr.book_mut().get_mut(&hash).expect("pending present");
    pending.status = status;
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-033 row 1: Reverted status → no `FinalisationResult`.
#[test]
fn test_dsl_033_reverted_pending_skipped() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let hash = admit_and_expire(&mut mgr, &mut view, 0x00);
    force_status(
        &mut mgr,
        hash,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0x99u8; 32]),
            reverted_at_epoch: 3,
        },
    );

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let mut bond = RecordingBond::default();
    let results = mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    assert!(results.is_empty(), "Reverted skipped → empty result");
}

/// DSL-033 row 2: no validator mutation for Reverted.
#[test]
fn test_dsl_033_reverted_no_validator_mutation() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let hash = admit_and_expire(&mut mgr, &mut view, 0x00);
    // slash_calls already = 1 from the base-slash at admission.
    let base_slash_count = *view.0.get(&9).unwrap().slash_calls.borrow();
    force_status(
        &mut mgr,
        hash,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0x99u8; 32]),
            reverted_at_epoch: 3,
        },
    );

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let mut bond = RecordingBond::default();
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );

    // No NEW slash_absolute calls after the Reverted skip.
    assert_eq!(
        *view.0.get(&9).unwrap().slash_calls.borrow(),
        base_slash_count,
    );
}

/// DSL-033 row 3: no bond.release for Reverted.
#[test]
fn test_dsl_033_reverted_no_bond_release() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let hash = admit_and_expire(&mut mgr, &mut view, 0x00);
    force_status(
        &mut mgr,
        hash,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0x99u8; 32]),
            reverted_at_epoch: 3,
        },
    );

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let mut bond = RecordingBond::default();
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    assert_eq!(*bond.release_calls.borrow(), 0, "no release for Reverted");
}

/// DSL-033 row 4: no schedule_exit for Reverted validators.
#[test]
fn test_dsl_033_reverted_no_exit_lock() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let hash = admit_and_expire(&mut mgr, &mut view, 0x00);
    force_status(
        &mut mgr,
        hash,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0x99u8; 32]),
            reverted_at_epoch: 3,
        },
    );

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let mut bond = RecordingBond::default();
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    assert_eq!(
        *view.0.get(&9).unwrap().exit_calls.borrow(),
        0,
        "no schedule_exit for Reverted",
    );
}

/// DSL-033 row 5: second finalise call is idempotent — Finalised
/// entries skipped.
#[test]
fn test_dsl_033_finalised_pending_skipped_idempotent() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    admit_and_expire(&mut mgr, &mut view, 0x00);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let mut bond = RecordingBond::default();
    let first = mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    assert_eq!(first.len(), 1);
    let release_after_first = *bond.release_calls.borrow();

    let second = mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    assert!(second.is_empty(), "idempotent: second call skips");
    assert_eq!(
        *bond.release_calls.borrow(),
        release_after_first,
        "idempotent: no additional releases",
    );
}

/// DSL-033 row 6: mixed batch — one Accepted, one Reverted. Result
/// has exactly one entry (the Accepted one).
#[test]
fn test_dsl_033_accepted_alongside_reverted_mixed_batch() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    mgr.set_epoch(0);
    let hash_accepted = admit_and_expire(&mut mgr, &mut view, 0x00);
    mgr.set_epoch(1);
    let hash_reverted = admit_and_expire(&mut mgr, &mut view, 0x10);
    force_status(
        &mut mgr,
        hash_reverted,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0x99u8; 32]),
            reverted_at_epoch: 5,
        },
    );

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 2);
    let mut bond = RecordingBond::default();
    let results = mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    assert_eq!(results.len(), 1, "only Accepted finalised");
    assert_eq!(results[0].evidence_hash, hash_accepted);
}

/// DSL-033 row 7: skipped Reverted pending remains in the book.
#[test]
fn test_dsl_033_reverted_pending_retained_in_book() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let hash = admit_and_expire(&mut mgr, &mut view, 0x00);
    let rev_status = PendingSlashStatus::Reverted {
        winning_appeal_hash: Bytes32::new([0x99u8; 32]),
        reverted_at_epoch: 3,
    };
    force_status(&mut mgr, hash, rev_status);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let mut bond = RecordingBond::default();
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );

    let pending = mgr.book().get(&hash).expect("still present");
    assert_eq!(pending.status, rev_status, "status unchanged");
}

/// DSL-033 row 8: determinism — two managers, identical setup +
/// forced Reverted status → identical (empty) result vecs.
#[test]
fn test_dsl_033_skip_determinism() {
    let build = || {
        let mut mgr = SlashingManager::new(0);
        let mut view = MapView(HashMap::new());
        let hash = admit_and_expire(&mut mgr, &mut view, 0x00);
        force_status(
            &mut mgr,
            hash,
            PendingSlashStatus::Reverted {
                winning_appeal_hash: Bytes32::new([0x99u8; 32]),
                reverted_at_epoch: 3,
            },
        );
        mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
        let mut bond = RecordingBond::default();
        mgr.finalise_expired_slashes(
            &mut view,
            &balances(),
            &mut bond,
            MIN_EFFECTIVE_BALANCE * 1000,
        )
    };
    assert_eq!(build(), build());
}
