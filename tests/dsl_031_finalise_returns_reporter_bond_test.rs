//! Requirement DSL-031: `finalise_expired_slashes` releases the
//! reporter bond in full via
//! `BondEscrow::release(reporter_idx, REPORTER_BOND_MOJOS,
//! BondTag::Reporter(evidence_hash))` and populates
//! `FinalisationResult::reporter_bond_returned == REPORTER_BOND_MOJOS`.
//!
//! Traces to: docs/resources/SPEC.md §2.6, §7.4 step 5, §12.3, §22.3.
//!
//! # Scope
//!
//! Release fires for both `Accepted → Finalised` and `ChallengeOpen
//! → Finalised` transitions (DSL-029). NOT for `Reverted` pendings —
//! those were forfeited on the sustained appeal (DSL-068) and are
//! skipped by DSL-033 entirely.
//!
//! # Test matrix (maps to DSL-031 Test Plan)
//!
//!   1. `test_dsl_031_release_called_on_finalise`
//!   2. `test_dsl_031_reporter_bond_returned_field`
//!   3. `test_dsl_031_release_amount_matches_lock`
//!   4. `test_dsl_031_release_tag_matches_evidence_hash`
//!   5. `test_dsl_031_release_single_call_idempotent`
//!   6. `test_dsl_031_release_multi_pendings`
//!   7. `test_dsl_031_release_principal_idx_matches_reporter`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    ProposerSlashing, ProposerView, REPORTER_BOND_MOJOS, RewardPayout, SLASH_APPEAL_WINDOW_EPOCHS,
    SignedBlockHeader, SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry,
    ValidatorView, block_signing_message,
};

// ── Bond mock recording lock + release args ────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum BondOp {
    Lock {
        principal: u32,
        amount: u64,
        tag: BondTag,
    },
    Release {
        principal: u32,
        amount: u64,
        tag: BondTag,
    },
}

#[derive(Default)]
struct RecordingBond {
    ops: RefCell<Vec<BondOp>>,
}

impl BondEscrow for RecordingBond {
    fn lock(&mut self, p: u32, amt: u64, tag: BondTag) -> Result<(), BondError> {
        self.ops.borrow_mut().push(BondOp::Lock {
            principal: p,
            amount: amt,
            tag,
        });
        Ok(())
    }
    fn release(&mut self, p: u32, amt: u64, tag: BondTag) -> Result<(), BondError> {
        self.ops.borrow_mut().push(BondOp::Release {
            principal: p,
            amount: amt,
            tag,
        });
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

const REPORTER_IDX: u32 = 42;

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
    map.insert(proposer_index, TestValidator { pk });
    let sk_prop = make_sk(0xFE);
    map.insert(
        0u32,
        TestValidator {
            pk: sk_prop.public_key(),
        },
    );

    let ev = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: REPORTER_IDX,
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

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-031 row 1: one `release(reporter_idx, REPORTER_BOND_MOJOS,
/// Reporter(hash))` call per finalised pending.
#[test]
fn test_dsl_031_release_called_on_finalise() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let (ev, view_new) = proposer_evidence(9, 0, 0x00);
    merge_view(&mut view, view_new);
    let hash = ev.hash();
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances(),
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let _ = mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );

    let releases: Vec<_> = bond
        .ops
        .borrow()
        .iter()
        .filter(|op| matches!(op, BondOp::Release { .. }))
        .cloned()
        .collect();
    assert_eq!(releases.len(), 1);
    assert_eq!(
        releases[0],
        BondOp::Release {
            principal: REPORTER_IDX,
            amount: REPORTER_BOND_MOJOS,
            tag: BondTag::Reporter(hash),
        },
    );
}

/// DSL-031 row 2: `FinalisationResult::reporter_bond_returned ==
/// REPORTER_BOND_MOJOS` on every finalised entry.
#[test]
fn test_dsl_031_reporter_bond_returned_field() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let (ev, view_new) = proposer_evidence(9, 0, 0x00);
    merge_view(&mut view, view_new);
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances(),
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let results = mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    assert_eq!(results[0].reporter_bond_returned, REPORTER_BOND_MOJOS);
}

/// DSL-031 row 3: locked amount at admission equals released amount
/// at finalisation — both `REPORTER_BOND_MOJOS`.
#[test]
fn test_dsl_031_release_amount_matches_lock() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let (ev, view_new) = proposer_evidence(9, 0, 0x00);
    merge_view(&mut view, view_new);
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances(),
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );

    let lock_amt = bond
        .ops
        .borrow()
        .iter()
        .find_map(|op| match op {
            BondOp::Lock { amount, .. } => Some(*amount),
            _ => None,
        })
        .unwrap();
    let release_amt = bond
        .ops
        .borrow()
        .iter()
        .find_map(|op| match op {
            BondOp::Release { amount, .. } => Some(*amount),
            _ => None,
        })
        .unwrap();
    assert_eq!(lock_amt, release_amt);
    assert_eq!(lock_amt, REPORTER_BOND_MOJOS);
}

/// DSL-031 row 4: release tag equals `BondTag::Reporter(evidence.hash())`.
#[test]
fn test_dsl_031_release_tag_matches_evidence_hash() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let (ev, view_new) = proposer_evidence(9, 0, 0x00);
    merge_view(&mut view, view_new);
    let hash = ev.hash();
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances(),
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );

    let release_tag = bond
        .ops
        .borrow()
        .iter()
        .find_map(|op| match op {
            BondOp::Release { tag, .. } => Some(*tag),
            _ => None,
        })
        .unwrap();
    assert_eq!(release_tag, BondTag::Reporter(hash));
}

/// DSL-031 row 5: second call to `finalise_expired_slashes` at the
/// same epoch does NOT emit another release — idempotent.
#[test]
fn test_dsl_031_release_single_call_idempotent() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let (ev, view_new) = proposer_evidence(9, 0, 0x00);
    merge_view(&mut view, view_new);
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances(),
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    let release_count_first = bond
        .ops
        .borrow()
        .iter()
        .filter(|op| matches!(op, BondOp::Release { .. }))
        .count();

    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );
    let release_count_second = bond
        .ops
        .borrow()
        .iter()
        .filter(|op| matches!(op, BondOp::Release { .. }))
        .count();

    assert_eq!(release_count_first, 1);
    assert_eq!(release_count_second, 1, "idempotent; no second release");
}

/// DSL-031 row 6: three distinct pendings → three release calls with
/// distinct hashes; each amount equals `REPORTER_BOND_MOJOS`.
#[test]
fn test_dsl_031_release_multi_pendings() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;

    let mut hashes = Vec::new();
    for (i, byte) in [0x01u8, 0x02, 0x03].iter().enumerate() {
        mgr.set_epoch(i as u64);
        let (ev, view_new) = proposer_evidence(9, i as u64, *byte);
        merge_view(&mut view, view_new);
        hashes.push(ev.hash());
        mgr.submit_evidence(
            ev,
            &mut view,
            &balances(),
            &mut bond,
            &mut reward,
            &FixedProposer,
            &network_id(),
        )
        .expect("admit");
    }

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 3); // past all windows
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );

    let releases: Vec<_> = bond
        .ops
        .borrow()
        .iter()
        .filter_map(|op| match op {
            BondOp::Release { tag, amount, .. } => Some((*tag, *amount)),
            _ => None,
        })
        .collect();
    assert_eq!(releases.len(), 3);
    for (tag, amt) in &releases {
        assert_eq!(*amt, REPORTER_BOND_MOJOS);
        assert!(matches!(tag, BondTag::Reporter(_)));
    }
    // All three hashes distinct.
    let tag_hashes: Vec<Bytes32> = releases
        .iter()
        .map(|(tag, _)| match tag {
            BondTag::Reporter(h) => *h,
            _ => unreachable!(),
        })
        .collect();
    for (i, h) in hashes.iter().enumerate() {
        assert!(tag_hashes.contains(h), "hash {i} released");
    }
}

/// DSL-031 row 7: release principal_idx equals the reporter index
/// from the envelope (not the proposer being slashed).
#[test]
fn test_dsl_031_release_principal_idx_matches_reporter() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    let (ev, view_new) = proposer_evidence(9, 0, 0x00);
    merge_view(&mut view, view_new);
    let mut bond = RecordingBond::default();
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances(),
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    mgr.finalise_expired_slashes(
        &mut view,
        &balances(),
        &mut bond,
        MIN_EFFECTIVE_BALANCE * 1000,
    );

    let release_principal = bond
        .ops
        .borrow()
        .iter()
        .find_map(|op| match op {
            BondOp::Release { principal, .. } => Some(*principal),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        release_principal, REPORTER_IDX,
        "release principal MUST be reporter, not proposer",
    );
}
