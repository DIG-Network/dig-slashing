//! Requirement DSL-032: `finalise_expired_slashes` schedules an exit
//! lock on every finalised validator via
//! `ValidatorEntry::schedule_exit(current_epoch + SLASH_LOCK_EPOCHS)`
//! and populates `FinalisationResult::exit_lock_until_epoch`.
//!
//! Traces to: docs/resources/SPEC.md §2.2, §7.4 step 4, §15.1, §22.3.
//!
//! # Role
//!
//! Locks slashed validators out of voluntary exit for 100 epochs so
//! they cannot escape correlation penalties or tail-end consequences
//! by withdrawing stake immediately after finalisation.
//!
//! # Test matrix (maps to DSL-032 Test Plan)
//!
//!   1. `test_dsl_032_schedule_exit_called_per_validator`
//!   2. `test_dsl_032_schedule_exit_attester_multi_validator`
//!   3. `test_dsl_032_exit_lock_epoch_arithmetic`
//!   4. `test_dsl_032_exit_lock_epochs_constant`
//!   5. `test_dsl_032_schedule_exit_missing_validator_tolerated`
//!   6. `test_dsl_032_exit_lock_deterministic`
//!   7. `test_dsl_032_result_field_matches_call_arg`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BondError, BondEscrow, BondTag, Checkpoint,
    EffectiveBalanceView, IndexedAttestation, MIN_EFFECTIVE_BALANCE, OffenseType, ProposerSlashing,
    ProposerView, RewardPayout, SLASH_APPEAL_WINDOW_EPOCHS, SLASH_LOCK_EPOCHS, SignedBlockHeader,
    SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry, ValidatorView,
    block_signing_message,
};

// ── Validator fixture recording schedule_exit calls ────────────────────

struct TestValidator {
    pk: PublicKey,
    exit_calls: RefCell<Vec<u64>>,
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
    fn schedule_exit(&mut self, exit_lock_until_epoch: u64) {
        self.exit_calls.borrow_mut().push(exit_lock_until_epoch);
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

struct AcceptingBond;
impl BondEscrow for AcceptingBond {
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

fn validator(pk: PublicKey) -> TestValidator {
    TestValidator {
        pk,
        exit_calls: RefCell::new(Vec::new()),
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

fn proposer_evidence(proposer_index: u32, epoch: u64) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = sample_header(proposer_index, epoch, 0xA1);
    let header_b = sample_header(proposer_index, epoch, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(proposer_index, validator(pk));
    let sk_prop = make_sk(0xFE);
    map.insert(0u32, validator(sk_prop.public_key()));

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

/// Build attester double-vote evidence with a specific set of slashable
/// indices (all present in both attestations).
fn attester_evidence(indices: Vec<u32>, epoch: u64) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let data_a = AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0xA1u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch,
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
            epoch,
            root: Bytes32::new([0x33u8; 32]),
        },
    };
    let sr_a = data_a.signing_root(&nid);
    let sr_b = data_b.signing_root(&nid);

    let mut sigs_a: Vec<Signature> = Vec::new();
    let mut sigs_b: Vec<Signature> = Vec::new();
    let mut map = HashMap::new();
    for idx in &indices {
        let sk = make_sk(*idx as u8);
        map.insert(*idx, validator(sk.public_key()));
        sigs_a.push(chia_bls::sign(&sk, sr_a.as_ref()));
        sigs_b.push(chia_bls::sign(&sk, sr_b.as_ref()));
    }
    // Block proposer for DSL-025 reward path.
    let sk_prop = make_sk(0xFE);
    map.insert(0u32, validator(sk_prop.public_key()));
    let agg_a = chia_bls::aggregate(&sigs_a);
    let agg_b = chia_bls::aggregate(&sigs_b);

    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 999,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch,
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
    (ev, MapView(map))
}

fn balances(indices: &[u32]) -> MapBalances {
    let mut m = HashMap::new();
    m.insert(0u32, MIN_EFFECTIVE_BALANCE);
    for idx in indices {
        m.insert(*idx, MIN_EFFECTIVE_BALANCE);
    }
    MapBalances(m)
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-032 row 1: Proposer slash → single `schedule_exit(current + 100)`
/// call on the accused proposer.
#[test]
fn test_dsl_032_schedule_exit_called_per_validator() {
    let mut mgr = SlashingManager::new(0);
    let (ev, mut view) = proposer_evidence(9, 0);
    let bal = balances(&[9]);
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &bal,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    let finalise_epoch = SLASH_APPEAL_WINDOW_EPOCHS + 1;
    mgr.set_epoch(finalise_epoch);
    let _ = mgr.finalise_expired_slashes(&mut view, &bal, &mut bond, MIN_EFFECTIVE_BALANCE * 1000);

    let calls = view.0.get(&9).unwrap().exit_calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0], finalise_epoch + SLASH_LOCK_EPOCHS);
}

/// DSL-032 row 2: AttesterSlashing with 3 slashable indices → 3
/// schedule_exit calls, all with the same exit_lock_until_epoch.
#[test]
fn test_dsl_032_schedule_exit_attester_multi_validator() {
    let indices = vec![3u32, 5, 7];
    let mut mgr = SlashingManager::new(0);
    let (ev, mut view) = attester_evidence(indices.clone(), 0);
    let bal = balances(&indices);
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &bal,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    let finalise_epoch = SLASH_APPEAL_WINDOW_EPOCHS + 1;
    mgr.set_epoch(finalise_epoch);
    mgr.finalise_expired_slashes(&mut view, &bal, &mut bond, MIN_EFFECTIVE_BALANCE * 1000);

    let expected_lock = finalise_epoch + SLASH_LOCK_EPOCHS;
    for idx in &indices {
        let calls = view.0.get(idx).unwrap().exit_calls.borrow();
        assert_eq!(calls.len(), 1, "validator {idx}: one call");
        assert_eq!(calls[0], expected_lock, "validator {idx}: same lock");
    }
}

/// DSL-032 row 3: finalise_epoch = 50 → exit_lock_until_epoch = 150;
/// result field matches.
#[test]
fn test_dsl_032_exit_lock_epoch_arithmetic() {
    let mut mgr = SlashingManager::new(0);
    let (ev, mut view) = proposer_evidence(9, 0);
    let bal = balances(&[9]);
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &bal,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(50);
    let results =
        mgr.finalise_expired_slashes(&mut view, &bal, &mut bond, MIN_EFFECTIVE_BALANCE * 1000);
    assert_eq!(results[0].exit_lock_until_epoch, 150);
    assert_eq!(view.0.get(&9).unwrap().exit_calls.borrow()[0], 150);
}

/// DSL-032 row 4: `SLASH_LOCK_EPOCHS == 100`.
#[test]
fn test_dsl_032_exit_lock_epochs_constant() {
    assert_eq!(SLASH_LOCK_EPOCHS, 100u64);
}

/// DSL-032 row 5: validator removed from view between admission +
/// finalisation → schedule_exit skipped silently; no panic.
#[test]
fn test_dsl_032_schedule_exit_missing_validator_tolerated() {
    let mut mgr = SlashingManager::new(0);
    let (ev, mut view) = proposer_evidence(9, 0);
    let bal = balances(&[9]);
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &bal,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    // Remove the slashed validator from the view before finalise.
    view.0.remove(&9);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    // Must not panic; finalise still emits a FinalisationResult.
    let results =
        mgr.finalise_expired_slashes(&mut view, &bal, &mut bond, MIN_EFFECTIVE_BALANCE * 1000);
    assert_eq!(results.len(), 1);
    // Proposer at idx 0 unaffected — not in slashable set.
    assert!(view.0.get(&0).unwrap().exit_calls.borrow().is_empty());
}

/// DSL-032 row 6: determinism — two managers, identical fixture, same
/// exit_calls sequence.
#[test]
fn test_dsl_032_exit_lock_deterministic() {
    let build = || {
        let mut mgr = SlashingManager::new(0);
        let (ev, mut view) = proposer_evidence(9, 0);
        let bal = balances(&[9]);
        let mut bond = AcceptingBond;
        let mut reward = NullReward;
        mgr.submit_evidence(
            ev,
            &mut view,
            &bal,
            &mut bond,
            &mut reward,
            &FixedProposer,
            &network_id(),
        )
        .expect("admit");
        mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
        mgr.finalise_expired_slashes(&mut view, &bal, &mut bond, MIN_EFFECTIVE_BALANCE * 1000);
        view.0.get(&9).unwrap().exit_calls.borrow().clone()
    };
    assert_eq!(build(), build());
}

/// DSL-032 row 7: `FinalisationResult::exit_lock_until_epoch` equals
/// the argument passed to `schedule_exit`.
#[test]
fn test_dsl_032_result_field_matches_call_arg() {
    let mut mgr = SlashingManager::new(0);
    let (ev, mut view) = proposer_evidence(9, 0);
    let bal = balances(&[9]);
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &bal,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(77);
    let results =
        mgr.finalise_expired_slashes(&mut view, &bal, &mut bond, MIN_EFFECTIVE_BALANCE * 1000);
    let call_arg = view.0.get(&9).unwrap().exit_calls.borrow()[0];
    assert_eq!(results[0].exit_lock_until_epoch, call_arg);
}
