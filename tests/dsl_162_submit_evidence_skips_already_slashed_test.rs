//! Requirement DSL-162: `submit_evidence` skips validator indices that report `is_slashed() == true`.
//!
//! Traces to: docs/resources/SPEC.md §7.3 step 5a.
//!
//! # Role
//!
//! Within the per-validator slash loop, every index returned by `VerifiedEvidence::slashable_validator_indices` is queried via `ValidatorEntry::is_slashed()`. Flagged indices are uniformly skipped:
//!
//!   - NO `slash_absolute` debit.
//!   - NO `PerValidatorSlash` entry in `SlashingResult::per_validator`.
//!   - NO `slashed_in_window` record inserted (which would pollute the DSL-030 cohort_sum with a validator that was already accounted for at its original admission).
//!
//! Defensive — covers the gap between `verify_evidence` (which for proposer evidence checks slashed-status at the reporter-isn't-accused gate but does NOT stop re-slashing of already-slashed proposers) and AttesterSlashing (whose intersection may include mixed already-slashed + still-active indices after a prior admission).
//!
//! Even when ALL indices are skipped, evidence is still marked in `processed` so DSL-026 dedup fires on a retry — otherwise a griefer could resubmit the same hash repeatedly.
//!
//! # Test matrix (maps to DSL-162 Test Plan)
//!
//!   1. `test_dsl_162_single_already_slashed_skipped` — AttesterSlashing with one intersection index whose `is_slashed()` returns true. Result `per_validator` empty; zero `slash_absolute` calls; no `slashed_in_window` row. NOTE: Proposer + InvalidBlock evidence is rejected at verify (they carry an explicit already-slashed precondition at src/evidence/verify.rs:273/504), so the per-validator skip-loop is only observable on AttesterSlashing — verify passes, then the loop filters.
//!   2. `test_dsl_162_partial_intersection_slashed` — AttesterSlashing with 5 intersection indices, 2 of them already slashed. Only 3 entries in `per_validator`; exactly 3 `slash_absolute` calls on the live indices; zero on the flagged ones.
//!   3. `test_dsl_162_all_indices_slashed` — every intersection index already slashed. `per_validator` empty; evidence nonetheless recorded in `processed` so a second submit returns `AlreadySlashed` rather than re-running the pipeline.
//!   4. `test_dsl_162_no_window_insert_for_skipped` — after a mixed-admission, `is_slashed_in_window(current_epoch, idx)` returns true for the 3 live indices and false for the 2 skipped — pins the correlation-window hygiene invariant.

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BondError, BondEscrow, BondTag, Checkpoint,
    EffectiveBalanceView, IndexedAttestation, MIN_EFFECTIVE_BALANCE, OffenseType, ProposerView,
    RewardPayout, SlashingError, SlashingEvidence, SlashingEvidencePayload, SlashingManager,
    ValidatorEntry, ValidatorView,
};

// ── mocks ───────────────────────────────────────────────────────

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

/// Validator with configurable `is_slashed()` return + per-call
/// recorder on `slash_absolute`. Lets each test assert the skip
/// branch genuinely inhibited debits (zero calls on skipped indices).
struct RecordingValidator {
    pk: PublicKey,
    is_slashed_flag: bool,
    slash_calls: RefCell<Vec<(u64, u64)>>,
}
impl RecordingValidator {
    fn new(pk: PublicKey) -> Self {
        Self {
            pk,
            is_slashed_flag: false,
            slash_calls: RefCell::new(Vec::new()),
        }
    }
}

impl ValidatorEntry for RecordingValidator {
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
        self.is_slashed_flag
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

struct MapView(HashMap<u32, RecordingValidator>);
impl ValidatorView for MapView {
    fn get(&self, i: u32) -> Option<&dyn ValidatorEntry> {
        self.0.get(&i).map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, i: u32) -> Option<&mut dyn ValidatorEntry> {
        self.0.get_mut(&i).map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

struct MapBalances(HashMap<u32, u64>);
impl EffectiveBalanceView for MapBalances {
    fn get(&self, i: u32) -> u64 {
        self.0.get(&i).copied().unwrap_or(0)
    }
    fn total_active(&self) -> u64 {
        self.0.values().sum()
    }
}

// ── fixtures ───────────────────────────────────────────────────

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_sk(seed: u8) -> SecretKey {
    SecretKey::from_seed(&[seed; 32])
}

fn inject_proposer(map: &mut HashMap<u32, RecordingValidator>) {
    let sk = SecretKey::from_seed(&[0xFEu8; 32]);
    map.insert(PROPOSER_IDX, RecordingValidator::new(sk.public_key()));
}

/// Attester double-vote envelope — real aggregate BLS signatures
/// over both data sides. All `indices` get registered in the view
/// with per-index signing keys; caller flips `is_slashed_flag` as
/// needed to simulate already-slashed validators.
fn attester_double_evidence(
    reporter: u32,
    indices: Vec<u32>,
    epoch: u64,
) -> (SlashingEvidence, MapView) {
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
    let mut map: HashMap<u32, RecordingValidator> = HashMap::new();
    for idx in &indices {
        // Use idx+0x40 so signing-key seeds don't collide with PROPOSER_IDX (0xFE seed) or reporter seeds.
        let sk = make_sk(*idx as u8 ^ 0x40);
        let pk = sk.public_key();
        map.insert(*idx, RecordingValidator::new(pk));
        sigs_a.push(chia_bls::sign(&sk, sr_a.as_ref()));
        sigs_b.push(chia_bls::sign(&sk, sr_b.as_ref()));
    }
    let agg_a = chia_bls::aggregate(&sigs_a);
    let agg_b = chia_bls::aggregate(&sigs_b);
    inject_proposer(&mut map);

    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: reporter,
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

// ── tests ──────────────────────────────────────────────────────

/// DSL-162 row 1: AttesterSlashing with a single already-slashed
/// intersection index. verify passes (attester path does NOT gate
/// on is_slashed), then submit_evidence's per-validator loop skips
/// the flagged index. Observable: empty `per_validator`, zero
/// `slash_absolute` calls, empty `slashed_in_window` row.
///
/// Uses Attester (not Proposer) because verify_proposer_slashing
/// rejects already-slashed proposers at verify_evidence BEFORE the
/// loop runs (src/evidence/verify.rs:273). The DSL-162 skip is
/// therefore only observable on attester evidence where the verify
/// path is silent on per-index slashed-status.
#[test]
fn test_dsl_162_single_already_slashed_skipped() {
    // AttesterDoubleVote requires at least 1 intersection idx; a
    // single-index intersection is valid — the verify path needs
    // the two attestations to disagree on data (distinct block
    // roots) which our fixture does by construction.
    let (ev, mut view) = attester_double_evidence(99, vec![9], 3);
    view.0.get_mut(&9).unwrap().is_slashed_flag = true;

    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut AcceptingBond,
            &mut NullReward,
            &FixedProposer,
            &network_id(),
        )
        .expect("attester evidence admits — skip is per-validator");

    assert!(
        result.per_validator.is_empty(),
        "per_validator vec omits already-slashed indices",
    );

    let v = view.0.get(&9).unwrap();
    assert_eq!(
        v.slash_calls.borrow().len(),
        0,
        "no slash_absolute call on already-slashed index",
    );
    assert!(
        !mgr.is_slashed_in_window(3, 9),
        "no slashed_in_window row inserted for skipped index",
    );
}

/// DSL-162 row 2: AttesterSlashing with 5 intersection indices, 2 of
/// which are already slashed. Expect exactly 3 per_validator entries
/// + 3 total slash_absolute calls across the view (one per live idx).
#[test]
fn test_dsl_162_partial_intersection_slashed() {
    let indices = vec![3u32, 5, 7, 11, 13];
    let (ev, mut view) = attester_double_evidence(99, indices.clone(), 3);

    // Flip validators 5 + 11 to already-slashed.
    view.0.get_mut(&5).unwrap().is_slashed_flag = true;
    view.0.get_mut(&11).unwrap().is_slashed_flag = true;

    let mut balances_map = HashMap::new();
    for idx in &indices {
        balances_map.insert(*idx, MIN_EFFECTIVE_BALANCE);
    }
    let balances = MapBalances(balances_map);
    let mut mgr = SlashingManager::new(3);

    let result = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut AcceptingBond,
            &mut NullReward,
            &FixedProposer,
            &network_id(),
        )
        .expect("attester slash admits");

    // Only 3 entries in the result vec.
    assert_eq!(
        result.per_validator.len(),
        3,
        "3 live indices → 3 per_validator entries (5 + 11 skipped)",
    );
    let result_indices: Vec<u32> = result
        .per_validator
        .iter()
        .map(|p| p.validator_index)
        .collect();
    assert!(result_indices.contains(&3));
    assert!(result_indices.contains(&7));
    assert!(result_indices.contains(&13));
    assert!(!result_indices.contains(&5));
    assert!(!result_indices.contains(&11));

    // Per-validator slash_absolute call counts.
    for live_idx in [3u32, 7, 13] {
        let v = view.0.get(&live_idx).unwrap();
        assert_eq!(
            v.slash_calls.borrow().len(),
            1,
            "idx={live_idx} live → exactly one slash_absolute call",
        );
    }
    for skipped in [5u32, 11] {
        let v = view.0.get(&skipped).unwrap();
        assert_eq!(
            v.slash_calls.borrow().len(),
            0,
            "idx={skipped} already-slashed → zero slash_absolute calls",
        );
    }
}

/// DSL-162 row 3: every index in the intersection is already slashed.
/// `per_validator` empty; evidence still recorded in `processed` so
/// retry surfaces AlreadySlashed (not re-runs the pipeline).
///
/// This is the grief-resistance invariant: an adversary cannot
/// poison admission by resubmitting all-already-slashed evidence
/// repeatedly — the first submit caches the hash in `processed`.
#[test]
fn test_dsl_162_all_indices_slashed() {
    let indices = vec![3u32, 5, 7];
    let (ev, mut view) = attester_double_evidence(99, indices.clone(), 3);

    // Flip every intersection index to already-slashed.
    for idx in &indices {
        view.0.get_mut(idx).unwrap().is_slashed_flag = true;
    }

    let mut balances_map = HashMap::new();
    for idx in &indices {
        balances_map.insert(*idx, MIN_EFFECTIVE_BALANCE);
    }
    let balances = MapBalances(balances_map);
    let mut mgr = SlashingManager::new(3);

    let evidence_hash = ev.hash();
    let result = mgr
        .submit_evidence(
            ev.clone(),
            &mut view,
            &balances,
            &mut AcceptingBond,
            &mut NullReward,
            &FixedProposer,
            &network_id(),
        )
        .expect("evidence still admits even when every index is skipped");

    assert!(
        result.per_validator.is_empty(),
        "all-skipped path yields empty per_validator vec",
    );
    assert!(
        mgr.is_processed(&evidence_hash),
        "evidence still recorded in processed — dedup map poisoning resistant",
    );

    // Retry with the same envelope surfaces AlreadySlashed BEFORE
    // re-running verify / slash loops.
    let retry = mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut AcceptingBond,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    );
    assert!(
        matches!(retry, Err(SlashingError::AlreadySlashed)),
        "retry hits DSL-026 dedup, not a fresh run",
    );
}

/// DSL-162 row 4: `slashed_in_window` carries ONLY live indices.
///
/// Correlation-window hygiene: DSL-030 uses `slashed_in_window` to
/// compute `cohort_sum` at finalisation. A skipped index must NOT
/// pollute this register — it was already accounted for at its
/// original admission epoch.
#[test]
fn test_dsl_162_no_window_insert_for_skipped() {
    let indices = vec![3u32, 5, 7, 11, 13];
    let (ev, mut view) = attester_double_evidence(99, indices.clone(), 3);

    view.0.get_mut(&5).unwrap().is_slashed_flag = true;
    view.0.get_mut(&11).unwrap().is_slashed_flag = true;

    let mut balances_map = HashMap::new();
    for idx in &indices {
        balances_map.insert(*idx, MIN_EFFECTIVE_BALANCE);
    }
    let balances = MapBalances(balances_map);
    let mut mgr = SlashingManager::new(3);

    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut AcceptingBond,
        &mut NullReward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    for live in [3u32, 7, 13] {
        assert!(
            mgr.is_slashed_in_window(3, live),
            "live idx={live} must have slashed_in_window row",
        );
    }
    for skipped in [5u32, 11] {
        assert!(
            !mgr.is_slashed_in_window(3, skipped),
            "skipped idx={skipped} must NOT have slashed_in_window row",
        );
    }
}
