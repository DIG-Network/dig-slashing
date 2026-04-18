//! Requirement DSL-030: `finalise_expired_slashes` applies the
//! correlation penalty per-validator using the Ethereum-parity
//! proportional-slashing formula:
//!
//!   correlation_penalty = eff_bal * min(cohort_sum * 3, total_active)
//!                         / total_active
//!
//! Traces to: docs/resources/SPEC.md §2.2, §4, §7.4 steps 3–4, §22.3.
//!
//! # Saturation
//!
//! When `cohort_sum * 3 >= total_active`, `min(..)` clamps to
//! `total_active` → penalty equals `eff_bal` (full-balance debit).
//! Coordinated-attack deterrent.
//!
//! # Cohort window
//!
//! `cohort_sum` aggregates every `eff_bal_at_slash` recorded by
//! `submit_evidence` in the `[current - CORRELATION_WINDOW_EPOCHS,
//! current]` range. Pre-window admissions do NOT contribute.
//!
//! # Test matrix (maps to DSL-030 Test Plan)
//!
//!   1. `test_dsl_030_isolated_slash_small_penalty`
//!   2. `test_dsl_030_saturates_at_eff_bal`
//!   3. `test_dsl_030_window_bounds`
//!   4. `test_dsl_030_multiplier_is_3`
//!   5. `test_dsl_030_penalty_recorded_in_result`
//!   6. `test_dsl_030_zero_cohort_zero_penalty`
//!   7. `test_dsl_030_zero_total_active_zero_penalty`
//!   8. `test_dsl_030_penalty_deterministic`

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, OffenseType,
    ProposerSlashing, ProposerView, RewardPayout, SLASH_APPEAL_WINDOW_EPOCHS, SignedBlockHeader,
    SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry, ValidatorView,
    block_signing_message,
};

// ── Mocks (slash-absolute recording) ───────────────────────────────────

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

struct TestValidator {
    pk: PublicKey,
    /// Every `slash_absolute(amount, epoch)` call recorded.
    slash_calls: RefCell<Vec<(u64, u64)>>,
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
            slash_calls: RefCell::new(Vec::new()),
        },
    );
    let sk_prop = make_sk(0xFE);
    map.insert(
        0u32,
        TestValidator {
            pk: sk_prop.public_key(),
            slash_calls: RefCell::new(Vec::new()),
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

fn merge_view(dst: &mut MapView, src: MapView) {
    for (k, v) in src.0 {
        dst.0.entry(k).or_insert(v);
    }
}

fn admit(
    mgr: &mut SlashingManager,
    view: &mut MapView,
    admit_epoch: u64,
    variant_byte: u8,
) -> Bytes32 {
    mgr.set_epoch(admit_epoch);
    let (ev, view_new) = proposer_evidence(9, 42, admit_epoch, variant_byte);
    merge_view(view, view_new);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    let hash = ev.hash();
    mgr.submit_evidence(
        ev,
        view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");
    hash
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-030 row 1: isolated slash, `cohort_sum == eff_bal`, large
/// `total_active` → tiny penalty ≈ `3 * eff_bal^2 / total`.
#[test]
fn test_dsl_030_isolated_slash_small_penalty() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    admit(&mut mgr, &mut view, 0, 0x00);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let total_active = MIN_EFFECTIVE_BALANCE * 1000;
    let results = mgr.finalise_expired_slashes(&mut view, &balances, total_active);

    // cohort_sum = MIN_EFFECTIVE_BALANCE (one slashed)
    // scaled = MIN_EFFECTIVE_BALANCE * 3
    // capped = min(MIN_EFFECTIVE_BALANCE * 3, total) = 3 * MIN_EFFECTIVE_BALANCE
    // penalty = eff_bal * 3 * eff_bal / total. u128 math required —
    // intermediate product exceeds u64::MAX at these magnitudes.
    let eff_bal = u128::from(MIN_EFFECTIVE_BALANCE);
    let expected = ((eff_bal * 3 * eff_bal) / u128::from(total_active)) as u64;
    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].per_validator_correlation_penalty,
        vec![(9, expected)]
    );
}

/// DSL-030 row 2: `cohort_sum * 3 >= total` → penalty saturates at
/// `eff_bal` (full-balance debit).
#[test]
fn test_dsl_030_saturates_at_eff_bal() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    admit(&mut mgr, &mut view, 0, 0x00);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    // Configure total_active so `cohort_sum * 3 > total`: pick
    // total_active = MIN_EFFECTIVE_BALANCE (single slashed = whole chain).
    let total_active = MIN_EFFECTIVE_BALANCE;
    let results = mgr.finalise_expired_slashes(&mut view, &balances, total_active);

    assert_eq!(
        results[0].per_validator_correlation_penalty,
        vec![(9, MIN_EFFECTIVE_BALANCE)]
    );
}

/// DSL-030 row 3: pre-window slash does NOT contribute to cohort_sum.
/// Two admissions: first OUTSIDE the correlation window (admitted
/// at epoch 0 but measured at epoch > CORRELATION_WINDOW_EPOCHS + ...);
/// DIG's CORRELATION_WINDOW_EPOCHS is 36. So admit at epoch 0 and
/// finalise at epoch 100; cohort from earliest admission inside window.
#[test]
fn test_dsl_030_window_bounds() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());

    // Out-of-window admission at epoch 0.
    admit(&mut mgr, &mut view, 0, 0x00);
    // In-window admission at epoch 80 (window covers 100-36=64..100).
    admit(&mut mgr, &mut view, 80, 0x10);

    let finalise_epoch = 100;
    mgr.set_epoch(finalise_epoch);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let total_active = MIN_EFFECTIVE_BALANCE * 1000;
    let results = mgr.finalise_expired_slashes(&mut view, &balances, total_active);

    // Both evidences expired (window ends at admit_epoch + 8).
    // Epoch 0 admission: finalised at 100; cohort_sum for its
    // finalisation = only in-window slashes = the epoch-80 admission
    // (eff_bal MIN_EFFECTIVE_BALANCE) — epoch 0 is outside the
    // window. Epoch-80 admission finalises at 100; cohort_sum sees
    // both (0 + 80 after window_lo=64) — NO, only epoch-80 is in
    // [64, 100]. So both finalisations see cohort_sum =
    // MIN_EFFECTIVE_BALANCE.
    assert_eq!(results.len(), 2);
    let eff_bal = u128::from(MIN_EFFECTIVE_BALANCE);
    let expected_penalty = ((eff_bal * 3 * eff_bal) / u128::from(total_active)) as u64;
    for r in &results {
        assert_eq!(
            r.per_validator_correlation_penalty,
            vec![(9, expected_penalty)],
        );
    }
}

/// DSL-030 row 4: multiplier == 3 — pick `cohort_sum = total/6` so
/// `cohort*3 = total/2` and penalty == `eff_bal / 2`.
#[test]
fn test_dsl_030_multiplier_is_3() {
    // Engineer cohort_sum = total / 6 by setting eff_bal_at_slash to
    // total/6 and admitting one evidence. Then penalty = eff_bal * 1/2.
    let eff_bal = 600u64;
    let total_active = eff_bal * 6; // 3600
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());

    // Admit uses EffectiveBalanceView::get(9) = MIN_EFFECTIVE_BALANCE
    // by default. To engineer eff_bal=600, override the helper's
    // balances at admission. Can't via admit() helper — inline.
    mgr.set_epoch(0);
    let (ev, view_new) = proposer_evidence(9, 42, 0, 0x00);
    merge_view(&mut view, view_new);
    let balances = MapBalances(HashMap::from([(9u32, eff_bal)]));
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let results = mgr.finalise_expired_slashes(&mut view, &balances, total_active);

    // cohort_sum = 600; scaled = 1800; capped = min(1800, 3600) = 1800;
    // penalty = 600 * 1800 / 3600 = 300 = eff_bal / 2.
    assert_eq!(results[0].per_validator_correlation_penalty, vec![(9, 300)]);
}

/// DSL-030 row 5: penalty recorded in `FinalisationResult::per_validator_correlation_penalty`
/// in pending order; `slash_absolute` called with the same penalty.
#[test]
fn test_dsl_030_penalty_recorded_in_result() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    admit(&mut mgr, &mut view, 0, 0x00);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let total_active = MIN_EFFECTIVE_BALANCE * 1000;
    let results = mgr.finalise_expired_slashes(&mut view, &balances, total_active);

    assert_eq!(results[0].per_validator_correlation_penalty.len(), 1);
    let (idx, penalty) = results[0].per_validator_correlation_penalty[0];
    assert_eq!(idx, 9);

    // Validator's `slash_absolute` called TWICE: once at admission
    // (base slash) and once at finalisation (correlation penalty).
    let calls = view.0.get(&9).unwrap().slash_calls.borrow();
    assert_eq!(calls.len(), 2, "base slash + correlation penalty");
    // Second call at finalisation epoch with the correlation penalty
    // amount.
    assert_eq!(calls[1].0, penalty);
    assert_eq!(calls[1].1, SLASH_APPEAL_WINDOW_EPOCHS + 1);
}

/// DSL-030 row 6: zero cohort → zero penalty. Construct by forcing
/// `eff_bal_at_slash = 0` via tiny balances at admission.
#[test]
fn test_dsl_030_zero_cohort_zero_penalty() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());

    mgr.set_epoch(0);
    let (ev, view_new) = proposer_evidence(9, 42, 0, 0x00);
    merge_view(&mut view, view_new);
    let balances_zero = MapBalances(HashMap::from([(9u32, 0u64)]));
    let mut bond = AcceptingBond;
    let mut reward = NullReward;
    mgr.submit_evidence(
        ev,
        &mut view,
        &balances_zero,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    )
    .expect("admit");

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let results = mgr.finalise_expired_slashes(&mut view, &balances_zero, 1_000_000);
    assert_eq!(results[0].per_validator_correlation_penalty, vec![(9, 0)]);
}

/// DSL-030 row 7: `total_active_balance == 0` → zero penalty
/// (defensive; division-by-zero guard).
#[test]
fn test_dsl_030_zero_total_active_zero_penalty() {
    let mut mgr = SlashingManager::new(0);
    let mut view = MapView(HashMap::new());
    admit(&mut mgr, &mut view, 0, 0x00);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let results = mgr.finalise_expired_slashes(&mut view, &balances, 0);
    assert_eq!(results[0].per_validator_correlation_penalty, vec![(9, 0)]);
}

/// DSL-030 row 8: identical inputs → byte-identical
/// `FinalisationResult` across two independent managers.
#[test]
fn test_dsl_030_penalty_deterministic() {
    let build = || {
        let mut mgr = SlashingManager::new(0);
        let mut view = MapView(HashMap::new());
        admit(&mut mgr, &mut view, 0, 0x00);
        mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
        let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
        mgr.finalise_expired_slashes(&mut view, &balances, MIN_EFFECTIVE_BALANCE * 1000)
    };
    assert_eq!(build(), build());
}
