//! Requirement DSL-151: correlation penalty saturation clamp.
//!
//! Traces to: docs/resources/SPEC.md §4, §7.4.
//!
//! # Formula under test
//!
//! ```text
//!   scaled  = cohort_sum.saturating_mul(PROPORTIONAL_SLASHING_MULTIPLIER=3)
//!   capped  = min(scaled, total_active_balance)           // clamp
//!   penalty = eff_bal * capped / total_active_balance     // u128 math
//! ```
//!
//! Per-validator `penalty` is guaranteed ≤ `eff_bal` by the clamp.
//!
//! # Why the clamp is load-bearing
//!
//! Without the clamp, a mass-slash where `cohort_sum * 3 >
//! total_active_balance` would produce `penalty > eff_bal`, saturating
//! the debit inside `ValidatorEntry::slash_absolute` but exposing a
//! LOGICALLY invalid pre-saturation value in `FinalisationResult`.
//! Downstream accounting (DSL-032 exit lock sizing, audit trails)
//! reads the result vec directly — the clamp enforces the invariant
//! at the formula level rather than relying on saturating arithmetic
//! in the validator trait.
//!
//! # Test matrix (maps to DSL-151 Test Plan)
//!
//!   1. `test_dsl_151_small_cohort_no_clamp` — cohort=1×eff,
//!      total=100×eff → correlation ≈ eff*3/100
//!   2. `test_dsl_151_mass_cohort_clamps` — cohort=50×eff,
//!      total=100×eff → penalty == eff_bal (clamped)
//!   3. `test_dsl_151_exact_ceiling` — cohort*3 == total →
//!      penalty == eff_bal (boundary of the clamp)
//!   4. `test_dsl_151_zero_total_guard` — total_active=0 →
//!      penalty=0 + no panic (defensive div-by-zero guard)
//!   5. `test_dsl_151_overflow_saturates` — cohort*3 overflows u64
//!      → saturating_mul → u64::MAX → clamped to total_active →
//!      penalty == eff_bal
//!
//! # Test strategy
//!
//! Admits ONE real evidence for idx=9 via `submit_evidence` to get a
//! PendingSlash in the book, then seeds additional
//! `slashed_in_window` rows directly via `mark_slashed_in_window` to
//! build arbitrary cohort_sum values without standing up 50 distinct
//! BLS-signed evidences. The `slashed_in_window` map is the
//! cohort_sum data source (src/manager.rs:456), so this seeding
//! exercises the exact code path.

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

// ────────────────────────── mocks ──────────────────────────────

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

// ─────────────────────── test helpers ──────────────────────────

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

/// Admit a single proposer-equivocation slash for `idx` at the given
/// epoch. Returns the evidence hash + the populated MapView.
fn admit_one(mgr: &mut SlashingManager, idx: u32, admit_epoch: u64) -> MapView {
    mgr.set_epoch(admit_epoch);
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = sample_header(idx, admit_epoch, 0xA1);
    let header_b = sample_header(idx, admit_epoch, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(
        idx,
        TestValidator {
            pk,
            slash_calls: RefCell::new(Vec::new()),
        },
    );
    // Reporter validator (idx=0) needs to exist in the view.
    let sk_rep = make_sk(0xFE);
    map.insert(
        0u32,
        TestValidator {
            pk: sk_rep.public_key(),
            slash_calls: RefCell::new(Vec::new()),
        },
    );
    let mut view = MapView(map);

    let ev = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: 0,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: admit_epoch,
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
    let balances = MapBalances(HashMap::from([(idx, MIN_EFFECTIVE_BALANCE)]));
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
    view
}

// ─────────────────────── tests ──────────────────────────────

/// DSL-151 row 1: cohort_sum = 1×eff, total_active = 100×eff.
/// `scaled = 3×eff`; `capped = min(3×eff, 100×eff) = 3×eff` (no clamp).
/// `penalty = eff × 3×eff / 100×eff = 3×eff / 100`.
///
/// Pins the linear-regime branch — every small cohort yields the
/// Ethereum-parity proportional penalty without the clamp engaging.
#[test]
fn test_dsl_151_small_cohort_no_clamp() {
    let mut mgr = SlashingManager::new(0);
    let mut view = admit_one(&mut mgr, 9, 0);

    // Advance past appeal window.
    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let total_active = MIN_EFFECTIVE_BALANCE * 100;

    let results =
        mgr.finalise_expired_slashes(&mut view, &balances, &mut AcceptingBond, total_active);

    // Expected: scaled = 3×MIN_EFFECTIVE_BALANCE.
    // capped = min(3×MIN_EFFECTIVE_BALANCE, 100×MIN_EFFECTIVE_BALANCE) = 3×MIN.
    // penalty = MIN × 3×MIN / (100×MIN) = 3×MIN / 100.
    let eff = u128::from(MIN_EFFECTIVE_BALANCE);
    let expected = ((eff * 3 * eff) / u128::from(total_active)) as u64;

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].per_validator_correlation_penalty,
        vec![(9, expected)],
    );
    assert!(
        expected < MIN_EFFECTIVE_BALANCE,
        "small-cohort penalty must stay below the clamp ceiling",
    );
}

/// DSL-151 row 2: cohort_sum = 50×eff, total = 100×eff.
/// `scaled = 150×eff`; `capped = min(150, 100) = 100×eff` (clamps).
/// `penalty = eff × 100×eff / 100×eff = eff` (saturates at full stake).
///
/// Built by admitting one evidence (contributes 1×eff) + seeding 49
/// extra `slashed_in_window` rows via `mark_slashed_in_window` so
/// cohort_sum exactly equals `50 × MIN_EFFECTIVE_BALANCE` without
/// standing up 50 distinct evidences.
#[test]
fn test_dsl_151_mass_cohort_clamps() {
    let mut mgr = SlashingManager::new(0);
    let mut view = admit_one(&mut mgr, 9, 0);

    // Seed 49 extra cohort members at the same admit epoch (0). Any
    // epoch inside `[current - CORRELATION_WINDOW_EPOCHS, current]`
    // works.
    for idx in 100u32..149 {
        mgr.mark_slashed_in_window(0, idx, MIN_EFFECTIVE_BALANCE);
    }

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let total_active = MIN_EFFECTIVE_BALANCE * 100;

    let results =
        mgr.finalise_expired_slashes(&mut view, &balances, &mut AcceptingBond, total_active);

    // cohort_sum = 50 × MIN_EFFECTIVE_BALANCE.
    // scaled = 150 × MIN (> total_active). capped → total_active.
    // penalty = eff × total_active / total_active = eff = MIN_EFFECTIVE_BALANCE.
    assert_eq!(
        results[0].per_validator_correlation_penalty,
        vec![(9, MIN_EFFECTIVE_BALANCE)],
        "mass-slash clamp must pin per-validator penalty at eff_bal",
    );
}

/// DSL-151 row 3: exact ceiling — cohort_sum × 3 == total_active.
/// `scaled == total_active`, so `capped == scaled == total_active`
/// without truncation.
/// `penalty = eff × total_active / total_active = eff`.
///
/// Pins the boundary condition: the clamp is triggered by `min`
/// returning the `total_active` branch even when `scaled ==
/// total_active` (no strict-inequality bug).
#[test]
fn test_dsl_151_exact_ceiling() {
    let mut mgr = SlashingManager::new(0);
    let mut view = admit_one(&mut mgr, 9, 0);

    // cohort_sum = eff + 33×eff = 34×eff? No — need cohort_sum × 3 == total.
    // Admit contributes 1×eff. Seed additional so cohort_sum × 3 == total.
    // Pick total_active = 102×MIN → cohort_sum needs 34×MIN → seed 33 extras.
    let total_active = MIN_EFFECTIVE_BALANCE * 102;
    for idx in 200u32..233 {
        mgr.mark_slashed_in_window(0, idx, MIN_EFFECTIVE_BALANCE);
    }

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));

    let results =
        mgr.finalise_expired_slashes(&mut view, &balances, &mut AcceptingBond, total_active);

    // cohort_sum = 34 × MIN; scaled = 102 × MIN == total_active.
    // capped = min(102×MIN, 102×MIN) = 102×MIN.
    // penalty = eff × 102×MIN / 102×MIN = eff = MIN.
    assert_eq!(
        results[0].per_validator_correlation_penalty,
        vec![(9, MIN_EFFECTIVE_BALANCE)],
        "exact-ceiling cohort must produce penalty == eff_bal",
    );
}

/// DSL-151 row 4: `total_active_balance == 0` is the
/// defensive-guard branch — formula is undefined (division by zero)
/// so the manager returns 0 without panicking.
///
/// Can only trigger at network genesis / pathological state; still
/// required as a robustness property so finalise never takes the
/// chain down.
#[test]
fn test_dsl_151_zero_total_guard() {
    let mut mgr = SlashingManager::new(0);
    let mut view = admit_one(&mut mgr, 9, 0);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let total_active = 0u64;

    // Must NOT panic on divide-by-zero.
    let results =
        mgr.finalise_expired_slashes(&mut view, &balances, &mut AcceptingBond, total_active);

    assert_eq!(
        results[0].per_validator_correlation_penalty,
        vec![(9, 0)],
        "total_active=0 guard must produce penalty=0 without panic",
    );
}

/// DSL-151 row 5: overflow saturation.
///
/// Set cohort_sum so that `cohort_sum × 3` overflows u64:
/// `saturating_mul` pins the result at `u64::MAX`, which the `min(.,
/// total_active)` then clamps back to `total_active`. End result:
/// penalty == eff_bal (identical observable behaviour to the mass-
/// slash clamp).
///
/// Achieved by seeding a single huge `slashed_in_window` entry at
/// `u64::MAX / 2` — scaling by 3 overflows but saturates.
#[test]
fn test_dsl_151_overflow_saturates() {
    let mut mgr = SlashingManager::new(0);
    let mut view = admit_one(&mut mgr, 9, 0);

    // Seed a giant cohort contributor so `cohort_sum × 3` overflows.
    // `u64::MAX / 2 × 3` > u64::MAX → saturating_mul == u64::MAX.
    mgr.mark_slashed_in_window(0, 999u32, u64::MAX / 2);

    mgr.set_epoch(SLASH_APPEAL_WINDOW_EPOCHS + 1);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    // total_active chosen modestly so clamp is the final effective
    // value: penalty = eff × total / total = eff.
    let total_active = MIN_EFFECTIVE_BALANCE * 10;

    let results =
        mgr.finalise_expired_slashes(&mut view, &balances, &mut AcceptingBond, total_active);

    assert_eq!(
        results[0].per_validator_correlation_penalty,
        vec![(9, MIN_EFFECTIVE_BALANCE)],
        "overflow → saturating_mul → clamp → eff_bal",
    );
}
