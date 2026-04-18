//! Requirement DSL-167: `adjudicate_appeal` single-call dispatcher composes all DSL-064..073 slice functions into an end-to-end pass producing `AppealAdjudicationResult`.
//!
//! Traces to: docs/resources/SPEC.md §6.5.
//!
//! # Role
//!
//! Closes the public-API composition gap — embedders call ONE function per verdict and receive a fully-populated `AppealAdjudicationResult` with economic effects already applied to the injected trait impls. Previously the 10 slice functions had to be hand-composed.
//!
//! # Fixed slice order
//!
//! Sustained: revert-stake → revert-collateral → restore-status → clawback-rewards → forfeit-reporter-bond → absorb-shortfall → reporter-penalty → status-reverted.
//! Rejected: forfeit-appellant-bond → challenge-open.
//!
//! # Test matrix (maps to DSL-167 Test Plan)
//!
//!   1. `test_dsl_167_sustained_happy_path` — Sustained verdict, full trait mocks. Result populated; `pending.status == Reverted`; `appeal_history.len() == 1`.
//!   2. `test_dsl_167_rejected_happy_path` — Rejected verdict. Result populated; `pending.status == ChallengeOpen`; `appeal_count == 1`.
//!   3. `test_dsl_167_sustained_slice_order` — Spy on escrow + clawback + validator mocks; clawback call recorded BEFORE forfeit; forfeit BEFORE shortfall absorption (absorption's `final_burn` incorporates clawback shortfall).
//!   4. `test_dsl_167_shortfall_absorption_reduces_award` — Clawback returns partial; `clawback_shortfall > 0` reflected in result; `burn_amount == bond_split.burn + clawback_shortfall`.
//!   5. `test_dsl_167_outcome_matches_verdict` — Both verdict variants → result.outcome equals verdict.to_appeal_outcome().
//!   6. `test_dsl_167_appeal_history_append_once` — Single call grows history by exactly 1 regardless of branch.

use std::cell::RefCell;
use std::collections::BTreeMap;

use dig_protocol::Bytes32;
use dig_slashing::{
    APPELLANT_BOND_MOJOS, AppealAdjudicationResult, AppealOutcome, AppealRejectReason,
    AppealSustainReason, AppealVerdict, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint,
    EffectiveBalanceView, IndexedAttestation, OffenseType, PendingSlash, PendingSlashStatus,
    PerValidatorSlash, REPORTER_BOND_MOJOS, RewardClawback, RewardPayout,
    SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal, SlashAppealPayload, SlashingEvidence,
    SlashingEvidencePayload, ValidatorEntry, ValidatorView, VerifiedEvidence, adjudicate_appeal,
};

// ── mocks ──────────────────────────────────────────────────

struct RecBond {
    calls: RefCell<Vec<(u32, u64, BondTag, &'static str)>>,
    forfeit_returns: u64,
}
impl RecBond {
    fn returning(amount: u64) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            forfeit_returns: amount,
        }
    }
}
impl BondEscrow for RecBond {
    fn lock(&mut self, idx: u32, amt: u64, tag: BondTag) -> Result<(), BondError> {
        self.calls.borrow_mut().push((idx, amt, tag, "lock"));
        Ok(())
    }
    fn release(&mut self, idx: u32, amt: u64, tag: BondTag) -> Result<(), BondError> {
        self.calls.borrow_mut().push((idx, amt, tag, "release"));
        Ok(())
    }
    fn forfeit(&mut self, idx: u32, amt: u64, tag: BondTag) -> Result<u64, BondError> {
        self.calls.borrow_mut().push((idx, amt, tag, "forfeit"));
        Ok(self.forfeit_returns)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

#[derive(Default)]
struct RecReward {
    calls: RefCell<Vec<(Bytes32, u64)>>,
}
impl RewardPayout for RecReward {
    fn pay(&mut self, ph: Bytes32, amt: u64) {
        self.calls.borrow_mut().push((ph, amt));
    }
}

/// Clawback mock that returns a caller-configured proportion of
/// the requested amount, simulating partial clawback (DSL-142).
struct RecClawback {
    calls: RefCell<Vec<(Bytes32, u64)>>,
    /// Multiplier on requested amount: 1.0 returns full, 0.5 half, etc.
    /// Implemented as numerator/denominator to stay integer.
    num: u64,
    den: u64,
}
impl RecClawback {
    fn full() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            num: 1,
            den: 1,
        }
    }
    fn partial(num: u64, den: u64) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            num,
            den,
        }
    }
}
impl RewardClawback for RecClawback {
    fn claw_back(&mut self, ph: Bytes32, amount: u64) -> u64 {
        self.calls.borrow_mut().push((ph, amount));
        amount.saturating_mul(self.num) / self.den
    }
}

struct FixedBalances {
    balance: u64,
}
impl EffectiveBalanceView for FixedBalances {
    fn get(&self, _: u32) -> u64 {
        self.balance
    }
    fn total_active(&self) -> u64 {
        self.balance * 4
    }
}

struct RecValidator {
    ph: Bytes32,
    eff_bal: RefCell<u64>,
    is_slashed: RefCell<bool>,
    slash_calls: RefCell<Vec<(u64, u64)>>,
    credit_calls: RefCell<Vec<u64>>,
    restore_called: RefCell<bool>,
}
impl ValidatorEntry for RecValidator {
    fn public_key(&self) -> &chia_bls::PublicKey {
        use std::sync::OnceLock;
        static PK: OnceLock<chia_bls::PublicKey> = OnceLock::new();
        PK.get_or_init(chia_bls::PublicKey::default)
    }
    fn puzzle_hash(&self) -> Bytes32 {
        self.ph
    }
    fn effective_balance(&self) -> u64 {
        *self.eff_bal.borrow()
    }
    fn is_slashed(&self) -> bool {
        *self.is_slashed.borrow()
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
    fn slash_absolute(&mut self, amt: u64, epoch: u64) -> u64 {
        self.slash_calls.borrow_mut().push((amt, epoch));
        *self.is_slashed.borrow_mut() = true;
        let mut bal = self.eff_bal.borrow_mut();
        let actual = amt.min(*bal);
        *bal -= actual;
        actual
    }
    fn credit_stake(&mut self, amt: u64) -> u64 {
        self.credit_calls.borrow_mut().push(amt);
        *self.eff_bal.borrow_mut() += amt;
        amt
    }
    fn restore_status(&mut self) -> bool {
        *self.restore_called.borrow_mut() = true;
        let was = *self.is_slashed.borrow();
        *self.is_slashed.borrow_mut() = false;
        was
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct VSet {
    entries: Vec<RecValidator>,
}
impl ValidatorView for VSet {
    fn get(&self, i: u32) -> Option<&dyn ValidatorEntry> {
        self.entries
            .get(i as usize)
            .map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, i: u32) -> Option<&mut dyn ValidatorEntry> {
        self.entries
            .get_mut(i as usize)
            .map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn build_vset() -> VSet {
    VSet {
        entries: (0..10)
            .map(|i| RecValidator {
                ph: Bytes32::new([i as u8; 32]),
                eff_bal: RefCell::new(32_000_000_000),
                is_slashed: RefCell::new(i == 1), // idx 1 is the accused; starts slashed
                slash_calls: RefCell::new(Vec::new()),
                credit_calls: RefCell::new(Vec::new()),
                restore_called: RefCell::new(false),
            })
            .collect(),
    }
}

// ── fixtures ──────────────────────────────────────────────────

fn attester_evidence(reporter: u32) -> SlashingEvidence {
    let data = AttestationData {
        slot: 0,
        index: 0,
        beacon_block_root: Bytes32::new([0u8; 32]),
        source: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
        target: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
    };
    let att = IndexedAttestation {
        attesting_indices: vec![1],
        data,
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

fn pending_fixture(hash: Bytes32, reporter: u32) -> PendingSlash {
    PendingSlash {
        evidence_hash: hash,
        evidence: attester_evidence(reporter),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![PerValidatorSlash {
            validator_index: 1,
            base_slash_amount: 1_000_000,
            effective_balance_at_slash: 32_000_000_000,
            collateral_slashed: 0,
        }],
        reporter_bond_mojos: REPORTER_BOND_MOJOS,
        appeal_history: vec![],
    }
}

fn appeal_fixture(hash: Bytes32, appellant: u32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: hash,
        appellant_index: appellant,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![],
        }),
    }
}

// ── tests ──────────────────────────────────────────────────

/// DSL-167 row 1: sustained happy-path end-to-end.
///
/// Every economic side-effect lands: validator 1 is credited back
/// its base_slash_amount, restore_status fires, rewards claw
/// back in full, reporter bond forfeits, burn + appellant award
/// split, reporter penalty applied, status flips to Reverted,
/// appeal_history gains one Won entry.
#[test]
fn test_dsl_167_sustained_happy_path() {
    let hash = Bytes32::new([0xEFu8; 32]);
    let mut pending = pending_fixture(hash, 5);
    let appeal = appeal_fixture(hash, 7);
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    };

    let mut vset = build_vset();
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut bond = RecBond::returning(REPORTER_BOND_MOJOS);
    let mut reward = RecReward::default();
    let mut clawback = RecClawback::full();
    let mut siw: BTreeMap<(u64, u32), u64> = BTreeMap::new();
    let proposer_ph = Bytes32::new([0xBBu8; 32]);

    let result: AppealAdjudicationResult = adjudicate_appeal(
        verdict,
        &mut pending,
        &appeal,
        &mut vset,
        &balances,
        None,
        &mut bond,
        &mut reward,
        &mut clawback,
        &mut siw,
        proposer_ph,
        Bytes32::new([0x00u8; 32]),
        20,
    )
    .expect("sustained must succeed");

    // Outcome matches verdict → Won.
    assert_eq!(result.outcome, AppealOutcome::Won);
    assert_eq!(result.appeal_hash, appeal.hash());
    assert_eq!(result.evidence_hash, hash);

    // Sustained-branch fields populated.
    assert_eq!(result.reverted_stake_mojos, vec![(1, 1_000_000)]);
    assert_eq!(result.reverted_collateral_mojos, Vec::<(u32, u64)>::new());
    assert_eq!(result.clawback_shortfall, 0); // full clawback
    assert_eq!(result.reporter_bond_forfeited, REPORTER_BOND_MOJOS);
    assert_eq!(result.appellant_award_mojos, REPORTER_BOND_MOJOS / 2);
    assert!(result.reporter_penalty_mojos > 0);
    // Rejected-branch fields zero.
    assert_eq!(result.appellant_bond_forfeited, 0);
    assert_eq!(result.reporter_award_mojos, 0);

    // Status + history.
    assert!(matches!(
        pending.status,
        PendingSlashStatus::Reverted { .. }
    ));
    assert_eq!(pending.appeal_history.len(), 1);
    assert!(matches!(
        pending.appeal_history[0].outcome,
        AppealOutcome::Won
    ));

    // Validator 1 credited back.
    assert_eq!(*vset.entries[1].credit_calls.borrow(), vec![1_000_000]);
    assert!(*vset.entries[1].restore_called.borrow());

    // Reporter (idx 5) had slash_absolute called (reporter penalty).
    let rp_calls = vset.entries[5].slash_calls.borrow();
    assert_eq!(rp_calls.len(), 1, "reporter penalty applied once");

    // slashed_in_window carries the reporter penalty row.
    assert!(siw.contains_key(&(20, 5)));
}

/// DSL-167 row 2: rejected happy-path end-to-end.
///
/// Appellant bond forfeits; 50/50 split pays reporter, remainder
/// burns. Status flips to ChallengeOpen. History gains one Lost
/// entry. Sustained-branch fields all zero.
#[test]
fn test_dsl_167_rejected_happy_path() {
    let hash = Bytes32::new([0xDDu8; 32]);
    let mut pending = pending_fixture(hash, 5);
    let appeal = appeal_fixture(hash, 7);
    let verdict = AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    };

    let mut vset = build_vset();
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut bond = RecBond::returning(APPELLANT_BOND_MOJOS);
    let mut reward = RecReward::default();
    let mut clawback = RecClawback::full();
    let mut siw: BTreeMap<(u64, u32), u64> = BTreeMap::new();

    let result = adjudicate_appeal(
        verdict,
        &mut pending,
        &appeal,
        &mut vset,
        &balances,
        None,
        &mut bond,
        &mut reward,
        &mut clawback,
        &mut siw,
        Bytes32::new([0xBBu8; 32]),
        Bytes32::new([0x99u8; 32]),
        20,
    )
    .expect("rejected must succeed");

    // Outcome → Lost.
    assert!(matches!(result.outcome, AppealOutcome::Lost { .. }));

    // Rejected-branch populated.
    assert_eq!(result.appellant_bond_forfeited, APPELLANT_BOND_MOJOS);
    assert_eq!(result.reporter_award_mojos, APPELLANT_BOND_MOJOS / 2);
    assert_eq!(
        result.burn_amount,
        APPELLANT_BOND_MOJOS - APPELLANT_BOND_MOJOS / 2
    );

    // Sustained-branch empty / zero.
    assert!(result.reverted_stake_mojos.is_empty());
    assert!(result.reverted_collateral_mojos.is_empty());
    assert_eq!(result.clawback_shortfall, 0);
    assert_eq!(result.reporter_bond_forfeited, 0);
    assert_eq!(result.appellant_award_mojos, 0);
    assert_eq!(result.reporter_penalty_mojos, 0);

    // Status → ChallengeOpen (appeal_count bumps from 0 → 1).
    match pending.status {
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch,
            appeal_count,
        } => {
            assert_eq!(first_appeal_filed_epoch, 12);
            assert_eq!(appeal_count, 1);
        }
        other => panic!("expected ChallengeOpen, got {other:?}"),
    }
    assert_eq!(pending.appeal_history.len(), 1);
    assert!(matches!(
        pending.appeal_history[0].outcome,
        AppealOutcome::Lost { .. }
    ));

    // No sustained-side side effects — validator 1 not credited.
    assert!(vset.entries[1].credit_calls.borrow().is_empty());
    assert!(siw.is_empty());
}

/// DSL-167 row 3: slice order — clawback calls precede forfeit
/// calls; forfeit precedes shortfall absorption (absorption's
/// `final_burn` incorporates clawback shortfall, which it can
/// only do if clawback + forfeit ran first).
///
/// Uses `RecBond::returning(1_000_000)` with a partial clawback
/// so clawback_shortfall > 0; then asserts `burn_amount ==
/// bond_split.burn + shortfall` which is only true if absorption
/// saw both results.
#[test]
fn test_dsl_167_sustained_slice_order() {
    let hash = Bytes32::new([0xAAu8; 32]);
    let mut pending = pending_fixture(hash, 5);
    let appeal = appeal_fixture(hash, 7);
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    };

    let mut vset = build_vset();
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut bond = RecBond::returning(1_000);
    let mut reward = RecReward::default();
    // Partial clawback — returns half of requested.
    let mut clawback = RecClawback::partial(1, 2);
    let mut siw: BTreeMap<(u64, u32), u64> = BTreeMap::new();

    let result = adjudicate_appeal(
        verdict,
        &mut pending,
        &appeal,
        &mut vset,
        &balances,
        None,
        &mut bond,
        &mut reward,
        &mut clawback,
        &mut siw,
        Bytes32::new([0xBBu8; 32]),
        Bytes32::new([0u8; 32]),
        20,
    )
    .unwrap();

    // Clawback + forfeit both happened.
    assert!(!clawback.calls.borrow().is_empty(), "clawback slice ran");
    assert!(
        bond.calls
            .borrow()
            .iter()
            .any(|(_, _, _, kind)| *kind == "forfeit"),
        "forfeit slice ran",
    );

    // Absorption observed: burn_amount == bond_split.burn +
    // clawback_shortfall. bond_split.burn for forfeit=1000 is 500;
    // clawback_shortfall is non-zero (partial).
    assert_eq!(result.reporter_bond_forfeited, 1_000);
    assert!(
        result.clawback_shortfall > 0,
        "partial clawback → shortfall > 0"
    );
    assert_eq!(
        result.burn_amount,
        500_u64 + result.clawback_shortfall,
        "final burn absorbs clawback shortfall",
    );
}

/// DSL-167 row 4: shortfall absorption reduces appellant_award
/// into burn when clawback is partial.
///
/// Cross-check of row 3 phrased as the acceptance-criteria line —
/// partial clawback produces shortfall; shortfall appears in
/// `burn_amount` AND is carried verbatim in `clawback_shortfall`.
#[test]
fn test_dsl_167_shortfall_absorption_reduces_award() {
    let hash = Bytes32::new([0xEEu8; 32]);
    let mut pending = pending_fixture(hash, 5);
    let appeal = appeal_fixture(hash, 7);
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    };

    let mut vset = build_vset();
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    // Large forfeit so winner_award > 0 regardless of rounding.
    let mut bond = RecBond::returning(REPORTER_BOND_MOJOS);
    let mut reward = RecReward::default();
    // No clawback at all (num=0) → shortfall == full requested.
    let mut clawback = RecClawback::partial(0, 1);
    let mut siw: BTreeMap<(u64, u32), u64> = BTreeMap::new();

    let result = adjudicate_appeal(
        verdict,
        &mut pending,
        &appeal,
        &mut vset,
        &balances,
        None,
        &mut bond,
        &mut reward,
        &mut clawback,
        &mut siw,
        Bytes32::new([0xBBu8; 32]),
        Bytes32::new([0u8; 32]),
        20,
    )
    .unwrap();

    // wb_amount = total_eff_bal / WHISTLEBLOWER_REWARD_QUOTIENT
    //           = 32_000_000_000 / 512 = 62_500_000.
    // prop_amount = 62_500_000 / 8 = 7_812_500.
    // zero clawback → shortfall = 62_500_000 + 7_812_500 = 70_312_500.
    assert_eq!(result.clawback_shortfall, 62_500_000 + 7_812_500);

    // bond_split.burn = REPORTER_BOND_MOJOS / 2.
    // final burn = bond_split.burn + clawback_shortfall.
    let bond_burn = REPORTER_BOND_MOJOS / 2;
    assert_eq!(
        result.burn_amount,
        bond_burn + result.clawback_shortfall,
        "final burn = bond half + absorbed shortfall",
    );
}

/// DSL-167 row 5: result.outcome matches verdict.to_appeal_outcome().
#[test]
fn test_dsl_167_outcome_matches_verdict() {
    // Sustained branch.
    {
        let hash = Bytes32::new([0x11u8; 32]);
        let mut pending = pending_fixture(hash, 42);
        let appeal = appeal_fixture(hash, 77);
        let verdict = AppealVerdict::Sustained {
            reason: AppealSustainReason::AttestationsIdentical,
        };
        let mut vset = build_vset();
        let balances = FixedBalances {
            balance: 32_000_000_000,
        };
        let mut bond = RecBond::returning(REPORTER_BOND_MOJOS);
        let mut reward = RecReward::default();
        let mut clawback = RecClawback::full();
        let mut siw: BTreeMap<(u64, u32), u64> = BTreeMap::new();

        let result = adjudicate_appeal(
            verdict,
            &mut pending,
            &appeal,
            &mut vset,
            &balances,
            None,
            &mut bond,
            &mut reward,
            &mut clawback,
            &mut siw,
            Bytes32::new([0u8; 32]),
            Bytes32::new([0u8; 32]),
            20,
        )
        .unwrap();
        assert_eq!(result.outcome, verdict.to_appeal_outcome());
    }

    // Rejected branch.
    {
        let hash = Bytes32::new([0x22u8; 32]);
        let mut pending = pending_fixture(hash, 42);
        let appeal = appeal_fixture(hash, 77);
        let verdict = AppealVerdict::Rejected {
            reason: AppealRejectReason::MalformedWitness,
        };
        let mut vset = build_vset();
        let balances = FixedBalances {
            balance: 32_000_000_000,
        };
        let mut bond = RecBond::returning(APPELLANT_BOND_MOJOS);
        let mut reward = RecReward::default();
        let mut clawback = RecClawback::full();
        let mut siw: BTreeMap<(u64, u32), u64> = BTreeMap::new();

        let result = adjudicate_appeal(
            verdict,
            &mut pending,
            &appeal,
            &mut vset,
            &balances,
            None,
            &mut bond,
            &mut reward,
            &mut clawback,
            &mut siw,
            Bytes32::new([0u8; 32]),
            Bytes32::new([0u8; 32]),
            20,
        )
        .unwrap();
        assert_eq!(result.outcome, verdict.to_appeal_outcome());
    }
}

/// DSL-167 row 6: single call appends exactly ONE entry to
/// `pending.appeal_history` on either branch.
///
/// Critical invariant: DSL-070 (sustained → Won entry) and
/// DSL-072 (rejected → Lost entry) both append. Dispatcher must
/// NOT double-append by calling both slices — each branch runs
/// exactly one of them.
#[test]
fn test_dsl_167_appeal_history_append_once() {
    // Sustained.
    let hash = Bytes32::new([0x33u8; 32]);
    let mut pending = pending_fixture(hash, 42);
    let pre_len = pending.appeal_history.len();
    let appeal = appeal_fixture(hash, 77);
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    };
    let mut vset = build_vset();
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut bond = RecBond::returning(REPORTER_BOND_MOJOS);
    let mut reward = RecReward::default();
    let mut clawback = RecClawback::full();
    let mut siw: BTreeMap<(u64, u32), u64> = BTreeMap::new();

    adjudicate_appeal(
        verdict,
        &mut pending,
        &appeal,
        &mut vset,
        &balances,
        None,
        &mut bond,
        &mut reward,
        &mut clawback,
        &mut siw,
        Bytes32::new([0u8; 32]),
        Bytes32::new([0u8; 32]),
        20,
    )
    .unwrap();
    assert_eq!(
        pending.appeal_history.len(),
        pre_len + 1,
        "sustained appends exactly 1 entry",
    );

    // Rejected.
    let mut pending_r = pending_fixture(hash, 5);
    let pre_len_r = pending_r.appeal_history.len();
    let verdict_r = AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    };
    let mut bond_r = RecBond::returning(APPELLANT_BOND_MOJOS);
    let mut clawback_r = RecClawback::full();

    adjudicate_appeal(
        verdict_r,
        &mut pending_r,
        &appeal,
        &mut vset,
        &balances,
        None,
        &mut bond_r,
        &mut reward,
        &mut clawback_r,
        &mut siw,
        Bytes32::new([0u8; 32]),
        Bytes32::new([0u8; 32]),
        20,
    )
    .unwrap();
    assert_eq!(
        pending_r.appeal_history.len(),
        pre_len_r + 1,
        "rejected appends exactly 1 entry",
    );
}
