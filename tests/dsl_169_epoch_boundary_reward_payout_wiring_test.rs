//! Requirement DSL-169: `run_epoch_boundary` wires `reward_payout` for `FlagDelta` rewards AND applies `inactivity_penalties` to validator stakes via `ValidatorEntry::slash_absolute`.
//!
//! Traces to: docs/resources/SPEC.md §10, §8.4.
//!
//! # Role
//!
//! Closes two wiring gaps in `run_epoch_boundary`:
//!
//!   1. `reward_payout: &mut dyn RewardPayout` was previously threaded through the signature but discarded (`let _ = &reward_payout;`). FlagDelta rewards accumulated in `report.flag_deltas` were never routed to the embedder's payout accumulator.
//!   2. `inactivity_penalties: Vec<(u32, u64)>` was computed by `epoch_penalties` (DSL-091/092) and returned in the report but never applied to validator stakes.
//!
//! Under DSL-169:
//!   - Step 1b (inside step 1 flag-delta computation) calls `RewardPayout::pay(puzzle_hash, reward)` per FlagDelta where `reward > 0`.
//!   - Step 3b (inside step 3 inactivity-penalty computation) calls `ValidatorEntry::slash_absolute(penalty, current_epoch_ending)` per `(idx, penalty)` in `inactivity_penalties`.
//!   - Validators missing from the view are silently skipped on both paths.
//!   - Zero-reward FlagDeltas do NOT trigger a `pay` call.
//!   - DSL-127 fixed 8-step order is preserved — the wiring is in-line inside existing steps, not new top-level steps.
//!
//! # Test matrix (maps to DSL-169 Test Plan)
//!
//!   1. `test_dsl_169_flag_delta_reward_paid` — attester hit + non-zero reward → exactly one `pay(ph, reward)` call with matching args.
//!   2. `test_dsl_169_zero_reward_no_pay` — idle validators (zero flags) → zero `pay` calls.
//!   3. `test_dsl_169_inactivity_penalty_slashes` — in stall + seeded scores → `slash_absolute(penalty, epoch)` called with exact amounts per validator.
//!   4. `test_dsl_169_missing_validator_skipped` — FlagDelta for idx outside view → no panic; no `pay` call.
//!   5. `test_dsl_169_step_order_preserved` — DSL-127 outcome-based ordering still passes (flag_deltas computed before rewards paid; penalties computed before slash calls; epoch counters advance last).

use std::cell::RefCell;

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, EffectiveBalanceView, InactivityScoreTracker,
    JustificationView, ParticipationFlags, ParticipationTracker, RewardPayout, SlashingManager,
    TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX, ValidatorEntry,
    ValidatorView, run_epoch_boundary,
};

// ── mocks ──────────────────────────────────────────────────

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

struct NoopBond;
impl BondEscrow for NoopBond {
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

/// Records every `pay(ph, amount)` call in insertion order.
#[derive(Default)]
struct RecordingPayout {
    calls: RefCell<Vec<(Bytes32, u64)>>,
}
impl RewardPayout for RecordingPayout {
    fn pay(&mut self, ph: Bytes32, amount: u64) {
        self.calls.borrow_mut().push((ph, amount));
    }
}

struct FixedJustification {
    finalized: u64,
}
impl JustificationView for FixedJustification {
    fn latest_finalized_epoch(&self) -> u64 {
        self.finalized
    }
}

/// Validator that records every `slash_absolute` + mutates its
/// own effective balance so post-call state can be inspected.
struct RecordingValidator {
    pk: PublicKey,
    ph: Bytes32,
    eff_bal: RefCell<u64>,
    is_slashed: RefCell<bool>,
    slash_calls: RefCell<Vec<(u64, u64)>>,
}
impl ValidatorEntry for RecordingValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
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
    fn slash_absolute(&mut self, amount: u64, epoch: u64) -> u64 {
        self.slash_calls.borrow_mut().push((amount, epoch));
        let mut bal = self.eff_bal.borrow_mut();
        let actual = amount.min(*bal);
        *bal -= actual;
        *self.is_slashed.borrow_mut() = true;
        actual
    }
    fn credit_stake(&mut self, _: u64) -> u64 {
        0
    }
    fn restore_status(&mut self) -> bool {
        false
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct RecordingValidatorSet {
    entries: Vec<RecordingValidator>,
}
impl ValidatorView for RecordingValidatorSet {
    fn get(&self, idx: u32) -> Option<&dyn ValidatorEntry> {
        self.entries
            .get(idx as usize)
            .map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, idx: u32) -> Option<&mut dyn ValidatorEntry> {
        self.entries
            .get_mut(idx as usize)
            .map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.entries.len()
    }
}

fn build_validators(n: usize) -> RecordingValidatorSet {
    RecordingValidatorSet {
        entries: (0..n)
            .map(|i| RecordingValidator {
                pk: PublicKey::default(),
                ph: Bytes32::new([i as u8; 32]),
                eff_bal: RefCell::new(32_000_000_000),
                is_slashed: RefCell::new(false),
                slash_calls: RefCell::new(Vec::new()),
            })
            .collect(),
    }
}

fn all_flags_hit() -> ParticipationFlags {
    let mut f = ParticipationFlags::default();
    f.set(TIMELY_SOURCE_FLAG_INDEX);
    f.set(TIMELY_TARGET_FLAG_INDEX);
    f.set(TIMELY_HEAD_FLAG_INDEX);
    f
}

// ── tests ──────────────────────────────────────────────────

/// DSL-169 row 1: FlagDelta with reward > 0 triggers exactly one
/// `RewardPayout::pay(ph, reward)` call with matching amount.
///
/// Seeds participation's PREVIOUS epoch with all three flags for
/// every validator — triggers the full DSL-082 reward on the
/// next run_epoch_boundary. `total_active_balance` is small so
/// the per-validator base reward is non-trivially positive.
#[test]
fn test_dsl_169_flag_delta_reward_paid() {
    let mut manager = SlashingManager::new(10);
    let mut participation = ParticipationTracker::new(4, 10);
    let mut inactivity = InactivityScoreTracker::new(4);
    let mut vset = build_validators(4);
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut escrow = NoopBond;
    let mut payout = RecordingPayout::default();
    let justification = FixedJustification { finalized: 10 };

    // Seed previous-epoch flags: rotate CURRENT into PREVIOUS with
    // flags set. Trick: record_attestation writes current_epoch;
    // rotate_epoch swaps current→previous. So record then rotate.
    let dummy_data = dig_slashing::AttestationData {
        slot: 0,
        index: 0,
        beacon_block_root: Bytes32::new([0u8; 32]),
        source: dig_slashing::Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
        target: dig_slashing::Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
    };
    participation
        .record_attestation(&dummy_data, &[0, 1, 2, 3], all_flags_hit())
        .expect("record");
    participation.rotate_epoch(11, 4);
    // After rotate: previous_epoch has all flags set for every idx.
    // But run_epoch_boundary sets tracker's current to current_epoch_ending+1
    // via its own rotate_epoch, so the fixture pre-rotation doesn't
    // interfere. The DSL-082 reward formula reads previous_flags.
    manager.set_epoch(11);

    let report = run_epoch_boundary(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut vset,
        &balances,
        &mut escrow,
        &mut payout,
        &justification,
        11,
        4,
        128_000_000_000,
    );

    // Every FlagDelta should have produced exactly one pay call
    // with (validator.ph, fd.reward) — filtered for reward > 0.
    let nonzero_rewards: Vec<&dig_slashing::FlagDelta> = report
        .flag_deltas
        .iter()
        .filter(|fd| fd.reward > 0)
        .collect();
    let calls = payout.calls.borrow();

    assert_eq!(
        calls.len(),
        nonzero_rewards.len(),
        "one pay call per non-zero FlagDelta ({} vs {} calls)",
        nonzero_rewards.len(),
        calls.len(),
    );

    // Each expected (ph, reward) pair MUST appear in the calls.
    for fd in &nonzero_rewards {
        let ph = vset.entries[fd.validator_index as usize].ph;
        assert!(
            calls.iter().any(|(p, a)| *p == ph && *a == fd.reward),
            "missing pay call for idx={} reward={}",
            fd.validator_index,
            fd.reward,
        );
    }
}

/// DSL-169 row 2: zero-reward FlagDeltas do NOT trigger `pay`.
///
/// No attestations recorded → previous_flags all zero → DSL-083
/// penalties dominate, rewards = 0. Zero calls to RewardPayout::pay
/// expected.
#[test]
fn test_dsl_169_zero_reward_no_pay() {
    let mut manager = SlashingManager::new(10);
    let mut participation = ParticipationTracker::new(4, 10);
    let mut inactivity = InactivityScoreTracker::new(4);
    let mut vset = build_validators(4);
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut escrow = NoopBond;
    let mut payout = RecordingPayout::default();
    let justification = FixedJustification { finalized: 10 };

    let report = run_epoch_boundary(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut vset,
        &balances,
        &mut escrow,
        &mut payout,
        &justification,
        10,
        4,
        128_000_000_000,
    );

    // Every FlagDelta has reward == 0 in this scenario.
    assert!(report.flag_deltas.iter().all(|fd| fd.reward == 0));
    assert_eq!(
        payout.calls.borrow().len(),
        0,
        "zero-reward path must make zero pay calls",
    );
}

/// DSL-169 row 3: inactivity penalties applied via
/// `ValidatorEntry::slash_absolute(penalty, current_epoch_ending)`.
///
/// Forces a finality stall (finalized << current_epoch_ending) so
/// DSL-092 formula fires, then seeds inactivity scores to
/// produce non-zero penalties. Each `(idx, penalty)` pair in
/// `inactivity_penalties` must map to exactly one slash_absolute
/// call on that validator.
#[test]
fn test_dsl_169_inactivity_penalty_slashes() {
    let mut manager = SlashingManager::new(100);
    let mut participation = ParticipationTracker::new(3, 100);
    let mut inactivity = InactivityScoreTracker::new(3);
    inactivity.set_score(0, 1024);
    inactivity.set_score(1, 2048);
    inactivity.set_score(2, 0);

    let mut vset = build_validators(3);
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut escrow = NoopBond;
    let mut payout = RecordingPayout::default();
    // Stall: finalized=95 (5 epochs back) → in_finality_stall true.
    let justification = FixedJustification { finalized: 95 };

    let report = run_epoch_boundary(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut vset,
        &balances,
        &mut escrow,
        &mut payout,
        &justification,
        100,
        3,
        96_000_000_000,
    );

    assert!(report.in_finality_stall);
    assert!(
        !report.inactivity_penalties.is_empty(),
        "non-zero scores in stall must produce non-empty penalty vec",
    );

    // Each penalty pair must match exactly one slash_absolute call
    // on that validator with (penalty_mojos, current_epoch_ending=100).
    for &(idx, penalty) in &report.inactivity_penalties {
        let v = &vset.entries[idx as usize];
        let calls = v.slash_calls.borrow();
        assert!(
            calls.iter().any(|(amt, ep)| *amt == penalty && *ep == 100),
            "idx={idx} penalty={penalty} not applied via slash_absolute",
        );
    }

    // NOTE: idx 2 was seeded with score=0, but DSL-089
    // (`update_for_epoch` in stall + miss) runs BEFORE
    // `epoch_penalties` inside the fixed step order, bumping
    // idx 2's score by INACTIVITY_SCORE_BIAS before penalty
    // evaluation. So idx 2 MAY appear in the penalty vec with a
    // small positive amount. This is correct DSL-127 ordering
    // behaviour and not in scope for DSL-169; the earlier
    // per-penalty assertion already covers the wiring contract.
}

/// DSL-169 row 4: FlagDelta referencing an index outside the view
/// does not panic and does not generate a `pay` call.
///
/// DSL-082 builds one FlagDelta per index the participation
/// tracker knows about. If the tracker is wider than the
/// validator view, the wiring must defensively skip rather than
/// panic on `validator_set.get(idx).unwrap()`.
#[test]
fn test_dsl_169_missing_validator_skipped() {
    let mut manager = SlashingManager::new(10);
    // Participation tracks 5 validators.
    let mut participation = ParticipationTracker::new(5, 10);
    let mut inactivity = InactivityScoreTracker::new(5);
    // View only has 3 — idx 3 + 4 are "missing".
    let mut vset = build_validators(3);
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut escrow = NoopBond;
    let mut payout = RecordingPayout::default();
    let justification = FixedJustification { finalized: 10 };

    // Seed previous flags for ALL 5 — rewards would fire on every
    // idx if the wiring didn't skip missing ones.
    let dummy_data = dig_slashing::AttestationData {
        slot: 0,
        index: 0,
        beacon_block_root: Bytes32::new([0u8; 32]),
        source: dig_slashing::Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
        target: dig_slashing::Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
    };
    participation
        .record_attestation(&dummy_data, &[0, 1, 2, 3, 4], all_flags_hit())
        .expect("record");
    participation.rotate_epoch(11, 5);
    manager.set_epoch(11);

    // Run with validator_count=3 so resize brings participation
    // back to 3 at the end — but the flag-delta pass above reads
    // PREVIOUS epoch (5 entries) so the out-of-view path is
    // exercised.
    run_epoch_boundary(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut vset,
        &balances,
        &mut escrow,
        &mut payout,
        &justification,
        11,
        3,
        96_000_000_000,
    );

    // No panic above. At most 3 pay calls (one per in-view
    // validator with a non-zero reward). Crucially, indices 3 + 4
    // must NOT have puzzle-hash entries in the call list.
    let calls = payout.calls.borrow();
    let ph_3 = Bytes32::new([3u8; 32]);
    let ph_4 = Bytes32::new([4u8; 32]);
    assert!(
        !calls.iter().any(|(p, _)| *p == ph_3),
        "missing idx=3 must not appear in pay calls",
    );
    assert!(
        !calls.iter().any(|(p, _)| *p == ph_4),
        "missing idx=4 must not appear in pay calls",
    );
    assert!(calls.len() <= 3, "at most 3 in-view pay calls");
}

/// DSL-169 row 5: the new wiring preserves DSL-127 fixed 8-step
/// order.
///
/// Outcome-based ordering: epoch counters advance, inactivity
/// tracker resizes if validator_count changes, report shape
/// matches DSL-127 invariants. This is a regression guard — the
/// new in-line wiring must not disturb the existing step order.
#[test]
fn test_dsl_169_step_order_preserved() {
    let mut manager = SlashingManager::new(10);
    let mut participation = ParticipationTracker::new(4, 10);
    let mut inactivity = InactivityScoreTracker::new(4);
    let mut vset = build_validators(4);
    let balances = FixedBalances {
        balance: 32_000_000_000,
    };
    let mut escrow = NoopBond;
    let mut payout = RecordingPayout::default();
    let justification = FixedJustification { finalized: 10 };

    let report = run_epoch_boundary(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut vset,
        &balances,
        &mut escrow,
        &mut payout,
        &justification,
        10,
        6, // grow: triggers step 7 resize
        128_000_000_000,
    );

    // DSL-127 invariants preserved:
    assert_eq!(manager.current_epoch(), 11, "manager advanced");
    assert_eq!(
        participation.current_epoch_number(),
        11,
        "participation advanced",
    );
    assert_eq!(inactivity.validator_count(), 6, "inactivity resized");
    assert_eq!(report.flag_deltas.len(), 4, "one delta per tracker entry");
}
