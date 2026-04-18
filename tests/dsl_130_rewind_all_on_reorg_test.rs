//! Requirement DSL-130: `rewind_all_on_reorg` is the global
//! reorg orchestrator. Rewinds (in order):
//!
//!   1. `SlashingManager::rewind_on_reorg` (DSL-129)
//!   2. `ParticipationTracker::rewind_on_reorg`
//!   3. `InactivityScoreTracker::rewind_on_reorg`
//!   4. `SlashingProtection::reconcile_with_chain_tip` (DSL-099)
//!
//! Depth > `CORRELATION_WINDOW_EPOCHS` (36) → `SlashingError::ReorgTooDeep`.
//! Depth == 36 → accepted (boundary).
//!
//! Traces to: docs/resources/SPEC.md §13, §22.15.
//!
//! # Role
//!
//! Closes Phase 8 Orchestration. The chain-shell orchestrator
//! calls this on detection of a fork-choice reorg to drop every
//! slashing-related side effect that attached to the now-orphan
//! chain.
//!
//! # Test matrix (maps to DSL-130 Test Plan + acceptance)
//!
//!   1. `test_dsl_130_all_four_rewound` — each subsystem's
//!      rewind fires, state reflects post-rewind invariants
//!   2. `test_dsl_130_reorg_too_deep` — depth=37 rejects with
//!      ReorgTooDeep { depth, limit }
//!   3. `test_dsl_130_boundary_36` — depth == 36 admits
//!      (strict `>` check)
//!   4. `test_dsl_130_report_populated` — ReorgReport carries
//!      rewound hashes + epoch-drop counts + protection flag

use std::cell::RefCell;

use chia_bls::PublicKey;
use dig_protocol::Bytes32;
use dig_slashing::{
    BondError, BondEscrow, BondTag, CollateralSlasher, InactivityScoreTracker,
    ParticipationTracker, ReorgReport, SlashingError, SlashingManager, SlashingProtection,
    ValidatorEntry, ValidatorView, rewind_all_on_reorg,
};

// ── Minimal trait impls ─────────────────────────────────────

struct FakeValidator {
    pk: PublicKey,
    ph: Bytes32,
    eff_bal: RefCell<u64>,
    is_slashed: RefCell<bool>,
}
impl ValidatorEntry for FakeValidator {
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
    fn slash_absolute(&mut self, amount: u64, _: u64) -> u64 {
        let mut bal = self.eff_bal.borrow_mut();
        let actual = amount.min(*bal);
        *bal -= actual;
        *self.is_slashed.borrow_mut() = true;
        actual
    }
    fn credit_stake(&mut self, amount: u64) -> u64 {
        *self.eff_bal.borrow_mut() += amount;
        amount
    }
    fn restore_status(&mut self) -> bool {
        let changed = *self.is_slashed.borrow();
        *self.is_slashed.borrow_mut() = false;
        changed
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct FakeValidatorSet {
    entries: Vec<FakeValidator>,
}
impl ValidatorView for FakeValidatorSet {
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

struct SpyCollateral {
    credits: RefCell<Vec<(u32, u64)>>,
}
impl CollateralSlasher for SpyCollateral {
    fn credit(&mut self, idx: u32, amount: u64) {
        self.credits.borrow_mut().push((idx, amount));
    }
}

fn vset(n: usize) -> FakeValidatorSet {
    FakeValidatorSet {
        entries: (0..n)
            .map(|_| FakeValidator {
                pk: PublicKey::default(),
                ph: Bytes32::new([0u8; 32]),
                eff_bal: RefCell::new(32_000_000_000),
                is_slashed: RefCell::new(false),
            })
            .collect(),
    }
}

/// DSL-130 row 1: all four subsystems rewound.
///
/// Pre-seed state so each subsystem has something to rewind:
///   - protection has a stored attestation → rewind clears
///   - inactivity has non-zero score → rewind zeroes
///   - participation rotated forward → rewind returns depth
///
/// Manager's own rewind is already covered by DSL-129; here we
/// check that `rewind_all_on_reorg` INVOKES it (state visible
/// via `current_epoch` ending up at `new_tip_epoch`).
#[test]
fn test_dsl_130_all_four_rewound() {
    let mut manager = SlashingManager::new(50);
    let mut participation = ParticipationTracker::new(4, 50);
    let mut inactivity = InactivityScoreTracker::new(4);
    let mut protection = SlashingProtection::new();
    // Seed protection state so we can observe the clear.
    protection.record_attestation(3, 5, &Bytes32::new([0xAAu8; 32]));
    // Seed inactivity.
    inactivity.set_score(0, 42);
    inactivity.set_score(1, 99);

    let mut vs = vset(4);
    let mut escrow = NoopBond;

    let report = rewind_all_on_reorg(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut protection,
        &mut vs,
        None,
        &mut escrow,
        /* new_tip_epoch */ 45,
        /* new_tip_slot */ 100,
        /* validator_count */ 4,
    )
    .expect("depth 5 must be under CORRELATION_WINDOW_EPOCHS=36");

    // Step 1: manager epoch anchored at new tip.
    assert_eq!(manager.current_epoch(), 45);

    // Step 2: participation rotated to new tip with zeroed flags.
    assert_eq!(participation.current_epoch_number(), 45);

    // Step 3: inactivity scores zeroed.
    assert_eq!(inactivity.score(0), Some(0));
    assert_eq!(inactivity.score(1), Some(0));

    // Step 4: protection reconciled — hash cleared, epochs
    // capped at new tip.
    assert!(protection.last_attested_block_hash().is_none());
    assert_eq!(protection.last_attested_source_epoch(), 3);
    assert_eq!(protection.last_attested_target_epoch(), 5);

    assert!(report.protection_rewound);
}

/// DSL-130 row 2: depth = 37 → ReorgTooDeep with both fields
/// populated. No state mutation.
#[test]
fn test_dsl_130_reorg_too_deep() {
    let mut manager = SlashingManager::new(40);
    let mut participation = ParticipationTracker::new(4, 40);
    let mut inactivity = InactivityScoreTracker::new(4);
    let mut protection = SlashingProtection::new();
    inactivity.set_score(0, 42);
    let mut vs = vset(4);
    let mut escrow = NoopBond;

    // depth = 40 - 3 = 37 > 36.
    let err = rewind_all_on_reorg(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut protection,
        &mut vs,
        None,
        &mut escrow,
        3,
        100,
        4,
    )
    .expect_err("depth 37 must reject");

    let SlashingError::ReorgTooDeep { depth, limit } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(depth, 37);
    assert_eq!(limit, 36);

    // No state mutation: scores preserved.
    assert_eq!(inactivity.score(0), Some(42));
    assert_eq!(manager.current_epoch(), 40, "manager epoch unchanged");
}

/// DSL-130 row 3: depth == 36 admits (strict `>` check).
#[test]
fn test_dsl_130_boundary_36() {
    let mut manager = SlashingManager::new(40);
    let mut participation = ParticipationTracker::new(4, 40);
    let mut inactivity = InactivityScoreTracker::new(4);
    let mut protection = SlashingProtection::new();
    let mut vs = vset(4);
    let mut escrow = NoopBond;

    rewind_all_on_reorg(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut protection,
        &mut vs,
        None,
        &mut escrow,
        /* new_tip_epoch = 40 - 36 = */ 4,
        50,
        4,
    )
    .expect("depth 36 must admit");

    assert_eq!(manager.current_epoch(), 4);
}

/// DSL-130 row 4: ReorgReport fields populated. The `rewound_pending_slashes`
/// vec is empty here (no pending slashes staged) but the field
/// EXISTS and is readable; the epoch_dropped fields carry the
/// caller-computed depth.
#[test]
fn test_dsl_130_report_populated() {
    let mut manager = SlashingManager::new(20);
    let mut participation = ParticipationTracker::new(4, 20);
    let mut inactivity = InactivityScoreTracker::new(4);
    let mut protection = SlashingProtection::new();
    let mut vs = vset(4);
    let mut escrow = NoopBond;
    let mut coll = SpyCollateral {
        credits: RefCell::new(Vec::new()),
    };

    let report: ReorgReport = rewind_all_on_reorg(
        &mut manager,
        &mut participation,
        &mut inactivity,
        &mut protection,
        &mut vs,
        Some(&mut coll),
        &mut escrow,
        15,
        30,
        4,
    )
    .unwrap();

    // No pending slashes — empty vec.
    assert!(report.rewound_pending_slashes.is_empty());
    // depth = 20 - 15 = 5, carried through both counters.
    assert_eq!(report.participation_epochs_dropped, 5);
    assert_eq!(report.inactivity_epochs_dropped, 5);
    // Protection rewound flag always true on successful path.
    assert!(report.protection_rewound);
}
