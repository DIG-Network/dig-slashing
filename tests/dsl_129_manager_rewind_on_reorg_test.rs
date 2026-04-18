//! Requirement DSL-129: `SlashingManager::rewind_on_reorg` must,
//! for every `PendingSlash` with `submitted_at_epoch > new_tip_epoch`:
//!
//!   - `credit_stake` each slashable validator (via
//!     `ValidatorEntry`)
//!   - `restore_status` each slashable validator
//!   - `CollateralSlasher::credit` per validator (when collateral
//!     present)
//!   - release reporter bond in FULL (NOT forfeit — reorg is not
//!     the reporter's fault)
//!   - remove entry from `processed` + `slashed_in_window`
//!   - return the rewound `evidence_hash` list
//!
//! Traces to: docs/resources/SPEC.md §13, §22.15.
//!
//! # Role
//!
//! Distinct from DSL-064 sustained-appeal revert: that path
//! applies a reporter penalty (DSL-069) because the reporter's
//! evidence was proven wrong. A reorg is a consensus-layer
//! signal that the original offense was never canonical, so
//! the reporter is not at fault — bond released intact.
//!
//! # Test matrix (maps to DSL-129 Test Plan + acceptance)
//!
//!   1. `test_dsl_129_credits_stake` — credit_stake called on
//!      each slashable validator
//!   2. `test_dsl_129_restores_collateral` — CollateralSlasher::credit
//!      called per validator when supplied
//!   3. `test_dsl_129_releases_bond_full` — bond escrow observes
//!      `release` (NOT forfeit) at `BondTag::Reporter(hash)`
//!   4. `test_dsl_129_removes_from_processed` — post-rewind
//!      `is_processed(hash) == false` AND `is_slashed_in_window`
//!      cleared
//!   5. `test_dsl_129_no_reporter_penalty` — reporter validator
//!      stake unchanged (no secondary slash applied)
//!   6. `test_dsl_129_returns_hashes` — return value contains
//!      every rewound hash; pre-tip slashes unaffected

use std::cell::RefCell;

use chia_bls::PublicKey;
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealAttempt, AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE, BondError, BondEscrow,
    BondTag, Checkpoint, CollateralSlasher, IndexedAttestation, OffenseType, PendingSlash,
    PendingSlashStatus, PerValidatorSlash, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, SlashingManager, ValidatorEntry, ValidatorView, VerifiedEvidence,
};

// ── Spy traits ──────────────────────────────────────────────

/// Records which method (release vs forfeit) was called, for
/// which (principal, tag, amount) tuple. DSL-129 MUST call
/// `release` — a `forfeit` would confiscate the reporter's bond,
/// which is semantically wrong for a reorg.
#[derive(Default)]
struct SpyBondEscrow {
    releases: RefCell<Vec<(u32, u64, BondTag)>>,
    forfeits: RefCell<Vec<(u32, u64, BondTag)>>,
}
impl BondEscrow for SpyBondEscrow {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn release(&mut self, principal: u32, amount: u64, tag: BondTag) -> Result<(), BondError> {
        self.releases.borrow_mut().push((principal, amount, tag));
        Ok(())
    }
    fn forfeit(&mut self, principal: u32, amount: u64, tag: BondTag) -> Result<u64, BondError> {
        self.forfeits.borrow_mut().push((principal, amount, tag));
        Ok(amount)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

/// Records every `credit(idx, amount)` call.
#[derive(Default)]
struct SpyCollateral {
    credits: RefCell<Vec<(u32, u64)>>,
}
impl CollateralSlasher for SpyCollateral {
    fn credit(&mut self, validator_index: u32, amount_mojos: u64) {
        self.credits
            .borrow_mut()
            .push((validator_index, amount_mojos));
    }
}

struct FakeValidator {
    pk: PublicKey,
    ph: Bytes32,
    eff_bal: RefCell<u64>,
    is_slashed: RefCell<bool>,
    credit_calls: RefCell<Vec<u64>>,
    restore_calls: RefCell<usize>,
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
        self.credit_calls.borrow_mut().push(amount);
        *self.eff_bal.borrow_mut() += amount;
        amount
    }
    fn restore_status(&mut self) -> bool {
        *self.restore_calls.borrow_mut() += 1;
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

fn fresh_validator(eff_bal: u64, slashed: bool) -> FakeValidator {
    FakeValidator {
        pk: PublicKey::default(),
        ph: Bytes32::new([0u8; 32]),
        eff_bal: RefCell::new(eff_bal),
        is_slashed: RefCell::new(slashed),
        credit_calls: RefCell::new(Vec::new()),
        restore_calls: RefCell::new(0),
    }
}

// ── Fixture: manager with one pre-staged PendingSlash ───────

fn sample_header() -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        9,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

/// Stage a PendingSlash for validator 7 submitted at `epoch`.
/// Returns the evidence_hash for downstream assertions.
fn stage_pending(
    manager: &mut SlashingManager,
    submitted_at_epoch: u64,
    validator_index: u32,
    base_slash_amount: u64,
    collateral_slashed: u64,
) -> Bytes32 {
    // Unique hash derived from (epoch, idx) to avoid collisions
    // across multi-stage fixtures.
    let mut hash_bytes = [0u8; 32];
    hash_bytes[0] = submitted_at_epoch as u8;
    hash_bytes[1] = validator_index as u8;
    let evidence_hash = Bytes32::new(hash_bytes);

    let evidence = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        epoch: submitted_at_epoch.saturating_sub(1),
        reporter_validator_index: 11,
        reporter_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: SignedBlockHeader {
                message: sample_header(),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            signed_header_b: SignedBlockHeader {
                message: sample_header(),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
        }),
    };

    let pending = PendingSlash {
        evidence_hash,
        evidence,
        verified: VerifiedEvidence {
            offense_type: OffenseType::ProposerEquivocation,
            slashable_validator_indices: vec![validator_index],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch,
        window_expires_at_epoch: submitted_at_epoch + 8,
        base_slash_per_validator: vec![PerValidatorSlash {
            validator_index,
            base_slash_amount,
            effective_balance_at_slash: 32_000_000_000,
            collateral_slashed,
        }],
        reporter_bond_mojos: 500_000_000,
        appeal_history: Vec::<AppealAttempt>::new(),
    };

    manager.book_mut().insert(pending).expect("book insert");
    manager.mark_processed(evidence_hash, submitted_at_epoch);
    manager.mark_slashed_in_window(submitted_at_epoch, validator_index, 32_000_000_000);

    evidence_hash
}

/// DSL-129 row 1: credit_stake called on each slashable validator.
#[test]
fn test_dsl_129_credits_stake() {
    let mut manager = SlashingManager::new(20);
    let hash = stage_pending(&mut manager, 15, 7, 1_000_000, 0);

    let mut vset = FakeValidatorSet {
        entries: (0..8)
            .map(|_| fresh_validator(32_000_000_000, true))
            .collect(),
    };
    let mut escrow = SpyBondEscrow::default();

    let rewound = manager.rewind_on_reorg(10, &mut vset, None, &mut escrow);
    assert_eq!(rewound, vec![hash]);

    let calls = vset.entries[7].credit_calls.borrow();
    assert_eq!(calls.len(), 1, "credit_stake called once on validator 7");
    assert_eq!(
        calls[0], 1_000_000,
        "credit amount matches base_slash_amount"
    );
}

/// DSL-129 row 2: CollateralSlasher::credit fires per validator
/// when supplied; omitted when None.
#[test]
fn test_dsl_129_restores_collateral() {
    let mut manager = SlashingManager::new(20);
    let _ = stage_pending(&mut manager, 15, 7, 1_000_000, 2_000_000);

    let mut vset = FakeValidatorSet {
        entries: (0..8)
            .map(|_| fresh_validator(32_000_000_000, true))
            .collect(),
    };
    let mut escrow = SpyBondEscrow::default();
    let mut coll = SpyCollateral::default();

    manager.rewind_on_reorg(10, &mut vset, Some(&mut coll), &mut escrow);

    let credits = coll.credits.borrow();
    assert_eq!(credits.len(), 1);
    assert_eq!(credits[0], (7, 2_000_000), "collateral restored");
}

/// DSL-129 row 3: reporter bond observed `release`, NOT `forfeit`.
/// This is THE load-bearing distinction vs DSL-068 sustained-appeal.
#[test]
fn test_dsl_129_releases_bond_full() {
    let mut manager = SlashingManager::new(20);
    let hash = stage_pending(&mut manager, 15, 7, 1_000_000, 0);

    let mut vset = FakeValidatorSet {
        entries: (0..8)
            .map(|_| fresh_validator(32_000_000_000, true))
            .collect(),
    };
    let mut escrow = SpyBondEscrow::default();

    manager.rewind_on_reorg(10, &mut vset, None, &mut escrow);

    let releases = escrow.releases.borrow();
    let forfeits = escrow.forfeits.borrow();
    assert_eq!(releases.len(), 1, "release called exactly once");
    assert!(forfeits.is_empty(), "NO forfeit on reorg path");
    assert_eq!(
        releases[0],
        (11, 500_000_000, BondTag::Reporter(hash)),
        "release: (reporter_idx=11, amount=bond, tag=Reporter(hash))",
    );
}

/// DSL-129 row 4: post-rewind `processed` and `slashed_in_window`
/// are cleared for the rewound hash.
#[test]
fn test_dsl_129_removes_from_processed() {
    let mut manager = SlashingManager::new(20);
    let hash = stage_pending(&mut manager, 15, 7, 1_000_000, 0);

    assert!(manager.is_processed(&hash), "precondition: processed");
    assert!(
        manager.is_slashed_in_window(15, 7),
        "precondition: slashed_in_window populated",
    );

    let mut vset = FakeValidatorSet {
        entries: (0..8)
            .map(|_| fresh_validator(32_000_000_000, true))
            .collect(),
    };
    let mut escrow = SpyBondEscrow::default();
    manager.rewind_on_reorg(10, &mut vset, None, &mut escrow);

    assert!(
        !manager.is_processed(&hash),
        "processed map cleared for rewound hash",
    );
    assert!(
        !manager.is_slashed_in_window(15, 7),
        "slashed_in_window row cleared",
    );
}

/// DSL-129 row 5: reporter validator stake is NOT debited. DSL-069
/// applies a reporter penalty on sustained-appeal; reorg does not.
#[test]
fn test_dsl_129_no_reporter_penalty() {
    let mut manager = SlashingManager::new(20);
    let _ = stage_pending(&mut manager, 15, 7, 1_000_000, 0);

    let mut vset = FakeValidatorSet {
        entries: (0..12)
            .map(|_| fresh_validator(32_000_000_000, false))
            .collect(),
    };
    let reporter_initial = *vset.entries[11].eff_bal.borrow();
    let mut escrow = SpyBondEscrow::default();
    manager.rewind_on_reorg(10, &mut vset, None, &mut escrow);

    assert_eq!(
        *vset.entries[11].eff_bal.borrow(),
        reporter_initial,
        "reporter stake unchanged — no secondary slash on reorg",
    );
    // And restore_status NOT called on the reporter either.
    assert_eq!(
        *vset.entries[11].restore_calls.borrow(),
        0,
        "reporter restore_status NOT called (reporter was never slashed)",
    );
}

/// DSL-129 row 6: returns the list of rewound hashes; pre-tip
/// slashes are left alone.
#[test]
fn test_dsl_129_returns_hashes() {
    let mut manager = SlashingManager::new(20);
    // One pre-tip slash (submitted at 5, won't be rewound at tip=10).
    let pre = stage_pending(&mut manager, 5, 3, 1_000_000, 0);
    // Two post-tip slashes.
    let post_a = stage_pending(&mut manager, 15, 7, 1_000_000, 0);
    let post_b = stage_pending(&mut manager, 18, 9, 2_000_000, 0);

    let mut vset = FakeValidatorSet {
        entries: (0..12)
            .map(|_| fresh_validator(32_000_000_000, true))
            .collect(),
    };
    let mut escrow = SpyBondEscrow::default();
    let rewound = manager.rewind_on_reorg(10, &mut vset, None, &mut escrow);

    assert_eq!(rewound.len(), 2, "only post-tip slashes rewound");
    assert!(rewound.contains(&post_a));
    assert!(rewound.contains(&post_b));
    assert!(!rewound.contains(&pre), "pre-tip slash preserved");

    // Pre-tip slash still in processed / slashed_in_window.
    assert!(manager.is_processed(&pre));
    assert!(manager.is_slashed_in_window(5, 3));
}

// Silence dead-code warnings for AttesterSlashing/Checkpoint/etc.
// unused in this test (kept for fixture-consistency across the
// DSL-NNN family).
#[allow(dead_code)]
fn _imports_keepalive() -> (
    AttesterSlashing,
    Checkpoint,
    AttestationData,
    IndexedAttestation,
) {
    unimplemented!()
}
