//! Requirement DSL-172: coverage top-ups for genuinely-untested own-logic
//! branches surfaced by the `cargo llvm-cov` sweep.
//!
//! Traces to: docs/resources/SPEC.md §6.5 (adjudicator revert scope),
//! §16.5 (block admission dispatcher), §15.1 (ValidatorView contract).
//!
//! # Why this file exists
//!
//! The DSL-001..171 suite already drives the crate to ~95% line coverage.
//! This file closes the remaining MEANINGFUL gaps — real, spec-defined
//! branches that no existing test happened to exercise:
//!
//!   1. The `AppealVerdict::Rejected` no-op branch of the three
//!      sustained-revert adjudicator functions (DSL-064/065/066). On a
//!      rejected appeal each revert step MUST be a complete no-op: no
//!      `credit_stake`, no `restore_status`, no collateral `credit`.
//!   2. The `ValidatorNotInIntersection` per-index scoping branch of
//!      `adjudicate_sustained_restore_status` and
//!      `adjudicate_sustained_revert_collateral` (DSL-066/065) — the
//!      base-slash variant was covered by DSL-064 row 3, but the
//!      restore-status and collateral-revert variants were not.
//!   3. The APPEAL half of `process_block_admissions` (DSL-168): the
//!      appeal block-cap truncation branch and the appeal submit loop
//!      (both the rejected and the report-population paths). The
//!      existing DSL-168 suite only drives the evidence half.
//!   4. `ValidatorView::is_empty` default method (DSL contract on the
//!      trait) — never invoked by the suite.
//!
//! These are regression guards for behaviour that already works; they
//! are NOT filler. Each asserts an observable spec-defined outcome.

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_peer_protocol::Bytes32;
use dig_slashing::{
    AppealSustainReason, AppealVerdict, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag, Checkpoint,
    CollateralSlasher, IndexedAttestation, MAX_APPEALS_PER_BLOCK, OffenseType, PendingSlash,
    PendingSlashStatus, PerValidatorSlash, ProposerAppealGround, ProposerSlashing,
    ProposerSlashingAppeal, RewardPayout, SLASH_APPEAL_WINDOW_EPOCHS, SignedBlockHeader,
    SlashAppeal, SlashAppealPayload, SlashingError, SlashingEvidence, SlashingEvidencePayload,
    SlashingManager, ValidatorEntry, ValidatorView, VerifiedEvidence,
    adjudicate_sustained_restore_status, adjudicate_sustained_revert_base_slash,
    adjudicate_sustained_revert_collateral, encode_slash_appeal_remark_payload_v1,
    process_block_admissions,
};

// ── ValidatorEntry / ValidatorView mocks (record side effects) ─────────

struct RecValidator {
    pk: PublicKey,
    credits: RefCell<Vec<u64>>,
    restore_calls: RefCell<u32>,
    /// Each `restore_status` call returns this then it flips false so
    /// idempotence is observable; here we keep it constant per test.
    restore_returns: bool,
}

impl RecValidator {
    fn new(seed: u8, restore_returns: bool) -> Self {
        Self {
            pk: SecretKey::from_seed(&[seed; 32]).public_key(),
            credits: RefCell::new(Vec::new()),
            restore_calls: RefCell::new(0),
            restore_returns,
        }
    }
}

impl ValidatorEntry for RecValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        Bytes32::new([0u8; 32])
    }
    fn effective_balance(&self) -> u64 {
        32_000_000_000
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
    fn is_active_at_epoch(&self, _epoch: u64) -> bool {
        true
    }
    fn slash_absolute(&mut self, _: u64, _: u64) -> u64 {
        0
    }
    fn credit_stake(&mut self, amount_mojos: u64) -> u64 {
        self.credits.borrow_mut().push(amount_mojos);
        amount_mojos
    }
    fn restore_status(&mut self) -> bool {
        *self.restore_calls.borrow_mut() += 1;
        self.restore_returns
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct MapView(HashMap<u32, RecValidator>);

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

/// Collateral slasher spy: records every `credit(index, amount)`.
struct RecCollateral(RefCell<Vec<(u32, u64)>>);
impl CollateralSlasher for RecCollateral {
    fn credit(&mut self, validator_index: u32, amount_mojos: u64) {
        self.0.borrow_mut().push((validator_index, amount_mojos));
    }
}

// ── fixture builders ──────────────────────────────────────────────────

fn sample_header(idx: u32) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        5,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        idx,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn attester_evidence(indices: Vec<u32>) -> SlashingEvidence {
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
        attesting_indices: indices,
        data,
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0u8; 32]),
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

fn proposer_evidence(idx: u32) -> SlashingEvidence {
    let signed = SignedBlockHeader {
        message: sample_header(idx),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0u8; 32]),
        epoch: 5,
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: signed.clone(),
            signed_header_b: signed,
        }),
    }
}

/// `per_validator` = `(index, base_slash_amount, collateral_slashed)`.
fn pending_with(
    evidence: SlashingEvidence,
    offense: OffenseType,
    per_validator: Vec<(u32, u64, u64)>,
) -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([0xA1u8; 32]),
        evidence,
        verified: VerifiedEvidence {
            offense_type: offense,
            slashable_validator_indices: per_validator.iter().map(|(i, _, _)| *i).collect(),
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: per_validator
            .iter()
            .map(|(i, amt, coll)| PerValidatorSlash {
                validator_index: *i,
                base_slash_amount: *amt,
                effective_balance_at_slash: 32_000_000_000,
                collateral_slashed: *coll,
            })
            .collect(),
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    }
}

fn proposer_appeal(evidence_hash: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

fn attester_appeal(evidence_hash: Bytes32, ground: AttesterAppealGround) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 12,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground,
            witness: vec![],
        }),
    }
}

fn view_of(indices: &[(u32, bool)]) -> MapView {
    let mut m = HashMap::new();
    for (seed, (idx, restore)) in indices.iter().enumerate() {
        m.insert(*idx, RecValidator::new(seed as u8 + 1, *restore));
    }
    MapView(m)
}

// ══ 1. Rejected-verdict no-op branch of all three revert functions ══

/// DSL-172.1a: `revert_base_slash` on a Rejected verdict is a complete
/// no-op — returns empty, zero `credit_stake` calls.
#[test]
fn test_dsl_172_revert_base_slash_rejected_is_noop() {
    let pending = pending_with(
        proposer_evidence(7),
        OffenseType::ProposerEquivocation,
        vec![(7, 1_000_000_000, 0)],
    );
    let appeal = proposer_appeal(pending.evidence_hash);
    let verdict = AppealVerdict::Rejected {
        reason: dig_slashing::AppealRejectReason::GroundDoesNotHold,
    };
    let mut view = view_of(&[(7, false)]);

    let reverted = adjudicate_sustained_revert_base_slash(&pending, &appeal, &verdict, &mut view);

    assert!(reverted.is_empty(), "rejected verdict reverts nothing");
    assert!(
        view.0.get(&7).unwrap().credits.borrow().is_empty(),
        "no credit_stake on a rejected appeal",
    );
}

/// DSL-172.1b: `restore_status` on a Rejected verdict is a no-op —
/// returns empty, zero `restore_status` calls.
#[test]
fn test_dsl_172_restore_status_rejected_is_noop() {
    let pending = pending_with(
        proposer_evidence(7),
        OffenseType::ProposerEquivocation,
        vec![(7, 1_000_000_000, 0)],
    );
    let appeal = proposer_appeal(pending.evidence_hash);
    let verdict = AppealVerdict::Rejected {
        reason: dig_slashing::AppealRejectReason::GroundDoesNotHold,
    };
    let mut view = view_of(&[(7, true)]);

    let restored = adjudicate_sustained_restore_status(&pending, &appeal, &verdict, &mut view);

    assert!(restored.is_empty(), "rejected verdict restores nothing");
    assert_eq!(
        *view.0.get(&7).unwrap().restore_calls.borrow(),
        0,
        "restore_status MUST NOT be called on a rejected appeal",
    );
}

/// DSL-172.1c: `revert_collateral` on a Rejected verdict is a no-op —
/// returns empty, zero collateral `credit` calls.
#[test]
fn test_dsl_172_revert_collateral_rejected_is_noop() {
    let pending = pending_with(
        proposer_evidence(7),
        OffenseType::ProposerEquivocation,
        vec![(7, 1_000_000_000, 5_000_000_000)],
    );
    let appeal = proposer_appeal(pending.evidence_hash);
    let verdict = AppealVerdict::Rejected {
        reason: dig_slashing::AppealRejectReason::GroundDoesNotHold,
    };
    let mut coll = RecCollateral(RefCell::new(Vec::new()));

    let credited =
        adjudicate_sustained_revert_collateral(&pending, &appeal, &verdict, Some(&mut coll));

    assert!(
        credited.is_empty(),
        "rejected verdict credits no collateral"
    );
    assert!(
        coll.0.borrow().is_empty(),
        "no collateral credit on a rejected appeal",
    );
}

// ══ 2. ValidatorNotInIntersection per-index scoping (restore + collateral) ══

/// DSL-172.2a: `restore_status` with a sustained
/// `ValidatorNotInIntersection{index:3}` restores ONLY index 3; the
/// other slashed indices' `restore_status` is never called.
#[test]
fn test_dsl_172_restore_status_not_in_intersection_scopes_to_named() {
    let pending = pending_with(
        attester_evidence(vec![2, 3, 4]),
        OffenseType::AttesterDoubleVote,
        vec![
            (2, 200_000_000, 0),
            (3, 300_000_000, 0),
            (4, 400_000_000, 0),
        ],
    );
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::ValidatorNotInIntersection { validator_index: 3 },
    );
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::ValidatorNotInIntersection,
    };
    let mut view = view_of(&[(2, true), (3, true), (4, true)]);

    let restored = adjudicate_sustained_restore_status(&pending, &appeal, &verdict, &mut view);

    assert_eq!(restored, vec![3], "only the named index is restored");
    assert_eq!(*view.0.get(&2).unwrap().restore_calls.borrow(), 0);
    assert_eq!(*view.0.get(&3).unwrap().restore_calls.borrow(), 1);
    assert_eq!(*view.0.get(&4).unwrap().restore_calls.borrow(), 0);
}

/// DSL-172.2b: `restore_status` skips an index whose `restore_status()`
/// returns false (idempotent already-active) — it is called but absent
/// from the result.
#[test]
fn test_dsl_172_restore_status_skips_already_active() {
    let pending = pending_with(
        attester_evidence(vec![2, 3]),
        OffenseType::AttesterDoubleVote,
        vec![(2, 200_000_000, 0), (3, 300_000_000, 0)],
    );
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    };
    // index 2 returns true (transitioned), index 3 returns false (no-op).
    let mut view = view_of(&[(2, true), (3, false)]);

    let restored = adjudicate_sustained_restore_status(&pending, &appeal, &verdict, &mut view);

    assert_eq!(restored, vec![2], "only the index that changed state");
    assert_eq!(*view.0.get(&3).unwrap().restore_calls.borrow(), 1);
}

/// DSL-172.2c: `revert_collateral` with a sustained
/// `ValidatorNotInIntersection{index:3}` credits ONLY index 3's
/// collateral. Index 2 (also collateral-slashed) is left debited.
#[test]
fn test_dsl_172_revert_collateral_not_in_intersection_scopes_to_named() {
    let pending = pending_with(
        attester_evidence(vec![2, 3]),
        OffenseType::AttesterDoubleVote,
        vec![
            (2, 200_000_000, 2_000_000_000),
            (3, 300_000_000, 3_000_000_000),
        ],
    );
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::ValidatorNotInIntersection { validator_index: 3 },
    );
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::ValidatorNotInIntersection,
    };
    let mut coll = RecCollateral(RefCell::new(Vec::new()));

    let credited =
        adjudicate_sustained_revert_collateral(&pending, &appeal, &verdict, Some(&mut coll));

    assert_eq!(credited, vec![3], "only the named index's collateral");
    assert_eq!(
        coll.0.borrow().as_slice(),
        &[(3u32, 3_000_000_000u64)],
        "exactly one collateral credit, for index 3",
    );
}

/// DSL-172.2d: `revert_collateral` skips a zero-`collateral_slashed`
/// validator even when in scope (no observable no-op credit).
#[test]
fn test_dsl_172_revert_collateral_skips_zero_collateral() {
    let pending = pending_with(
        attester_evidence(vec![2, 3]),
        OffenseType::AttesterDoubleVote,
        // index 2 had collateral, index 3 had none.
        vec![(2, 200_000_000, 2_000_000_000), (3, 300_000_000, 0)],
    );
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    };
    let mut coll = RecCollateral(RefCell::new(Vec::new()));

    let credited =
        adjudicate_sustained_revert_collateral(&pending, &appeal, &verdict, Some(&mut coll));

    assert_eq!(credited, vec![2], "only the index with non-zero collateral");
    assert_eq!(coll.0.borrow().as_slice(), &[(2u32, 2_000_000_000u64)]);
}

// ══ 3. process_block_admissions — the APPEAL half ══

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
impl dig_slashing::ProposerView for FixedProposer {
    fn proposer_at_slot(&self, _: u64) -> Option<u32> {
        Some(0)
    }
    fn current_slot(&self) -> u64 {
        0
    }
}

struct EmptyBalances;
impl dig_slashing::EffectiveBalanceView for EmptyBalances {
    fn get(&self, _: u32) -> u64 {
        0
    }
    fn total_active(&self) -> u64 {
        0
    }
}

struct EmptyView;
impl ValidatorView for EmptyView {
    fn get(&self, _: u32) -> Option<&dyn ValidatorEntry> {
        None
    }
    fn get_mut(&mut self, _: u32) -> Option<&mut dyn ValidatorEntry> {
        None
    }
    fn len(&self) -> usize {
        0
    }
}

/// DSL-172.3a: an appeal REMARK whose evidence_hash is unknown to the
/// manager flows through the appeal submit loop and lands in
/// `rejected_appeals` with `UnknownEvidence`. Drives the previously
/// uncovered appeal submission branch of `process_block_admissions`.
#[test]
fn test_dsl_172_admissions_appeal_unknown_evidence_rejected() {
    let appeal = proposer_appeal(Bytes32::new([0xDEu8; 32]));
    let expected_hash = appeal.hash();
    let payloads = vec![encode_slash_appeal_remark_payload_v1(&appeal).expect("encode")];

    let mut mgr = SlashingManager::new(5);
    let mut view = EmptyView;
    let balances = EmptyBalances;
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &Bytes32::new([0xAAu8; 32]),
    );

    assert!(report.admitted_appeals.is_empty());
    assert_eq!(report.rejected_appeals.len(), 1);
    assert_eq!(report.rejected_appeals[0].0, expected_hash);
    assert!(matches!(
        report.rejected_appeals[0].1,
        SlashingError::UnknownEvidence(_),
    ));
    assert_eq!(report.cap_dropped_appeals, 0);
}

/// DSL-172.3b: more than `MAX_APPEALS_PER_BLOCK` appeal REMARKs in a
/// block triggers the appeal cap-drop branch. `cap_dropped_appeals`
/// counts the surplus; only the first MAX reach `submit_appeal`.
#[test]
fn test_dsl_172_admissions_appeal_cap_drops_excess() {
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    // Each appeal must hash distinctly — vary the evidence_hash byte.
    for i in 0..(MAX_APPEALS_PER_BLOCK + 7) {
        let appeal = proposer_appeal(Bytes32::new([i as u8; 32]));
        payloads.push(encode_slash_appeal_remark_payload_v1(&appeal).expect("encode"));
    }

    let mut mgr = SlashingManager::new(5);
    let mut view = EmptyView;
    let balances = EmptyBalances;
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &Bytes32::new([0xAAu8; 32]),
    );

    assert_eq!(report.cap_dropped_appeals, 7);
    // All surviving appeals reference unknown evidence → all rejected.
    assert_eq!(
        report.admitted_appeals.len() + report.rejected_appeals.len(),
        MAX_APPEALS_PER_BLOCK,
        "only the first MAX appeals reached submit_appeal",
    );
}

/// DSL-172.3c: an appeal REMARK referencing a pending slash already in
/// the book is admitted through `process_block_admissions` — its hash
/// lands in `admitted_appeals` (the previously-uncovered `Ok(())`
/// branch of the appeal submit loop). Pre-seeds the manager's book
/// via `book_mut().insert(..)` so `submit_appeal` finds the evidence.
#[test]
fn test_dsl_172_admissions_appeal_admitted() {
    let evidence_hash = Bytes32::new([0xB7u8; 32]);

    // Seed a pending slash with an Attester evidence so an Attester
    // appeal with the AttestationsIdentical ground matches variant +
    // window (filed_epoch 12 < window_expires 10 + WINDOW).
    let mut mgr = SlashingManager::new(100);
    let pending = PendingSlash {
        evidence_hash,
        evidence: attester_evidence(vec![1]),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![],
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    };
    mgr.book_mut().insert(pending).expect("fixture insert");

    let appeal = attester_appeal(evidence_hash, AttesterAppealGround::AttestationsIdentical);
    let expected_hash = appeal.hash();
    let payloads = vec![encode_slash_appeal_remark_payload_v1(&appeal).expect("encode")];

    let mut view = EmptyView;
    let balances = EmptyBalances;
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &Bytes32::new([0xAAu8; 32]),
    );

    assert_eq!(report.admitted_appeals, vec![expected_hash]);
    assert!(report.rejected_appeals.is_empty());
    assert_eq!(report.cap_dropped_appeals, 0);
}

// ══ 4. ValidatorView::is_empty default method ══

/// DSL-172.4: `ValidatorView::is_empty` reflects `len() == 0`. Exercises
/// the trait default provided for `Vec`-contract parity.
#[test]
fn test_dsl_172_validator_view_is_empty() {
    let empty = view_of(&[]);
    assert!(empty.is_empty(), "no registered validators → is_empty");
    assert_eq!(empty.len(), 0);

    let populated = view_of(&[(1, false), (2, false)]);
    assert!(!populated.is_empty(), "two validators → not empty");
    assert_eq!(populated.len(), 2);
}
