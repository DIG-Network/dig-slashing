//! Requirement DSL-066: on `AppealVerdict::Sustained`, the
//! adjudicator MUST call `ValidatorEntry::restore_status()` per
//! reverted validator. Transitions Slashed → Active.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Role
//!
//! Third economic side-effect of a sustained appeal (after
//! DSL-064 stake revert + DSL-065 collateral revert). Without
//! `restore_status` a validator credited back to full balance
//! would still carry the `Slashed` flag — consensus would keep
//! rejecting their attestations.
//!
//! # Test matrix (maps to DSL-066 Test Plan)
//!
//!   1. `test_dsl_066_restore_status_called` — Sustained appeal
//!      → `restore_status` call recorded on the reverted index
//!   2. `test_dsl_066_slashed_to_active` — pre-state
//!      `is_slashed() == true`; post-call `is_slashed() == false`
//!   3. `test_dsl_066_multi_validator` — AttesterSlashing with
//!      3 indices → 3 `restore_status` calls

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealSustainReason, AppealVerdict, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation, OffenseType,
    PendingSlash, PendingSlashStatus, PerValidatorSlash, SLASH_APPEAL_WINDOW_EPOCHS, SlashAppeal,
    SlashAppealPayload, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry, ValidatorView,
    VerifiedEvidence, adjudicate_sustained_restore_status,
};

/// Validator that tracks Slashed flag + records every
/// `restore_status` call for assertion.
struct RecValidator {
    pk: PublicKey,
    slashed: RefCell<bool>,
    restore_calls: RefCell<u32>,
}

impl RecValidator {
    fn slashed_starting() -> Self {
        Self {
            pk: SecretKey::from_seed(&[0x01u8; 32]).public_key(),
            slashed: RefCell::new(true),
            restore_calls: RefCell::new(0),
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
        *self.slashed.borrow()
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
        *self.restore_calls.borrow_mut() += 1;
        let was_slashed = *self.slashed.borrow();
        *self.slashed.borrow_mut() = false;
        was_slashed
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

fn pending_with(indices: Vec<u32>) -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([0xA1u8; 32]),
        evidence: attester_evidence(indices.clone()),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: indices.clone(),
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: indices
            .iter()
            .map(|i| PerValidatorSlash {
                validator_index: *i,
                base_slash_amount: 1_000_000_000,
                effective_balance_at_slash: 32_000_000_000,
                collateral_slashed: 0,
            })
            .collect(),
        reporter_bond_mojos: 0,
        appeal_history: vec![],
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

fn view_slashed(indices: Vec<u32>) -> MapView {
    let mut m = HashMap::new();
    for idx in indices {
        m.insert(idx, RecValidator::slashed_starting());
    }
    MapView(m)
}

fn sustained_identical() -> AppealVerdict {
    AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    }
}

/// DSL-066 row 1: single reverted index → exactly one
/// `restore_status` call recorded. Adjudicator returns the
/// restored index in the result vec.
#[test]
fn test_dsl_066_restore_status_called() {
    let pending = pending_with(vec![7]);
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let mut view = view_slashed(vec![7]);

    let restored =
        adjudicate_sustained_restore_status(&pending, &appeal, &sustained_identical(), &mut view);
    assert_eq!(restored, vec![7]);

    assert_eq!(*view.0.get(&7).unwrap().restore_calls.borrow(), 1);
}

/// DSL-066 row 2: pre-state `is_slashed() == true`; post-call
/// `is_slashed() == false`. `restore_status` return value is
/// propagated through the adjudicator's result vec (only `true`
/// returns appear).
#[test]
fn test_dsl_066_slashed_to_active() {
    let pending = pending_with(vec![7]);
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let mut view = view_slashed(vec![7]);

    assert!(view.0.get(&7).unwrap().is_slashed(), "pre-state Slashed");

    let restored =
        adjudicate_sustained_restore_status(&pending, &appeal, &sustained_identical(), &mut view);
    assert_eq!(restored, vec![7], "restore_status returned true");

    assert!(
        !view.0.get(&7).unwrap().is_slashed(),
        "post-call Active (is_slashed() == false)"
    );
}

/// DSL-066 row 3: AttesterSlashing with indices {2, 3, 4} → 3
/// `restore_status` calls, one per index. Iteration order follows
/// `base_slash_per_validator` (DSL-007 sorted intersection).
#[test]
fn test_dsl_066_multi_validator() {
    let pending = pending_with(vec![2, 3, 4]);
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let mut view = view_slashed(vec![2, 3, 4]);

    let restored =
        adjudicate_sustained_restore_status(&pending, &appeal, &sustained_identical(), &mut view);
    assert_eq!(restored, vec![2, 3, 4]);

    for idx in [2u32, 3, 4] {
        assert_eq!(
            *view.0.get(&idx).unwrap().restore_calls.borrow(),
            1,
            "index {idx} restore_status called exactly once",
        );
        assert!(!view.0.get(&idx).unwrap().is_slashed());
    }
}
