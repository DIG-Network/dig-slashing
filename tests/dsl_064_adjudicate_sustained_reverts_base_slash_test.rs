//! Requirement DSL-064: on `AppealVerdict::Sustained`, the
//! adjudicator MUST credit each `PerValidatorSlash::base_slash_amount`
//! back to the validator's stake via
//! `ValidatorEntry::credit_stake(amount)`.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Role
//!
//! Opens the adjudicator section. First economic side-effect of
//! a sustained appeal: reverse the DSL-022 per-validator slash.
//! Scope branching:
//!   - `ValidatorNotInIntersection` → only the named index
//!     (DSL-047 per-validator appeal semantics).
//!   - Every other sustained reason → every slashed index.
//!
//! # Test matrix (maps to DSL-064 Test Plan)
//!
//!   1. `test_dsl_064_single_validator_credited` — ProposerSlashing
//!      sustained; `credit_stake` called once with the single
//!      index's `base_slash_amount`
//!   2. `test_dsl_064_multi_validator_credited` — AttesterSlashing
//!      sustained with 3 intersected validators; `credit_stake`
//!      called on all three
//!   3. `test_dsl_064_per_index_for_not_in_intersection` —
//!      `ValidatorNotInIntersection { validator_index }` → only
//!      the named index credited; other indices retain their debit

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealSustainReason, AppealVerdict, AttestationData, AttesterAppealGround, AttesterSlashing,
    AttesterSlashingAppeal, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation, InvalidBlockReason,
    OffenseType, PendingSlash, PendingSlashStatus, PerValidatorSlash, ProposerAppealGround,
    ProposerSlashing, ProposerSlashingAppeal, SLASH_APPEAL_WINDOW_EPOCHS, SignedBlockHeader,
    SlashAppeal, SlashAppealPayload, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry,
    ValidatorView, VerifiedEvidence, adjudicate_sustained_revert_base_slash,
};

/// ValidatorEntry mock that RECORDS every `credit_stake` call for
/// assertion.
struct RecValidator {
    pk: PublicKey,
    credits: RefCell<Vec<u64>>,
}

impl RecValidator {
    fn new(seed: u8) -> Self {
        Self {
            pk: SecretKey::from_seed(&[seed; 32]).public_key(),
            credits: RefCell::new(Vec::new()),
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
        false
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

// ── Evidence + PendingSlash builders ───────────────────────────────────

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

fn pending_with(
    evidence: SlashingEvidence,
    offense: OffenseType,
    per_validator: Vec<(u32, u64)>,
) -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([0xA1u8; 32]),
        evidence,
        verified: VerifiedEvidence {
            offense_type: offense,
            slashable_validator_indices: per_validator.iter().map(|(i, _)| *i).collect(),
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: per_validator
            .iter()
            .map(|(i, amt)| PerValidatorSlash {
                validator_index: *i,
                base_slash_amount: *amt,
                effective_balance_at_slash: 32_000_000_000,
                collateral_slashed: 0,
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

fn view_of(indices: Vec<u32>) -> MapView {
    let mut m = HashMap::new();
    for (seed, idx) in indices.iter().enumerate() {
        m.insert(*idx, RecValidator::new(seed as u8 + 1));
    }
    MapView(m)
}

/// DSL-064 row 1: ProposerSlashing sustained → single index
/// credited once with `base_slash_amount`.
#[test]
fn test_dsl_064_single_validator_credited() {
    let pending = pending_with(
        proposer_evidence(7),
        OffenseType::ProposerEquivocation,
        vec![(7, 1_000_000_000)],
    );
    let appeal = proposer_appeal(pending.evidence_hash);
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::HeadersIdentical,
    };
    let mut view = view_of(vec![7]);

    let reverted = adjudicate_sustained_revert_base_slash(&pending, &appeal, &verdict, &mut view);
    assert_eq!(reverted, vec![7]);

    let credits = view.0.get(&7).unwrap().credits.borrow();
    assert_eq!(credits.as_slice(), &[1_000_000_000]);
}

/// DSL-064 row 2: AttesterSlashing sustained on a non-per-
/// validator ground → EVERY index in `base_slash_per_validator`
/// credited (here: {2, 3, 4}). Each gets its own
/// `base_slash_amount`.
#[test]
fn test_dsl_064_multi_validator_credited() {
    let pending = pending_with(
        attester_evidence(vec![2, 3, 4]),
        OffenseType::AttesterDoubleVote,
        vec![(2, 200_000_000), (3, 300_000_000), (4, 400_000_000)],
    );
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::AttestationsIdentical,
    );
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    };
    let mut view = view_of(vec![2, 3, 4]);

    let reverted = adjudicate_sustained_revert_base_slash(&pending, &appeal, &verdict, &mut view);
    assert_eq!(reverted, vec![2, 3, 4]);

    assert_eq!(
        view.0.get(&2).unwrap().credits.borrow().as_slice(),
        &[200_000_000]
    );
    assert_eq!(
        view.0.get(&3).unwrap().credits.borrow().as_slice(),
        &[300_000_000]
    );
    assert_eq!(
        view.0.get(&4).unwrap().credits.borrow().as_slice(),
        &[400_000_000]
    );
}

/// DSL-064 row 3: `ValidatorNotInIntersection{ validator_index: 3 }`
/// → only index 3 credited; 2 and 4 retain their debit (no
/// `credit_stake` call recorded).
#[test]
fn test_dsl_064_per_index_for_not_in_intersection() {
    let pending = pending_with(
        attester_evidence(vec![2, 3, 4]),
        OffenseType::AttesterDoubleVote,
        vec![(2, 200_000_000), (3, 300_000_000), (4, 400_000_000)],
    );
    let appeal = attester_appeal(
        pending.evidence_hash,
        AttesterAppealGround::ValidatorNotInIntersection { validator_index: 3 },
    );
    let verdict = AppealVerdict::Sustained {
        reason: AppealSustainReason::ValidatorNotInIntersection,
    };
    let mut view = view_of(vec![2, 3, 4]);

    let reverted = adjudicate_sustained_revert_base_slash(&pending, &appeal, &verdict, &mut view);
    assert_eq!(reverted, vec![3]);

    assert!(
        view.0.get(&2).unwrap().credits.borrow().is_empty(),
        "index 2 MUST NOT be credited"
    );
    assert_eq!(
        view.0.get(&3).unwrap().credits.borrow().as_slice(),
        &[300_000_000]
    );
    assert!(
        view.0.get(&4).unwrap().credits.borrow().is_empty(),
        "index 4 MUST NOT be credited"
    );

    // Bind the unused InvalidBlockReason import (future DSLs in this
    // module will exercise invalid-block adjudication paths).
    let _ = InvalidBlockReason::BadStateRoot;
}
