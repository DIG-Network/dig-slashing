//! Requirement DSL-117: mempool rejects appeals whose payload
//! variant disagrees with the pending evidence's payload variant
//! via `SlashingError::AppealVariantMismatch`.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Mempool pre-filter upstream of DSL-057 manager variant check.
//! The three valid pairings are:
//!
//!   - Appeal::Proposer     ↔ Evidence::Proposer
//!   - Appeal::Attester     ↔ Evidence::Attester
//!   - Appeal::InvalidBlock ↔ Evidence::InvalidBlock
//!
//! Any cross-pairing is a protocol error — the appeal logic
//! branches per variant and mis-targeted witnesses cannot prove
//! anything about the wrong evidence.
//!
//! # Test matrix (maps to DSL-117 Test Plan + acceptance)
//!
//!   1. `test_dsl_117_proposer_vs_attester` — ProposerAppeal
//!      against AttesterSlashing → AppealVariantMismatch
//!   2. `test_dsl_117_attester_vs_invalid` — AttesterAppeal
//!      against InvalidBlockProof → AppealVariantMismatch
//!   3. `test_dsl_117_invalid_vs_proposer` — InvalidBlockAppeal
//!      against ProposerSlashing → AppealVariantMismatch
//!   4. `test_dsl_117_each_match_ok` — every matching variant
//!      pair admits
//!   5. `test_dsl_117_unknown_hash_skipped` — absent hash is
//!      DSL-114's responsibility, not this fn's

use std::collections::HashMap;

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterAppealGround, AttesterSlashing, AttesterSlashingAppeal,
    BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation, InvalidBlockAppeal,
    InvalidBlockAppealGround, InvalidBlockProof, InvalidBlockReason, ProposerAppealGround,
    ProposerSlashing, ProposerSlashingAppeal, SignedBlockHeader, SlashAppeal, SlashAppealPayload,
    SlashingError, SlashingEvidencePayload, enforce_slash_appeal_variant_policy,
};

fn sample_header(state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_byte; 32]),
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

fn proposer_evidence() -> SlashingEvidencePayload {
    SlashingEvidencePayload::Proposer(ProposerSlashing {
        signed_header_a: SignedBlockHeader {
            message: sample_header(0x02),
            signature: vec![0u8; BLS_SIGNATURE_SIZE],
        },
        signed_header_b: SignedBlockHeader {
            message: sample_header(0x99),
            signature: vec![0u8; BLS_SIGNATURE_SIZE],
        },
    })
}

fn attester_evidence() -> SlashingEvidencePayload {
    let att = IndexedAttestation {
        attesting_indices: vec![1, 2, 3],
        data: AttestationData {
            slot: 10,
            index: 0,
            beacon_block_root: Bytes32::new([0xAAu8; 32]),
            source: Checkpoint {
                epoch: 1,
                root: Bytes32::new([0xBBu8; 32]),
            },
            target: Checkpoint {
                epoch: 2,
                root: Bytes32::new([0xCCu8; 32]),
            },
        },
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidencePayload::Attester(AttesterSlashing {
        attestation_a: att.clone(),
        attestation_b: att,
    })
}

fn invalid_block_evidence() -> SlashingEvidencePayload {
    SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: sample_header(0x02),
            signature: vec![0u8; BLS_SIGNATURE_SIZE],
        },
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    })
}

fn proposer_appeal(h: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: h,
        appellant_index: 11,
        appellant_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

fn attester_appeal(h: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: h,
        appellant_index: 11,
        appellant_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![],
        }),
    }
}

fn invalid_appeal(h: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: h,
        appellant_index: 11,
        appellant_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::InvalidBlock(InvalidBlockAppeal {
            ground: InvalidBlockAppealGround::BlockActuallyValid,
            witness: vec![],
        }),
    }
}

/// DSL-117 row 1: ProposerAppeal against AttesterSlashing.
#[test]
fn test_dsl_117_proposer_vs_attester() {
    let h = Bytes32::new([0x11u8; 32]);
    let mut map = HashMap::new();
    map.insert(h, attester_evidence());

    let err = enforce_slash_appeal_variant_policy(&[proposer_appeal(h)], &map)
        .expect_err("cross-variant must reject");
    assert!(matches!(err, SlashingError::AppealVariantMismatch));
}

/// DSL-117 row 2: AttesterAppeal against InvalidBlockProof.
#[test]
fn test_dsl_117_attester_vs_invalid() {
    let h = Bytes32::new([0x22u8; 32]);
    let mut map = HashMap::new();
    map.insert(h, invalid_block_evidence());

    let err = enforce_slash_appeal_variant_policy(&[attester_appeal(h)], &map)
        .expect_err("cross-variant must reject");
    assert!(matches!(err, SlashingError::AppealVariantMismatch));
}

/// DSL-117 row 3: InvalidBlockAppeal against ProposerSlashing.
#[test]
fn test_dsl_117_invalid_vs_proposer() {
    let h = Bytes32::new([0x33u8; 32]);
    let mut map = HashMap::new();
    map.insert(h, proposer_evidence());

    let err = enforce_slash_appeal_variant_policy(&[invalid_appeal(h)], &map)
        .expect_err("cross-variant must reject");
    assert!(matches!(err, SlashingError::AppealVariantMismatch));
}

/// DSL-117 row 4: every matching permutation admits. Verifies
/// the positive path is exhaustive — a regression collapsing
/// one match arm into another would fail here.
#[test]
fn test_dsl_117_each_match_ok() {
    let h_p = Bytes32::new([0x44u8; 32]);
    let h_a = Bytes32::new([0x55u8; 32]);
    let h_i = Bytes32::new([0x66u8; 32]);
    let mut map = HashMap::new();
    map.insert(h_p, proposer_evidence());
    map.insert(h_a, attester_evidence());
    map.insert(h_i, invalid_block_evidence());

    enforce_slash_appeal_variant_policy(&[proposer_appeal(h_p)], &map).expect("P-P admits");
    enforce_slash_appeal_variant_policy(&[attester_appeal(h_a)], &map).expect("A-A admits");
    enforce_slash_appeal_variant_policy(&[invalid_appeal(h_i)], &map).expect("I-I admits");
}

/// Edge: hash absent from the evidence-variant map is DSL-114's
/// responsibility. Must skip here so DSL-114's error is surfaced
/// by the caller's policy chain, not masked by this one.
#[test]
fn test_dsl_117_unknown_hash_skipped() {
    let unknown = Bytes32::new([0x77u8; 32]);
    let map: HashMap<Bytes32, SlashingEvidencePayload> = HashMap::new();
    enforce_slash_appeal_variant_policy(&[proposer_appeal(unknown)], &map)
        .expect("unknown hash is DSL-114's job");
}
