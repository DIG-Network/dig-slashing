//! Requirement DSL-019: `verify_invalid_block` rejects evidence when
//! `signed_header.message.epoch != evidence.epoch`, returning
//! `SlashingError::InvalidSlashingEvidence("epoch mismatch: ...")`.
//!
//! Traces to: docs/resources/SPEC.md §5.4, §22.2.
//!
//! # Role
//!
//! The envelope's `epoch` field drives the DSL-011 lookback check AND
//! the DSL-030 correlation window. If it disagrees with the header's
//! epoch, either the reporter is buggy (different offense than claimed)
//! or an adversary is trying to replay an old envelope under a new
//! lookback. Reject with the cheapest scalar compare BEFORE any BLS
//! work.
//!
//! # Ordering
//!
//! Runs FIRST in `verify_invalid_block` — even ahead of witness size
//! check, signature decode, and BLS pairing. Mirrors DSL-016 ordering
//! principle (cheapest filter first).
//!
//! # Mirrors
//!
//! Appeal ground `InvalidBlockAppeal::EvidenceEpochMismatch` (DSL-052)
//! uses the same predicate.
//!
//! # Test matrix (maps to DSL-019 Test Plan)
//!
//!   1. `test_dsl_019_matching_epochs_accepted`
//!   2. `test_dsl_019_mismatch_rejected`
//!   3. `test_dsl_019_error_message_includes_both`
//!   4. `test_dsl_019_runs_before_bls` — mismatched + bad sig → epoch
//!      mismatch wins, not BLS-verify failure

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, InvalidBlockProof, InvalidBlockReason, OffenseType, SignedBlockHeader,
    SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry, ValidatorView,
    block_signing_message, verify_evidence,
};

// ── Validator fixtures ──────────────────────────────────────────────────

struct TestValidator {
    pk: PublicKey,
}

impl ValidatorEntry for TestValidator {
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

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn sample_header(proposer_index: u32, epoch: u64) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        epoch,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
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

fn sign_with(sk: &SecretKey, header: &L2BlockHeader, nid: &Bytes32) -> Vec<u8> {
    let msg = block_signing_message(nid, header.epoch, &header.hash(), header.proposer_index);
    chia_bls::sign(sk, msg).to_bytes().to_vec()
}

/// Build an invalid-block envelope with separately-controlled
/// `envelope.epoch` and `header.epoch`.
fn evidence_with_epochs(
    proposer_index: u32,
    envelope_epoch: u64,
    header_epoch: u64,
) -> (SlashingEvidence, MapView) {
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header = sample_header(proposer_index, header_epoch);
    let sig = sign_with(&sk, &header, &network_id());

    let mut map = HashMap::new();
    map.insert(proposer_index, TestValidator { pk });

    let ev = SlashingEvidence {
        offense_type: OffenseType::InvalidBlock,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: envelope_epoch,
        payload: SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: SignedBlockHeader {
                message: header,
                signature: sig,
            },
            failure_witness: vec![1, 2, 3, 4, 5],
            failure_reason: InvalidBlockReason::BadStateRoot,
        }),
    };
    (ev, MapView(map))
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-019 row 1: matching epochs pass the check (and the rest of the
/// pipeline, on honest fixtures).
#[test]
fn test_dsl_019_matching_epochs_accepted() {
    let (ev, view) = evidence_with_epochs(9, 3, 3);
    let verified =
        verify_evidence(&ev, &view, &network_id(), 3).expect("matching epochs must verify");
    assert_eq!(verified.offense_type, OffenseType::InvalidBlock);
}

/// DSL-019 row 2: mismatched epochs rejected as
/// `InvalidSlashingEvidence("epoch mismatch: ...")`.
#[test]
fn test_dsl_019_mismatch_rejected() {
    let (ev, view) = evidence_with_epochs(9, 3, 4); // envelope 3, header 4
    // current_epoch ≥ max(3, 4) to keep DSL-011 happy.
    let err = verify_evidence(&ev, &view, &network_id(), 4).expect_err("mismatch must reject");
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(ref s) if s.contains("epoch mismatch")),
        "got {err:?}",
    );
}

/// DSL-019 row 3: error message includes BOTH the envelope epoch and
/// the header epoch for adjudicator diagnosis (DSL-052 appeal ground
/// needs both values to reconstruct the violation).
#[test]
fn test_dsl_019_error_message_includes_both() {
    let (ev, view) = evidence_with_epochs(9, 7, 10);
    let err = verify_evidence(&ev, &view, &network_id(), 10).unwrap_err();
    match err {
        SlashingError::InvalidSlashingEvidence(s) => {
            assert!(
                s.contains("header=10") && s.contains("envelope=7"),
                "message must include both epochs; got: {s}",
            );
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

/// DSL-019 row 4: ordering — mismatched epoch + deliberately corrupt
/// signature → epoch mismatch wins (BLS never attempted).
///
/// If BLS ran first, we'd see `bad invalid-block signature`. If epoch
/// check ran first, we see `epoch mismatch`.
#[test]
fn test_dsl_019_runs_before_bls() {
    let (mut ev, view) = evidence_with_epochs(9, 3, 4);
    if let SlashingEvidencePayload::InvalidBlock(p) = &mut ev.payload {
        // Corrupt sig: all 0xFF → decode may succeed or fail; either
        // way, if BLS ran before epoch, we'd get a non-"epoch mismatch"
        // error.
        p.signed_header.signature = vec![0xFFu8; BLS_SIGNATURE_SIZE];
    }
    let err = verify_evidence(&ev, &view, &network_id(), 4).unwrap_err();
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(ref s) if s.contains("epoch mismatch")),
        "epoch check MUST run before BLS; got {err:?}",
    );
}

/// DSL-019: symmetric case — header epoch LARGER than envelope epoch
/// also rejected (predicate is `!=`, not a one-sided comparison).
#[test]
fn test_dsl_019_mismatch_reversed() {
    let (ev, view) = evidence_with_epochs(9, 10, 5);
    let err = verify_evidence(&ev, &view, &network_id(), 10).unwrap_err();
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(ref s) if s.contains("epoch mismatch")),
        "reversed mismatch must also reject; got {err:?}",
    );
}
