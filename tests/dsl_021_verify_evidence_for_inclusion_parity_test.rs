//! Requirement DSL-021: `verify_evidence_for_inclusion` produces a
//! byte-equal verdict to `verify_evidence` on identical inputs — the
//! mempool-admission wrapper performs the full DSL-011..020 chain
//! without any state mutation.
//!
//! Traces to: docs/resources/SPEC.md §5.5, §22.2.
//!
//! # Role
//!
//! REMARK admission (DSL-106) runs this to screen evidence envelopes
//! BEFORE a block is accepted. The two functions must agree on every
//! branch — any divergence is a mempool / consensus split.
//!
//! # Signature contract
//!
//! Both functions take `&dyn ValidatorView` (NOT `&mut`), guaranteeing
//! by type that no state mutation occurs. This test suite locks that
//! by: (a) running both functions on the same fixture, (b) asserting
//! byte-equal verdicts, (c) reusing the same `&` view for both calls
//! (if `&mut` were required the second call would not compile).
//!
//! # Test matrix (maps to DSL-021 Test Plan)
//!
//!   1. `test_dsl_021_parity_happy_path`           — valid evidence
//!   2. `test_dsl_021_parity_offense_too_old`
//!   3. `test_dsl_021_parity_reporter_is_accused`
//!   4. `test_dsl_021_parity_bls_fail`             — tampered sig
//!   5. `test_dsl_021_parity_attester_accepted`    — Attester payload
//!   6. `test_dsl_021_parity_invalid_block_accepted`
//!   7. `test_dsl_021_takes_shared_borrow`         — `&dyn` (no mut)

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, Checkpoint, IndexedAttestation, InvalidBlockProof,
    InvalidBlockReason, OffenseType, ProposerSlashing, SLASH_LOOKBACK_EPOCHS, SignedBlockHeader,
    SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry, ValidatorView,
    block_signing_message, verify_evidence, verify_evidence_for_inclusion,
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

// ── Fixtures ────────────────────────────────────────────────────────────

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

/// Valid proposer-slashing fixture (same pattern as DSL-013).
fn proposer_evidence(proposer_index: u32, reporter: u32) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk = make_sk(0x01);
    let pk = sk.public_key();
    let header_a = sample_header(proposer_index, 3, 0xA1);
    let header_b = sample_header(proposer_index, 3, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(proposer_index, TestValidator { pk });

    let ev = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 3,
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
    (ev, MapView(map))
}

/// Valid double-vote attester fixture.
fn attester_evidence(reporter: u32) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let mut map: HashMap<u32, TestValidator> = HashMap::new();
    let indices = [3u32, 5, 7];
    let data_a = AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0xA1u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    };
    let data_b = AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0xB2u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    };
    let sr_a = data_a.signing_root(&nid);
    let sr_b = data_b.signing_root(&nid);

    let mut sigs_a = Vec::new();
    let mut sigs_b = Vec::new();
    for idx in &indices {
        let sk = make_sk(*idx as u8);
        map.insert(
            *idx,
            TestValidator {
                pk: sk.public_key(),
            },
        );
        sigs_a.push(chia_bls::sign(&sk, sr_a.as_ref()));
        sigs_b.push(chia_bls::sign(&sk, sr_b.as_ref()));
    }
    let agg_a = chia_bls::aggregate(&sigs_a);
    let agg_b = chia_bls::aggregate(&sigs_b);

    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 3,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: IndexedAttestation {
                attesting_indices: indices.to_vec(),
                data: data_a,
                signature: agg_a.to_bytes().to_vec(),
            },
            attestation_b: IndexedAttestation {
                attesting_indices: indices.to_vec(),
                data: data_b,
                signature: agg_b.to_bytes().to_vec(),
            },
        }),
    };
    (ev, MapView(map))
}

/// Valid invalid-block fixture.
fn invalid_block_evidence(proposer_index: u32, reporter: u32) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header = sample_header(proposer_index, 3, 0xA1);
    let sig = sign_header(&sk, &header, &nid);

    let mut map = HashMap::new();
    map.insert(proposer_index, TestValidator { pk });

    let ev = SlashingEvidence {
        offense_type: OffenseType::InvalidBlock,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 3,
        payload: SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: SignedBlockHeader {
                message: header,
                signature: sig,
            },
            failure_witness: vec![1, 2, 3, 4],
            failure_reason: InvalidBlockReason::BadStateRoot,
        }),
    };
    (ev, MapView(map))
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-021 row 1: happy path — both functions produce byte-equal Ok
/// verdicts on valid evidence.
#[test]
fn test_dsl_021_parity_happy_path() {
    let (ev, view) = proposer_evidence(9, 42);
    let a = verify_evidence(&ev, &view, &network_id(), 3);
    let b = verify_evidence_for_inclusion(&ev, &view, &network_id(), 3);
    assert_eq!(a, b, "verdicts must match on valid evidence");
    assert!(a.is_ok());
}

/// DSL-021 row 2: OffenseTooOld surfaces identically.
#[test]
fn test_dsl_021_parity_offense_too_old() {
    let (ev, view) = proposer_evidence(9, 42);
    // current_epoch far enough that envelope.epoch=3 falls past the window.
    let current = 3 + SLASH_LOOKBACK_EPOCHS + 1;
    let a = verify_evidence(&ev, &view, &network_id(), current);
    let b = verify_evidence_for_inclusion(&ev, &view, &network_id(), current);
    assert_eq!(a, b);
    assert!(matches!(a, Err(SlashingError::OffenseTooOld { .. })));
}

/// DSL-021 row 3: ReporterIsAccused surfaces identically.
#[test]
fn test_dsl_021_parity_reporter_is_accused() {
    // Reporter = proposer → self-accuse.
    let (ev, view) = proposer_evidence(9, 9);
    let a = verify_evidence(&ev, &view, &network_id(), 3);
    let b = verify_evidence_for_inclusion(&ev, &view, &network_id(), 3);
    assert_eq!(a, b);
    assert_eq!(a, Err(SlashingError::ReporterIsAccused(9)));
}

/// DSL-021 row 4: BLS verify failure surfaces identically on both
/// paths — tampered signature in a proposer fixture.
#[test]
fn test_dsl_021_parity_bls_fail() {
    let (mut ev, view) = proposer_evidence(9, 42);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev.payload {
        p.signed_header_a.signature[0] ^= 0xFF;
    }
    let a = verify_evidence(&ev, &view, &network_id(), 3);
    let b = verify_evidence_for_inclusion(&ev, &view, &network_id(), 3);
    assert_eq!(a, b, "bad-sig verdicts must match");
    assert!(a.is_err());
}

/// DSL-021 row 5: Attester double-vote verdict parity.
#[test]
fn test_dsl_021_parity_attester_accepted() {
    let (ev, view) = attester_evidence(99);
    let a = verify_evidence(&ev, &view, &network_id(), 3);
    let b = verify_evidence_for_inclusion(&ev, &view, &network_id(), 3);
    assert_eq!(a, b);
    let verified = a.expect("attester must verify");
    assert_eq!(verified.slashable_validator_indices, vec![3, 5, 7]);
}

/// DSL-021 row 6: InvalidBlock verdict parity.
#[test]
fn test_dsl_021_parity_invalid_block_accepted() {
    let (ev, view) = invalid_block_evidence(9, 99);
    let a = verify_evidence(&ev, &view, &network_id(), 3);
    let b = verify_evidence_for_inclusion(&ev, &view, &network_id(), 3);
    assert_eq!(a, b);
    assert!(a.is_ok());
}

/// DSL-021 row 7: `&dyn ValidatorView` (no `&mut`) is enforced by the
/// signature. Call `verify_evidence_for_inclusion` TWICE with the
/// SAME shared borrow — if `&mut` were required, this would not
/// compile. Compile-time check; the assertion is trivially true.
#[test]
fn test_dsl_021_takes_shared_borrow() {
    let (ev, view) = proposer_evidence(9, 42);
    let borrow: &dyn ValidatorView = &view;
    // Two consecutive calls through the SAME shared borrow.
    let first = verify_evidence_for_inclusion(&ev, borrow, &network_id(), 3);
    let second = verify_evidence_for_inclusion(&ev, borrow, &network_id(), 3);
    assert_eq!(first, second, "deterministic across shared-borrow calls");
    // Also: bad-fixture mismatches surface identically.
    let (mut ev_bad, view_bad) = proposer_evidence(9, 42);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev_bad.payload {
        p.signed_header_b.message = p.signed_header_a.message.clone();
    }
    let bad1 = verify_evidence_for_inclusion(&ev_bad, &view_bad, &network_id(), 3);
    let bad2 = verify_evidence(&ev_bad, &view_bad, &network_id(), 3);
    assert_eq!(bad1, bad2);
}
