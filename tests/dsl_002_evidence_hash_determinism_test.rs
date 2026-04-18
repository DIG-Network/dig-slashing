//! Requirement DSL-002: `SlashingEvidence::hash()` is the deterministic,
//! content-addressed identity of an evidence envelope. Same bytes in, same
//! `Bytes32` out — across process, build, and machine. Any single-field or
//! single-byte mutation MUST shift the hash.
//!
//! Traces to: docs/resources/SPEC.md §3.5, §2.10, §22.1.
//!
//! # Role
//!
//! The hash is the primary key for two runtime structures:
//!
//!   - `SlashingManager::processed` — dedup map keyed by evidence hash
//!     (DSL-026 AlreadySlashed short-circuit).
//!   - `BondEscrow::Reporter(hash)` — bond tag binding the reporter's
//!     escrowed bond to the specific evidence they submitted (DSL-023).
//!
//! If `hash()` were non-deterministic OR insensitive to any field, either
//! structure would silently corrupt: two honest nodes would disagree on
//! what's "already processed" (liveness fork) or a reporter could submit
//! a mutated envelope under a colliding key (economic attack).
//!
//! # Hash construction (SPEC §3.5)
//!
//!   `hash() = SHA256(DOMAIN_SLASHING_EVIDENCE || bincode::serialize(self))`
//!
//! Using `chia_sha2::Sha256` (not the plain `sha2` crate) — same hasher
//! backing attestation signing roots (DSL-004), proposer signatures, and
//! every other protocol digest. Domain tag prevents cross-context collision
//! with, e.g., an `AttestationData` that happens to serialize to the same
//! bytes under a different context.
//!
//! # Test matrix (maps to DSL-002 Test Plan)
//!
//!   1. `test_dsl_002_hash_deterministic` — idempotent on identical input
//!   2. `test_dsl_002_hash_changes_on_offense_type` — offense variant field
//!   3. `test_dsl_002_hash_changes_on_reporter_index` — reporter_validator_index
//!   4. `test_dsl_002_hash_changes_on_puzzle_hash` — reporter_puzzle_hash
//!   5. `test_dsl_002_hash_changes_on_epoch` — epoch scalar
//!   6. `test_dsl_002_hash_changes_on_payload_byte` — single byte in payload
//!   7. `test_dsl_002_domain_prefixed` — manual SHA-256 parity check
//!   8. `test_dsl_002_cross_variant_distinct` — Proposer/Attester/InvalidBlock
//!      envelopes with same scalar fields hash differently

use chia_sha2::Sha256;
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttesterSlashing, BLS_SIGNATURE_SIZE, DOMAIN_SLASHING_EVIDENCE, IndexedAttestation,
    InvalidBlockProof, InvalidBlockReason, OffenseType, ProposerSlashing, SignedBlockHeader,
    SlashingEvidence, SlashingEvidencePayload,
};

/// Canonical header — arbitrary but stable so hash determinism tests have
/// a well-defined baseline.
fn sample_header(height: u64, proposer_index: u32) -> L2BlockHeader {
    L2BlockHeader::new(
        height,
        3,
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

fn sample_signed_header(height: u64, proposer_index: u32) -> SignedBlockHeader {
    SignedBlockHeader {
        message: sample_header(height, proposer_index),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

fn sample_proposer_payload() -> SlashingEvidencePayload {
    SlashingEvidencePayload::Proposer(ProposerSlashing {
        signed_header_a: sample_signed_header(100, 9),
        signed_header_b: sample_signed_header(100, 9),
    })
}

fn sample_evidence() -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: 17,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 42,
        payload: sample_proposer_payload(),
    }
}

/// DSL-002 row 1: two `hash()` calls on the same envelope return byte-exact
/// equal `Bytes32`.
///
/// Trivial but load-bearing: `SlashingManager::processed` stores the first
/// hash and checks against the second; any non-determinism (pointer-address
/// leakage, iteration-order dependence on a `HashMap`) would manifest as
/// intermittent AlreadySlashed miss and duplicate slashing.
#[test]
fn test_dsl_002_hash_deterministic() {
    let evidence = sample_evidence();
    let h1 = evidence.hash();
    let h2 = evidence.hash();
    assert_eq!(h1, h2, "hash() must be deterministic across calls");

    // Re-clone + rehash — identity under Clone is implied but we test it so
    // that a future change to Clone semantics (e.g., accidental `Rc`) would
    // trip this test.
    let clone = evidence.clone();
    assert_eq!(evidence.hash(), clone.hash(), "Clone must preserve hash");
}

/// DSL-002 row 2: mutating `offense_type` shifts the hash.
#[test]
fn test_dsl_002_hash_changes_on_offense_type() {
    let a = sample_evidence();
    let mut b = a.clone();
    b.offense_type = OffenseType::InvalidBlock;
    assert_ne!(a.hash(), b.hash(), "offense_type must be part of the hash");

    // Every distinct variant hashes to a distinct value (no collision).
    let variants = [
        OffenseType::ProposerEquivocation,
        OffenseType::InvalidBlock,
        OffenseType::AttesterDoubleVote,
        OffenseType::AttesterSurroundVote,
    ];
    let mut hashes = Vec::with_capacity(variants.len());
    for v in variants {
        let mut e = a.clone();
        e.offense_type = v;
        hashes.push(e.hash());
    }
    for i in 0..hashes.len() {
        for j in i + 1..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "offense_type variants must hash distinctly: {:?} vs {:?}",
                variants[i], variants[j],
            );
        }
    }
}

/// DSL-002 row 3: mutating `reporter_validator_index` shifts the hash.
#[test]
fn test_dsl_002_hash_changes_on_reporter_index() {
    let a = sample_evidence();
    let mut b = a.clone();
    b.reporter_validator_index = a.reporter_validator_index + 1;
    assert_ne!(
        a.hash(),
        b.hash(),
        "reporter_validator_index must be part of the hash",
    );

    // Even a single-bit flip propagates.
    let mut c = a.clone();
    c.reporter_validator_index ^= 0x01;
    assert_ne!(a.hash(), c.hash(), "single-bit flip must shift hash");
}

/// DSL-002 row 4: mutating any byte of `reporter_puzzle_hash` shifts the hash.
#[test]
fn test_dsl_002_hash_changes_on_puzzle_hash() {
    let a = sample_evidence();

    // Every byte position is load-bearing.
    for byte_idx in 0..32 {
        let mut b = a.clone();
        let mut bytes = b.reporter_puzzle_hash.to_bytes();
        bytes[byte_idx] ^= 0xFF;
        b.reporter_puzzle_hash = Bytes32::new(bytes);
        assert_ne!(
            a.hash(),
            b.hash(),
            "puzzle_hash byte {byte_idx} mutation must shift hash",
        );
    }
}

/// DSL-002 row 5: mutating `epoch` shifts the hash.
#[test]
fn test_dsl_002_hash_changes_on_epoch() {
    let a = sample_evidence();
    let mut b = a.clone();
    b.epoch = a.epoch + 1;
    assert_ne!(a.hash(), b.hash(), "epoch must be part of the hash");

    // Single-bit flip propagates.
    let mut c = a.clone();
    c.epoch ^= 0x01;
    assert_ne!(a.hash(), c.hash());
}

/// DSL-002 row 6: mutating the payload (any field of any variant) shifts
/// the hash. Proves the enum discriminant + inner-variant bytes are both
/// part of the digest.
#[test]
fn test_dsl_002_hash_changes_on_payload_byte() {
    let a = sample_evidence();

    // Mutation inside Proposer payload: change signature byte.
    let mut b = a.clone();
    if let SlashingEvidencePayload::Proposer(p) = &mut b.payload {
        p.signed_header_a.signature[0] ^= 0xFF;
    } else {
        panic!("sample_evidence is Proposer");
    }
    assert_ne!(
        a.hash(),
        b.hash(),
        "payload signature-byte mutation must shift hash",
    );

    // Mutation of header field inside payload.
    let mut c = a.clone();
    if let SlashingEvidencePayload::Proposer(p) = &mut c.payload {
        p.signed_header_b = sample_signed_header(101, 9); // different height
    }
    assert_ne!(
        a.hash(),
        c.hash(),
        "payload header field mutation must shift hash",
    );
}

/// DSL-002 row 7: the hash MUST be SHA-256 of `DOMAIN_SLASHING_EVIDENCE ||
/// bincode(envelope)`. Rebuild the digest by hand and compare.
///
/// This locks the wire contract: an alternate implementation cannot drop
/// the domain tag or switch hashers without this test flipping.
#[test]
fn test_dsl_002_domain_prefixed() {
    let evidence = sample_evidence();
    let encoded = bincode::serialize(&evidence).expect("bincode ser");

    let mut h = Sha256::new();
    h.update(DOMAIN_SLASHING_EVIDENCE);
    h.update(&encoded);
    let expected = Bytes32::new(h.finalize());

    assert_eq!(
        evidence.hash(),
        expected,
        "hash must equal SHA-256(DOMAIN_SLASHING_EVIDENCE || bincode(envelope))",
    );

    // Negative: stripping the domain tag yields a DIFFERENT hash — proves
    // the tag is actually mixed in (not appended post-hash or ignored).
    let mut h_no_domain = Sha256::new();
    h_no_domain.update(&encoded);
    let no_domain = Bytes32::new(h_no_domain.finalize());
    assert_ne!(
        evidence.hash(),
        no_domain,
        "domain tag MUST be part of the digest input",
    );
}

/// DSL-002 row 8: two envelopes identical in scalar fields but carrying
/// different payload variants hash to distinct values. Guards against a
/// regression where the payload enum discriminant is dropped during
/// serialization (which would collapse Proposer/Attester/InvalidBlock into
/// the same hash and break `processed` dedup).
#[test]
fn test_dsl_002_cross_variant_distinct() {
    let proposer = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: 17,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 42,
        payload: sample_proposer_payload(),
    };

    // Minimal AttesterSlashing with an empty validator set — structurally
    // valid for hashing (validate_structure is not called here).
    let attester_payload = SlashingEvidencePayload::Attester(AttesterSlashing {
        attestation_a: IndexedAttestation {
            attesting_indices: vec![],
            data: sample_attestation_data(),
            signature: vec![0u8; BLS_SIGNATURE_SIZE],
        },
        attestation_b: IndexedAttestation {
            attesting_indices: vec![],
            data: sample_attestation_data(),
            signature: vec![0u8; BLS_SIGNATURE_SIZE],
        },
    });
    let attester = SlashingEvidence {
        payload: attester_payload,
        ..proposer.clone()
    };

    let invalid_block_payload = SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
        signed_header: sample_signed_header(100, 9),
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    });
    let invalid_block = SlashingEvidence {
        payload: invalid_block_payload,
        ..proposer.clone()
    };

    let hp = proposer.hash();
    let ha = attester.hash();
    let hi = invalid_block.hash();

    assert_ne!(hp, ha, "Proposer vs Attester must hash distinctly");
    assert_ne!(hp, hi, "Proposer vs InvalidBlock must hash distinctly");
    assert_ne!(ha, hi, "Attester vs InvalidBlock must hash distinctly");
}

fn sample_attestation_data() -> dig_slashing::AttestationData {
    use dig_slashing::{AttestationData, Checkpoint};
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x11u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}
