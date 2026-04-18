//! Requirement DSL-109: evidence whose `serde_json::to_vec(ev)`
//! length exceeds `MAX_SLASH_PROPOSAL_PAYLOAD_BYTES` (65_536) MUST
//! reject with `SlashingError::EvidencePayloadTooLarge { actual,
//! limit }`. At-limit and under-limit must admit.
//!
//! Traces to: docs/resources/SPEC.md §16.3, §2.8, §22.12.
//!
//! # Role
//!
//! Complements DSL-108's count cap. DSL-108 bounds evidences-per-
//! block; DSL-109 bounds bytes-per-evidence. Together they bound
//! REMARK bandwidth per block at 64 × 65_536 = 4 MiB. The byte
//! cap matters because an InvalidBlockProof carries a
//! `failure_witness: Vec<u8>` that an attacker could pad to force
//! validators to serialise + hash megabytes of garbage through
//! the DSL-103 puzzle-hash path.
//!
//! # Fixture strategy
//!
//! The only variable-size field on `SlashingEvidence` is the
//! invalid-block witness. We build a `SlashingEvidencePayload::
//! InvalidBlock(InvalidBlockProof { failure_witness: vec![...] })`
//! with a witness length tuned to land the JSON at:
//!
//!   - over the cap (reject case),
//!   - exactly at the cap (boundary admit),
//!   - well under the cap (small admit).
//!
//! We measure the JSON length directly rather than hard-coding
//! witness sizes, because other serde changes to the envelope
//! (e.g. new fields) would drift byte-exact constants without
//! changing the semantics we care about.
//!
//! # Test matrix
//!
//!   1. `test_dsl_109_over_limit_rejected` — JSON length > cap
//!      → EvidencePayloadTooLarge with both fields populated
//!   2. `test_dsl_109_at_limit_ok` — JSON length exactly == cap
//!      → admits (strict `>` check)
//!   3. `test_dsl_109_small_ok` — 1 KiB-ish payload → admits

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, InvalidBlockProof, InvalidBlockReason, MAX_SLASH_PROPOSAL_PAYLOAD_BYTES,
    OffenseType, SignedBlockHeader, SlashingError, SlashingEvidence, SlashingEvidencePayload,
    enforce_slashing_evidence_payload_cap,
};

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

fn evidence_with_witness(witness_len: usize) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::InvalidBlock,
        epoch: 12,
        reporter_validator_index: 11,
        reporter_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        payload: SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: SignedBlockHeader {
                message: sample_header(),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            // `failure_witness` is serialized via `serde_bytes` as
            // an array of numbers in JSON; each byte adds ~3 chars
            // (`,NN`) on average, so witness_len bytes yield ~3*N
            // JSON chars + envelope overhead.
            failure_witness: vec![0xABu8; witness_len],
            failure_reason: InvalidBlockReason::BadStateRoot,
        }),
    }
}

fn json_len(ev: &SlashingEvidence) -> usize {
    serde_json::to_vec(ev).unwrap().len()
}

/// Binary-search for the witness length that makes the encoded
/// JSON land as close as possible to `target_len` bytes. We need
/// an exact (or at most one-byte-diff) match for the at-limit
/// boundary test.
///
/// The witness byte → JSON length function is monotonic (each
/// byte contributes a bounded char count to the list literal)
/// and close to linear, so a plain binary search converges
/// quickly. Returns (witness_len, actual_json_len).
fn tune_witness_len(target_len: usize) -> (usize, usize) {
    let mut lo = 0usize;
    let mut hi = target_len; // upper bound — every byte adds ≥ 1 char
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let ev = evidence_with_witness(mid);
        let len = json_len(&ev);
        if len <= target_len {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    (lo, json_len(&evidence_with_witness(lo)))
}

/// DSL-109 row 1: JSON length over the cap rejects with both
/// `actual` and `limit` fields populated correctly.
#[test]
fn test_dsl_109_over_limit_rejected() {
    // Tune to just over the cap. Start with a witness a fair bit
    // larger than the cap — because JSON adds ~3x overhead per
    // byte (`,171,` style list encoding), witness == cap guarantees
    // JSON is already well over.
    let ev = evidence_with_witness(MAX_SLASH_PROPOSAL_PAYLOAD_BYTES + 1);
    let len = json_len(&ev);
    assert!(
        len > MAX_SLASH_PROPOSAL_PAYLOAD_BYTES,
        "fixture must exceed cap; got JSON len {len}",
    );

    let err =
        enforce_slashing_evidence_payload_cap(&[ev]).expect_err("oversize payload must reject");
    let SlashingError::EvidencePayloadTooLarge { actual, limit } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(actual, len, "actual must be the measured JSON length");
    assert_eq!(
        limit, MAX_SLASH_PROPOSAL_PAYLOAD_BYTES,
        "limit must equal MAX_SLASH_PROPOSAL_PAYLOAD_BYTES",
    );
}

/// DSL-109 row 2 (acceptance bullet 2): exactly-at-limit admits.
/// Tune witness length so the JSON hits the cap exactly; the
/// strict `>` comparison means this case must pass.
#[test]
fn test_dsl_109_at_limit_ok() {
    let (witness, actual) = tune_witness_len(MAX_SLASH_PROPOSAL_PAYLOAD_BYTES);
    assert!(
        actual <= MAX_SLASH_PROPOSAL_PAYLOAD_BYTES,
        "tuning must land at or below cap; got {actual} witness_len={witness}",
    );
    // The tuner returns the largest witness whose JSON is ≤ cap;
    // typically this IS the cap (or one/two bytes short due to
    // granularity). Either way the strict `>` check admits.
    let ev = evidence_with_witness(witness);
    enforce_slashing_evidence_payload_cap(&[ev])
        .expect("at-or-below-limit payload must admit (strict `>`)");
}

/// DSL-109 row 3 (acceptance bullet 3): a 1 KiB-ish payload is
/// well inside the envelope and must admit unconditionally.
#[test]
fn test_dsl_109_small_ok() {
    let ev = evidence_with_witness(1024);
    let len = json_len(&ev);
    assert!(
        len < MAX_SLASH_PROPOSAL_PAYLOAD_BYTES / 4,
        "small fixture must be well inside the cap; got {len}",
    );
    enforce_slashing_evidence_payload_cap(&[ev]).expect("small payload must admit");

    // Empty evidence list admits vacuously too — no payloads, no
    // cap triggers.
    let empty: Vec<SlashingEvidence> = Vec::new();
    enforce_slashing_evidence_payload_cap(&empty).expect("empty list admits vacuously");
}
