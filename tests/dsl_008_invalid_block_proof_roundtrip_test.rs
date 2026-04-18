//! Requirement DSL-008: `InvalidBlockProof` + `InvalidBlockReason`
//! serde round-trip byte-exactly, enumerate all 8 reason variants, and
//! `PartialEq` considers every field.
//!
//! Traces to: docs/resources/SPEC.md §3.4, §22.1.
//!
//! # Role
//!
//! `InvalidBlockProof` is the per-offense payload for `OffenseType::InvalidBlock`
//! (DSL-001). Carries:
//!
//!   - `signed_header` — the offending block header + its BLS signature
//!     (DSL-009).
//!   - `failure_witness` — caller-supplied bytes the `InvalidBlockOracle`
//!     (DSL-020) uses to reproduce the validation failure. Wire-size
//!     matters: encoded via `#[serde(with = "serde_bytes")]` for binary-format
//!     compactness.
//!   - `failure_reason` — categorical tag from `InvalidBlockReason`.
//!     Eight variants covering the distinct canonical-validation failure
//!     modes; also consumed by the `FailureReasonMismatch` appeal ground
//!     (DSL-051).
//!
//! # Test matrix (maps to DSL-008 Test Plan)
//!
//!   1. `test_dsl_008_all_reasons_enumerated` — all 8 variants constructable + roundtrip
//!   2. `test_dsl_008_bincode_roundtrip`
//!   3. `test_dsl_008_json_roundtrip`
//!   4. `test_dsl_008_witness_bytes_serde` — observable serde_bytes contract
//!   5. `test_dsl_008_partial_eq_signed_header` — mutation in header field
//!   6. `test_dsl_008_partial_eq_witness` — mutation in witness field
//!   7. `test_dsl_008_partial_eq_reason` — mutation in reason field

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{BLS_SIGNATURE_SIZE, InvalidBlockProof, InvalidBlockReason, SignedBlockHeader};

/// Canonical block header fixture.
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

fn sample() -> InvalidBlockProof {
    InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: sample_header(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        failure_witness: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        failure_reason: InvalidBlockReason::BadStateRoot,
    }
}

/// DSL-008 row 1: all 8 variants constructable + each round-trips through
/// bincode.
///
/// Exhaustive match on the return value of `all_reasons()` acts as a
/// compile-time guard — adding a 9th variant will make this test fail
/// to compile unless the match is updated, which is the intended review
/// gate on protocol-level enum changes.
#[test]
fn test_dsl_008_all_reasons_enumerated() {
    // Complete list — MUST stay in sync with the enum definition.
    let all = [
        InvalidBlockReason::BadStateRoot,
        InvalidBlockReason::BadParentRoot,
        InvalidBlockReason::BadTimestamp,
        InvalidBlockReason::BadProposerIndex,
        InvalidBlockReason::TransactionExecutionFailure,
        InvalidBlockReason::OverweightBlock,
        InvalidBlockReason::DuplicateTransaction,
        InvalidBlockReason::Other,
    ];
    assert_eq!(
        all.len(),
        8,
        "SPEC §3.4: exactly 8 InvalidBlockReason variants"
    );

    // Compile-time exhaustiveness guard — a new variant will make this
    // match non-exhaustive and block the build until updated.
    for r in all {
        match r {
            InvalidBlockReason::BadStateRoot
            | InvalidBlockReason::BadParentRoot
            | InvalidBlockReason::BadTimestamp
            | InvalidBlockReason::BadProposerIndex
            | InvalidBlockReason::TransactionExecutionFailure
            | InvalidBlockReason::OverweightBlock
            | InvalidBlockReason::DuplicateTransaction
            | InvalidBlockReason::Other => {}
        }
        // Each variant round-trips individually too.
        let bytes = bincode::serialize(&r).expect("bincode ser reason");
        let decoded: InvalidBlockReason = bincode::deserialize(&bytes).expect("bincode deser");
        assert_eq!(r, decoded);
    }
}

/// DSL-008 row 2: bincode round-trip preserves byte-exact equality.
#[test]
fn test_dsl_008_bincode_roundtrip() {
    let original = sample();
    let bytes = bincode::serialize(&original).expect("bincode ser");
    let decoded: InvalidBlockProof = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(original, decoded);
}

/// DSL-008 row 3: serde_json round-trip preserves equality.
#[test]
fn test_dsl_008_json_roundtrip() {
    let original = sample();
    let json = serde_json::to_vec(&original).expect("json ser");
    let decoded: InvalidBlockProof = serde_json::from_slice(&json).expect("json deser");
    assert_eq!(original, decoded);
}

/// DSL-008 row 4: `failure_witness` is annotated `#[serde(with =
/// "serde_bytes")]`, verified via observable round-trip fidelity.
///
/// Same framing caveat as DSL-009 `signature`: serde_json has no native
/// byte-string type so the JSON shape is still an integer array. The
/// observable contract is round-trip fidelity + addressable JSON field
/// plus compact bincode encoding. Real serde_bytes payoff surfaces in
/// DSL-102 / DSL-110 REMARK tests once CBOR / MessagePack paths exist.
#[test]
fn test_dsl_008_witness_bytes_serde() {
    let proof = sample();

    // Field present in JSON (not flattened).
    let v: serde_json::Value = serde_json::to_value(&proof).expect("json value");
    let _witness_field = v
        .get("failure_witness")
        .expect("failure_witness field present");

    // JSON round-trip preserves witness bytes exactly.
    let json = serde_json::to_vec(&proof).expect("json ser");
    let from_json: InvalidBlockProof = serde_json::from_slice(&json).expect("json deser");
    assert_eq!(from_json.failure_witness, proof.failure_witness);

    // bincode round-trip + compact size sanity.
    let bin = bincode::serialize(&proof).expect("bincode ser");
    let from_bin: InvalidBlockProof = bincode::deserialize(&bin).expect("bincode deser");
    assert_eq!(from_bin.failure_witness, proof.failure_witness);
    assert!(
        bin.len() < 1024,
        "bincode encoding must be compact; got {} bytes",
        bin.len(),
    );
}

/// DSL-008 row 5a: mutation in `signed_header` breaks `PartialEq`.
#[test]
fn test_dsl_008_partial_eq_signed_header() {
    let a = sample();
    let mut b = a.clone();
    b.signed_header.signature[0] ^= 0xFF;
    assert_ne!(a, b);
}

/// DSL-008 row 5b: mutation in `failure_witness` breaks `PartialEq`.
#[test]
fn test_dsl_008_partial_eq_witness() {
    let a = sample();
    let mut b = a.clone();
    b.failure_witness.push(0xFF);
    assert_ne!(a, b);

    // Even a single-bit flip breaks equality.
    let mut c = a.clone();
    c.failure_witness[0] ^= 0x01;
    assert_ne!(a, c);
}

/// DSL-008 row 5c: mutation in `failure_reason` breaks `PartialEq`.
///
/// Each pair-wise reason comparison proves the variant discriminant is
/// part of equality, not just field-wise content (`Copy` + `Eq` on the
/// enum makes this trivial but the test documents the contract).
#[test]
fn test_dsl_008_partial_eq_reason() {
    let a = sample();
    let mut b = a.clone();
    b.failure_reason = InvalidBlockReason::BadParentRoot;
    assert_ne!(a, b);

    // Every distinct pair is distinguishable.
    let reasons = [
        InvalidBlockReason::BadStateRoot,
        InvalidBlockReason::BadParentRoot,
        InvalidBlockReason::BadTimestamp,
        InvalidBlockReason::BadProposerIndex,
        InvalidBlockReason::TransactionExecutionFailure,
        InvalidBlockReason::OverweightBlock,
        InvalidBlockReason::DuplicateTransaction,
        InvalidBlockReason::Other,
    ];
    for (i, r1) in reasons.iter().enumerate() {
        for (j, r2) in reasons.iter().enumerate() {
            if i == j {
                assert_eq!(r1, r2);
            } else {
                assert_ne!(r1, r2, "{r1:?} must not equal {r2:?}");
            }
        }
    }
}
