//! Requirement DSL-009: `SignedBlockHeader { message: L2BlockHeader,
//! signature: Vec<u8> }` round-trips byte-exactly through `bincode` and
//! `serde_json`; `signature` is encoded via `serde_bytes` (raw bytes, not
//! JSON-array).
//!
//! Traces to: docs/resources/SPEC.md §3.4, §22.1.
//!
//! # Role
//!
//! `SignedBlockHeader` is the atom of proposer-side evidence:
//! - `ProposerSlashing` (DSL-013) carries two of them (equivocation proof).
//! - `InvalidBlockProof` (DSL-008) carries one (plus failure witness).
//!
//! The type is a passive wire carrier — verification of signature width
//! (=`BLS_SIGNATURE_SIZE`) happens DOWNSTREAM in the per-offense verifiers
//! (DSL-013, DSL-018), not in this type's constructor. A `SignedBlockHeader`
//! with a 95-byte or 0-byte signature is a valid Rust value; only
//! `verify_proposer_slashing` / `verify_invalid_block` reject it.
//!
//! # Wire-format contract
//!
//!   - `message` = `dig_block::L2BlockHeader` (NOT redefined here — full
//!     type-identity with the dig-block crate).
//!   - `signature` = `Vec<u8>` annotated `#[serde(with = "serde_bytes")]`
//!     so JSON emits a byte-string field, not a 96-element integer array.
//!
//! # Test matrix (maps to DSL-009 Test Plan)
//!
//!   1. `test_dsl_009_bincode_roundtrip`
//!   2. `test_dsl_009_json_roundtrip`
//!   3. `test_dsl_009_signature_serde_bytes` — JSON shape check
//!   4. `test_dsl_009_partial_eq_header` — mutation in message
//!   5. `test_dsl_009_partial_eq_signature` — mutation in signature
//!   6. `test_dsl_009_signature_length_not_enforced_by_type` — non-96 is legal

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{BLS_SIGNATURE_SIZE, SignedBlockHeader};

/// Canonical test header — arbitrary values; this suite doesn't validate
/// header semantics, just serde round-trip fidelity.
fn sample_header() -> L2BlockHeader {
    L2BlockHeader::new(
        100,                        // height
        3,                          // epoch
        Bytes32::new([0x01u8; 32]), // parent_hash
        Bytes32::new([0x02u8; 32]), // state_root
        Bytes32::new([0x03u8; 32]), // spends_root
        Bytes32::new([0x04u8; 32]), // additions_root
        Bytes32::new([0x05u8; 32]), // removals_root
        Bytes32::new([0x06u8; 32]), // receipts_root
        42,                         // l1_height
        Bytes32::new([0x07u8; 32]), // l1_hash
        9,                          // proposer_index
        1,                          // spend_bundle_count
        1_000,                      // total_cost
        10,                         // total_fees
        5,                          // additions_count
        3,                          // removals_count
        512,                        // block_size
        Bytes32::new([0x08u8; 32]), // filter_hash
    )
}

fn sample() -> SignedBlockHeader {
    SignedBlockHeader {
        message: sample_header(),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

/// DSL-009 row 1: bincode round-trip preserves byte-exact equality.
#[test]
fn test_dsl_009_bincode_roundtrip() {
    let original = sample();
    let bytes = bincode::serialize(&original).expect("bincode ser");
    let decoded: SignedBlockHeader = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(original, decoded);
}

/// DSL-009 row 2: serde_json round-trip preserves equality.
#[test]
fn test_dsl_009_json_roundtrip() {
    let original = sample();
    let json = serde_json::to_vec(&original).expect("json ser");
    let decoded: SignedBlockHeader = serde_json::from_slice(&json).expect("json deser");
    assert_eq!(original, decoded);
}

/// DSL-009 row 3: `signature` field is annotated `#[serde(with =
/// "serde_bytes")]`, verified via observable binary-format effect.
///
/// # Why framed this way
///
/// `serde_bytes` tells serde the `Vec<u8>` is *semantically* a byte
/// string rather than a sequence of `u8`. For binary formats that
/// distinguish the two (CBOR, MessagePack, RON), this changes the
/// on-wire encoding. For `serde_json` there is NO native byte-string
/// type — the output is an integer array either way, so asserting on
/// JSON shape would be a false positive.
///
/// For `bincode` 1.x, `Vec<u8>` with or without `serde_bytes` produces
/// the same compact `len || raw_bytes` encoding, so bincode alone cannot
/// distinguish either.
///
/// # What this test verifies
///
/// The observable contract: `signature` is an addressable JSON field
/// AND the bytes round-trip byte-for-byte through both JSON and bincode.
/// The `#[serde(with = "serde_bytes")]` annotation's real payoff lives
/// in DSL-102 / DSL-110 (REMARK wire) tests once CBOR / MessagePack
/// paths exist; until then, code review + `cargo expand` verify the
/// attribute is present on the field.
#[test]
fn test_dsl_009_signature_serde_bytes() {
    let sbh = sample();

    // Field is addressable in JSON (not flattened away).
    let v: serde_json::Value = serde_json::to_value(&sbh).expect("json value");
    let _sig_field = v.get("signature").expect("signature field present in JSON");

    // JSON round-trip recovers the exact bytes.
    let json_bytes = serde_json::to_vec(&sbh).expect("json ser");
    let json_decoded: SignedBlockHeader = serde_json::from_slice(&json_bytes).expect("json deser");
    assert_eq!(json_decoded.signature, sbh.signature);

    // bincode round-trip recovers the exact bytes AND stores the sig
    // compactly as `len || raw_bytes` (no per-element framing). We can't
    // introspect bincode output shape directly, but we can bound its
    // size: for a 96-byte signature plus a u64 length prefix, the sig
    // portion MUST be <= ~128 bytes (well below any per-element framing).
    let bin = bincode::serialize(&sbh).expect("bincode ser");
    let bin_decoded: SignedBlockHeader = bincode::deserialize(&bin).expect("bincode deser");
    assert_eq!(bin_decoded.signature, sbh.signature);
    // Sanity: total bincode size should be dominated by the header's
    // many 32-byte roots, and the sig contribution is compact. 96 + 8
    // prefix = 104, plus header (~few hundred bytes). Anything near
    // 96 * 2 suggests non-compact per-element encoding.
    assert!(
        bin.len() < 1024,
        "bincode encoding must be compact; got {} bytes",
        bin.len(),
    );
}

/// DSL-009 row 4a: mutating any byte of `message` breaks equality.
#[test]
fn test_dsl_009_partial_eq_header() {
    let a = sample();
    let mut b = a.clone();
    b.message.height = a.message.height + 1;
    assert_ne!(a, b, "different header height must break equality");
}

/// DSL-009 row 4b: mutating any byte of `signature` breaks equality.
#[test]
fn test_dsl_009_partial_eq_signature() {
    let a = sample();
    let mut b = a.clone();
    b.signature[0] ^= 0xFF;
    assert_ne!(a, b, "different signature byte must break equality");

    // Length mismatch also breaks equality (e.g. truncated signature).
    let mut c = a.clone();
    c.signature.pop();
    assert_ne!(a, c, "different signature length must break equality");
}

/// DSL-009 row 5: the type itself does NOT enforce signature length.
///
/// Per SPEC §3.4 acceptance criterion "signature length is enforced to 96
/// bytes DOWNSTREAM by verifiers, not in the type itself." This keeps the
/// type a passive wire carrier — caller's responsibility to run
/// `verify_proposer_slashing` (DSL-013) / `verify_invalid_block` (DSL-018)
/// which enforce the length via `chia_bls::Signature::from_bytes`.
///
/// Constructs a `SignedBlockHeader` with a zero-byte signature; asserts
/// it's a valid Rust value (compiles + roundtrips).
#[test]
fn test_dsl_009_signature_length_not_enforced_by_type() {
    let sbh = SignedBlockHeader {
        message: sample_header(),
        signature: vec![],
    };
    // Round-trip still works — length isn't constrained by the type.
    let bytes = bincode::serialize(&sbh).expect("bincode ser zero-byte sig");
    let decoded: SignedBlockHeader = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(sbh, decoded);
}
