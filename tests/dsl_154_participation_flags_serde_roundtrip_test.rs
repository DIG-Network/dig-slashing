//! Requirement DSL-154: `ParticipationFlags(u8)` round-trips
//! byte-exactly via `bincode` and `serde_json`.
//!
//! Traces to: docs/resources/SPEC.md §3.10, §18.
//!
//! # Role
//!
//! `ParticipationFlags` is a 3-bit bitmask (TIMELY_SOURCE,
//! TIMELY_TARGET, TIMELY_HEAD) wrapping a single `u8`. It appears
//! in:
//!
//!   - `EpochBoundaryReport` → per-validator reward / penalty
//!     decisions serialised for metrics + audit.
//!   - `ReorgReport` → post-rewind state snapshots.
//!   - On-disk tracker snapshots (consumer-side persistence).
//!
//! Byte-exact roundtrip is therefore load-bearing — any drift in
//! the serde contract would silently corrupt reward math on a
//! node that snapshot-restores from disk. Also required so a
//! bincode-encoded `Vec<ParticipationFlags>` matches the raw
//! `&[u8]` layout of the underlying tracker vector.
//!
//! # Test matrix (maps to DSL-154 Test Plan)
//!
//!   1. `test_dsl_154_bincode_roundtrip` — bincode ser/deser for
//!      a single `ParticipationFlags` → equal + wire is 1 byte.
//!   2. `test_dsl_154_json_roundtrip` — serde_json ser/deser +
//!      wire shape asserted (plain integer, not object).
//!   3. `test_dsl_154_vec_roundtrip` — `Vec<ParticipationFlags>`
//!      preserves order + per-element value.
//!   4. `test_dsl_154_all_bit_patterns` — every `u8` value in
//!      0..=255 roundtrips identically under both codecs. Covers
//!      the 3 defined bits + 5 reserved bits — serde MUST NOT
//!      mask reserved bits, since future protocol upgrades may
//!      claim them (bit 3+ currently "RESERVED" per DSL-074).

use dig_slashing::{
    ParticipationFlags, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};

/// DSL-154 row 1: bincode roundtrip of a single value preserves
/// both the byte value AND the 1-byte wire size (u8 transparent
/// encoding — bincode encodes newtype struct as its inner type).
///
/// Wire-size assertion matters: snapshots of the tracker's
/// `Vec<ParticipationFlags>` rely on 1-byte-per-entry density for
/// the millions-of-validators storage case.
#[test]
fn test_dsl_154_bincode_roundtrip() {
    let mut f = ParticipationFlags::default();
    f.set(TIMELY_SOURCE_FLAG_INDEX);
    f.set(TIMELY_TARGET_FLAG_INDEX);
    // Byte value after SOURCE + TARGET = 0b011 = 3.
    assert_eq!(f.0, 0b0000_0011);

    let bytes = bincode::serialize(&f).expect("bincode ser");
    assert_eq!(
        bytes.len(),
        1,
        "bincode newtype-struct wraps a single u8 as 1 wire byte",
    );
    assert_eq!(bytes[0], 0b0000_0011);

    let decoded: ParticipationFlags = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(decoded, f);
    assert_eq!(decoded.0, f.0, "byte value identical post-roundtrip");
}

/// DSL-154 row 2: serde_json roundtrip.
///
/// serde's tuple-struct encoding for `ParticipationFlags(pub u8)`
/// yields a plain integer (not a JSON object) — confirmed by the
/// wire-shape assertion. Test uses the full-mask value so the
/// high-bit encoding is also exercised (no i8 sign confusion).
#[test]
fn test_dsl_154_json_roundtrip() {
    let mut f = ParticipationFlags::default();
    f.set(TIMELY_SOURCE_FLAG_INDEX);
    f.set(TIMELY_TARGET_FLAG_INDEX);
    f.set(TIMELY_HEAD_FLAG_INDEX);
    assert_eq!(f.0, 0b0000_0111);

    let json = serde_json::to_string(&f).expect("json ser");
    // Newtype struct serialised as its inner value: bare integer.
    assert_eq!(json, "7", "serde transparent-newtype yields bare int");

    let decoded: ParticipationFlags = serde_json::from_str(&json).expect("json deser");
    assert_eq!(decoded, f);
    assert_eq!(decoded.0, 0b0000_0111);
}

/// DSL-154 row 3: `Vec<ParticipationFlags>` roundtrips under both
/// codecs, preserving order and per-element byte value. The
/// tracker stores two such vectors (current + previous epoch);
/// snapshot restore depends on index-stable decode.
#[test]
fn test_dsl_154_vec_roundtrip() {
    let original: Vec<ParticipationFlags> = vec![
        ParticipationFlags(0),
        ParticipationFlags(1),
        ParticipationFlags(3),
        ParticipationFlags(7),
        ParticipationFlags(42),
        ParticipationFlags(255),
    ];

    // bincode: each element 1 byte → total 8 bytes length prefix
    // (u64) + 6 bytes data.
    let bin = bincode::serialize(&original).expect("bincode ser vec");
    let bin_decoded: Vec<ParticipationFlags> =
        bincode::deserialize(&bin).expect("bincode deser vec");
    assert_eq!(bin_decoded, original);

    // serde_json: `[0,1,3,7,42,255]` — plain int array.
    let json = serde_json::to_string(&original).expect("json ser vec");
    assert_eq!(json, "[0,1,3,7,42,255]");
    let json_decoded: Vec<ParticipationFlags> =
        serde_json::from_str(&json).expect("json deser vec");
    assert_eq!(json_decoded, original);
}

/// DSL-154 row 4: every u8 value 0..=255 roundtrips identically
/// under both codecs.
///
/// Spec's test plan says "each bit pattern (0..=7)" meaning the
/// three defined flag-bit combinations. We widen to 0..=255 to
/// prove the serde contract is transparent for the full `u8`
/// range — reserved bits (3..=7 in DSL-074) MUST NOT be masked
/// out during ser/deser or a future protocol upgrade that claims
/// bit 3 would read stale data.
#[test]
fn test_dsl_154_all_bit_patterns() {
    for v in 0u8..=u8::MAX {
        let f = ParticipationFlags(v);

        let bin = bincode::serialize(&f).expect("bincode ser");
        let bin_decoded: ParticipationFlags = bincode::deserialize(&bin).expect("bincode deser");
        assert_eq!(
            bin_decoded.0, v,
            "bincode must preserve byte value {v} exactly (including reserved bits 3..=7)",
        );

        let json = serde_json::to_string(&f).expect("json ser");
        let json_decoded: ParticipationFlags = serde_json::from_str(&json).expect("json deser");
        assert_eq!(
            json_decoded.0, v,
            "serde_json must preserve byte value {v} exactly",
        );

        // Also cross-codec: bincode-then-json and json-then-bincode
        // must agree on the decoded value (no silent truncation).
        let json_of_bin: ParticipationFlags =
            serde_json::from_str(&serde_json::to_string(&bin_decoded).unwrap()).unwrap();
        assert_eq!(json_of_bin.0, v);
    }
}
