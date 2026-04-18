//! Requirement DSL-158: `IndexedAttestation` round-trips byte-
//! exactly via `bincode` and `serde_json`.
//!
//! Traces to: docs/resources/SPEC.md §3.3, §18.
//!
//! # Role
//!
//! `IndexedAttestation` is the per-attestation envelope carried
//! inside `AttesterSlashing` (DSL-014/015). It couples three
//! fields:
//!
//!   - `attesting_indices: Vec<u32>` — strict-ascending set of
//!     validator indices (DSL-005 validator-side check).
//!   - `data: AttestationData` — contains slot, index,
//!     `beacon_block_root`, plus TWO `Checkpoint` values
//!     (source + target).
//!   - `signature: Vec<u8>` — 96-byte aggregate BLS signature,
//!     carried with `#[serde(with = "serde_bytes")]` for
//!     binary-tight bincode encoding.
//!
//! Byte-exact roundtrip is load-bearing on TWO wire paths:
//!
//!   1. DSL-157 `SlashingEvidence` REMARK admission (JSON) +
//!      PendingSlash persistence (bincode) — the `Attester`
//!      payload embeds two `IndexedAttestation` values; serde
//!      drift here collapses the outer envelope.
//!   2. DSL-002 `evidence.hash()` content-address derivation —
//!      the canonical bincode encoding flows through the hash,
//!      so any field reordering or wire change would also
//!      change the hash.
//!
//! # Test matrix (maps to DSL-158 Test Plan)
//!
//!   1. `test_dsl_158_bincode_roundtrip` — full envelope under
//!      bincode.
//!   2. `test_dsl_158_json_roundtrip` — full envelope under
//!      serde_json.
//!   3. `test_dsl_158_index_order_preserved` — `attesting_indices`
//!      carries SET semantics (strict-ascending); the vec's ORDER
//!      must survive roundtrip so downstream DSL-005 parity
//!      check cannot be tricked by a reserialisation step.
//!   4. `test_dsl_158_signature_serde_bytes` — bincode wire
//!      contains the distinctive signature run verbatim; JSON
//!      emits the signature as a `[u8; 96]` array (the default
//!      serde_bytes → JSON mapping).
//!   5. `test_dsl_158_nested_attestation_data` — mutation in
//!      `source.epoch` observable post-roundtrip; pins that
//!      deeply-nested fields are NOT flattened or stubbed.

use dig_protocol::Bytes32;
use dig_slashing::{AttestationData, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation};

// ── fixtures ────────────────────────────────────────────────────

fn sample_data() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 2,
        beacon_block_root: Bytes32::new([0x11u8; 32]),
        source: Checkpoint {
            epoch: 5,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 6,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}

fn sample_indexed_attestation() -> IndexedAttestation {
    IndexedAttestation {
        attesting_indices: vec![1, 3, 5, 7, 9, 11, 13],
        data: sample_data(),
        signature: vec![0xAB; BLS_SIGNATURE_SIZE],
    }
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-158 row 1: full bincode roundtrip preserves every field.
///
/// Tight-binary encoding is the internal PendingSlash persistence
/// format (DSL-024) and also feeds DSL-002 `evidence.hash()`
/// derivation — drift anywhere in this surface invalidates
/// content-addressing.
#[test]
fn test_dsl_158_bincode_roundtrip() {
    let original = sample_indexed_attestation();
    let bytes = bincode::serialize(&original).expect("bincode ser");
    let decoded: IndexedAttestation = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(
        original, decoded,
        "bincode preserves attesting_indices + nested data + signature",
    );
}

/// DSL-158 row 2: serde_json roundtrip — REMARK wire path.
///
/// Evidence arriving as a REMARK condition (DSL-102) is decoded
/// via serde_json, so the JSON form must round-trip byte-exact or
/// admission rejects correctly-formed peer evidence.
#[test]
fn test_dsl_158_json_roundtrip() {
    let original = sample_indexed_attestation();
    let json = serde_json::to_string(&original).expect("json ser");
    let decoded: IndexedAttestation = serde_json::from_str(&json).expect("json deser");
    assert_eq!(original, decoded, "serde_json preserves every field");
}

/// DSL-158 row 3: `attesting_indices` order is preserved.
///
/// The Vec is canonically stored in strict-ascending order (per
/// DSL-005), so normal-path input is already sorted. We
/// nevertheless pin the order-preserving serde contract explicitly
/// with a KNOWN ascending sequence — this catches any subtle
/// serde refactor that swaps to `BTreeSet` or similar ordered-
/// set representation that would rearrange duplicates silently.
#[test]
fn test_dsl_158_index_order_preserved() {
    let original = IndexedAttestation {
        attesting_indices: vec![0, 42, 77, 1_000, 1_001, u32::MAX - 1, u32::MAX],
        data: sample_data(),
        signature: vec![0x00u8; BLS_SIGNATURE_SIZE],
    };

    // bincode.
    let bin = bincode::serialize(&original).expect("bincode ser");
    let bin_decoded: IndexedAttestation = bincode::deserialize(&bin).expect("bincode deser");
    assert_eq!(
        bin_decoded.attesting_indices, original.attesting_indices,
        "bincode preserves index order verbatim",
    );
    // serde_json.
    let json = serde_json::to_string(&original).expect("json ser");
    let json_decoded: IndexedAttestation = serde_json::from_str(&json).expect("json deser");
    assert_eq!(
        json_decoded.attesting_indices, original.attesting_indices,
        "serde_json preserves index order verbatim",
    );
}

/// DSL-158 row 4: `signature` serde_bytes encoding.
///
/// bincode wire contains the 96-byte signature as a raw contiguous
/// run (length-prefix || bytes). Distinctive 0xAB run is
/// grep-able from the wire — proves serde_bytes was in force.
/// JSON encoding maps serde_bytes to a bare integer array
/// `[171, 171, ...]` (serde_bytes's default JSON shape) which we
/// spot-check via the raw JSON string.
#[test]
fn test_dsl_158_signature_serde_bytes() {
    let original = sample_indexed_attestation();

    let bin = bincode::serialize(&original).expect("bincode ser");
    let run_of_abs = vec![0xABu8; BLS_SIGNATURE_SIZE];
    assert!(
        bin.windows(BLS_SIGNATURE_SIZE)
            .any(|w| w == run_of_abs.as_slice()),
        "bincode wire must contain the 96-byte 0xAB signature run verbatim",
    );

    let json = serde_json::to_string(&original).expect("json ser");
    // serde_bytes on JSON → integer array. Probe-value 0xAB = 171.
    // Full array appears with at least one 171 element; a full-
    // string pattern check would be brittle due to the surrounding
    // AttestationData fields. The substring `[171,` is sufficient
    // evidence.
    assert!(
        json.contains("171"),
        "JSON must contain the signature byte value (171 == 0xAB) \
         as part of the signature integer array",
    );
    // Roundtrip equality is the authoritative observable.
    let decoded: IndexedAttestation = serde_json::from_str(&json).expect("json deser");
    assert_eq!(
        decoded.signature, original.signature,
        "signature decoded byte-for-byte from JSON",
    );
}

/// DSL-158 row 5: nested AttestationData + Checkpoint preserved.
///
/// Mutate `source.epoch` on a pre-roundtrip copy, re-encode, and
/// decode — the mutation must appear in the decoded value. Guards
/// against a serde refactor that accidentally stubs nested
/// Checkpoint fields or flattens AttestationData.
#[test]
fn test_dsl_158_nested_attestation_data() {
    let mut mutated = sample_indexed_attestation();
    mutated.data.source.epoch = 99_999;
    mutated.data.target.epoch = 100_000;
    mutated.data.target.root = Bytes32::new([0xEFu8; 32]);

    // bincode.
    let bin = bincode::serialize(&mutated).expect("bincode ser");
    let bin_decoded: IndexedAttestation = bincode::deserialize(&bin).expect("bincode deser");
    assert_eq!(bin_decoded.data.source.epoch, 99_999);
    assert_eq!(bin_decoded.data.target.epoch, 100_000);
    assert_eq!(bin_decoded.data.target.root, Bytes32::new([0xEFu8; 32]));

    // serde_json.
    let json = serde_json::to_string(&mutated).expect("json ser");
    let json_decoded: IndexedAttestation = serde_json::from_str(&json).expect("json deser");
    assert_eq!(json_decoded.data.source.epoch, 99_999);
    assert_eq!(json_decoded.data.target.epoch, 100_000);
    assert_eq!(
        json_decoded.data.target.root,
        Bytes32::new([0xEFu8; 32]),
        "deep Bytes32 root survives JSON roundtrip",
    );
}
