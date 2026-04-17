//! Requirement DSL-003: `Checkpoint` serde + equality + hash round-trip.
//!
//! Traces to: docs/resources/SPEC.md §3.3 (Checkpoint definition), §22.1
//! (catalogue row).
//!
//! The `Checkpoint` is the FFG vote `(epoch, root)` pair consumed by
//! `AttestationData::source` / `.target` (DSL-004), `JustificationView`
//! (DSL-143), and every attester-related code path in this crate. It is the
//! smallest primitive in the evidence module — zero nested types beyond the
//! `Bytes32` root — so it is the first type implemented under the TDD
//! workflow.
//!
//! Required derives per SPEC §3.3: `Debug, Clone, Copy, Serialize,
//! Deserialize, PartialEq, Eq, Hash`. These tests exercise every derived
//! trait's contract:
//!
//!   1. `test_dsl_003_bincode_roundtrip` — bincode ser + deser yields equal value.
//!   2. `test_dsl_003_json_roundtrip` — serde_json ser + deser yields equal value.
//!   3. `test_dsl_003_equality_fields` — `PartialEq` considers epoch AND root.
//!   4. `test_dsl_003_hash_consistency` — equal values hash to identical u64.
//!   5. `test_dsl_003_copy_semantics` — `Copy` does not move ownership.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use dig_protocol::Bytes32;
use dig_slashing::Checkpoint;

/// Construct a canonical test checkpoint. Shared by every test below so
/// the fixture stays consistent across the suite — if any test needs a
/// different value, it builds one explicitly.
fn sample() -> Checkpoint {
    Checkpoint {
        epoch: 42,
        root: Bytes32::new([0x11u8; 32]),
    }
}

/// DSL-003 row 1: bincode round-trip preserves byte-exact equality.
///
/// Proves `Serialize` + `Deserialize` compose into a lossless round-trip
/// via the compact `bincode` encoding used by internal storage paths
/// (`PendingSlash`, `AppealAttempt`, snapshot/restore).
#[test]
fn test_dsl_003_bincode_roundtrip() {
    let original = sample();
    let encoded = bincode::serialize(&original).expect("bincode ser");
    let decoded: Checkpoint = bincode::deserialize(&encoded).expect("bincode deser");
    assert_eq!(
        original, decoded,
        "bincode round-trip must preserve Checkpoint"
    );
}

/// DSL-003 row 2: serde_json round-trip preserves equality.
///
/// REMARK wires use JSON (DSL-102, DSL-110). `Checkpoint` travels inside
/// `AttestationData` which travels inside `IndexedAttestation` which travels
/// inside `AttesterSlashing`. JSON fidelity at the leaf propagates up.
#[test]
fn test_dsl_003_json_roundtrip() {
    let original = sample();
    let encoded = serde_json::to_vec(&original).expect("json ser");
    let decoded: Checkpoint = serde_json::from_slice(&encoded).expect("json deser");
    assert_eq!(
        original, decoded,
        "serde_json round-trip must preserve Checkpoint",
    );
}

/// DSL-003 row 3: `PartialEq` considers every field.
///
/// Proves that `Checkpoint` equality is field-wise — mutating either
/// `epoch` OR `root` produces a non-equal value. Critical for dedup
/// semantics in higher-level types that contain Checkpoint.
#[test]
fn test_dsl_003_equality_fields() {
    let a = sample();

    let mut b = a;
    b.epoch += 1;
    assert_ne!(a, b, "different epoch must be non-equal");

    let mut c = a;
    c.root = Bytes32::new([0x22u8; 32]);
    assert_ne!(a, c, "different root must be non-equal");

    // Two separately-constructed equal values compare equal.
    assert_eq!(a, sample(), "field-identical Checkpoints must be equal");
}

/// DSL-003 row 4: `Hash` output is consistent for equal values.
///
/// Proves that `Checkpoint` can be used as a `HashMap`/`HashSet` key —
/// `JustificationView` surfaces checkpoints, and consumers may key
/// decisions on them. The `Eq + Hash` contract requires equal values to
/// hash identically.
#[test]
fn test_dsl_003_hash_consistency() {
    // Smoke test via std's DefaultHasher — two equal values MUST produce
    // the same u64 hash output.
    let a = sample();
    let b = sample();
    let mut ha = DefaultHasher::new();
    let mut hb = DefaultHasher::new();
    a.hash(&mut ha);
    b.hash(&mut hb);
    assert_eq!(
        ha.finish(),
        hb.finish(),
        "equal Checkpoints must hash equal"
    );

    // Also verify usability as a HashMap key.
    let mut m: HashMap<Checkpoint, &'static str> = HashMap::new();
    m.insert(a, "yes");
    assert_eq!(
        m.get(&b),
        Some(&"yes"),
        "HashMap lookup must find equal key"
    );
}

/// DSL-003 row 5: `Copy` permits pass-by-value without move.
///
/// Proves that `Checkpoint` can be freely passed into functions returning
/// by-value copies without borrow/move friction. This keeps downstream
/// APIs (`AttestationData::signing_root`, `JustificationView` accessors)
/// ergonomic.
#[test]
fn test_dsl_003_copy_semantics() {
    let a = sample();
    let b = a; // copy, not move
    // Both usable — compiles only if Copy is derived.
    assert_eq!(a, b);
    assert_eq!(a.epoch, b.epoch);
}
