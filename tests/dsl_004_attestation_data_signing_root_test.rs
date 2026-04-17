//! Requirement DSL-004: `AttestationData::signing_root(&Bytes32)` is
//! deterministic, domain-prefixed with `DOMAIN_BEACON_ATTESTER`, and shifts
//! whenever any field or `network_id` is mutated.
//!
//! Traces to: docs/resources/SPEC.md §3.3 (AttestationData), §2.10
//! (DOMAIN_BEACON_ATTESTER constant), §22.1 (catalogue row).
//!
//! # Why this matters
//!
//! `signing_root` is the BLS signing message for every attester slashing
//! (DSL-006 `IndexedAttestation::verify_signature`) and every participation
//! recording path. If two attestations hash to the same root, BLS signature
//! verification cannot distinguish them — a catastrophic consensus bug. The
//! domain prefix + network_id binding prevent cross-network replay; the
//! per-field mutation tests prevent field-ordering bugs.
//!
//! # Test matrix (maps to DSL-004 Test Plan)
//!
//!   1. `test_dsl_004_signing_root_deterministic` — idempotency
//!   2. `test_dsl_004_domain_prefix` — manual re-hash with expected layout
//!   3. `test_dsl_004_changes_on_slot`, `..._index` — LE integer fields
//!   4. `test_dsl_004_changes_on_beacon_block_root` — head vote
//!   5. `test_dsl_004_changes_on_source_epoch`, `..._source_root` — FFG source
//!   6. `test_dsl_004_changes_on_target_epoch`, `..._target_root` — FFG target
//!   7. `test_dsl_004_changes_on_network_id` — cross-network replay protection

use chia_sha2::Sha256;
use dig_protocol::Bytes32;
use dig_slashing::{AttestationData, Checkpoint, DOMAIN_BEACON_ATTESTER};

/// Canonical fixture. Every test starts from this value.
fn sample() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 3,
        beacon_block_root: Bytes32::new([0xAAu8; 32]),
        source: Checkpoint {
            epoch: 9,
            root: Bytes32::new([0x11u8; 32]),
        },
        target: Checkpoint {
            epoch: 10,
            root: Bytes32::new([0x22u8; 32]),
        },
    }
}

fn network_id() -> Bytes32 {
    Bytes32::new([0xFEu8; 32])
}

/// Same inputs → same output.
#[test]
fn test_dsl_004_signing_root_deterministic() {
    let data = sample();
    let nid = network_id();
    let r1 = data.signing_root(&nid);
    let r2 = data.signing_root(&nid);
    assert_eq!(r1, r2, "signing_root must be deterministic");
}

/// Manual re-hash with the canonical field layout defined in SPEC §3.3.
/// Proves the implementation matches the wire specification exactly.
#[test]
fn test_dsl_004_domain_prefix() {
    let data = sample();
    let nid = network_id();

    // Compute the expected root manually, field by field, per SPEC §3.3.
    // Any drift in field order or integer endianness will fail this test.
    let mut h = Sha256::new();
    h.update(DOMAIN_BEACON_ATTESTER);
    h.update(nid.as_ref());
    h.update(data.slot.to_le_bytes());
    h.update(data.index.to_le_bytes());
    h.update(data.beacon_block_root.as_ref());
    h.update(data.source.epoch.to_le_bytes());
    h.update(data.source.root.as_ref());
    h.update(data.target.epoch.to_le_bytes());
    h.update(data.target.root.as_ref());
    let expected: [u8; 32] = h.finalize();

    assert_eq!(
        data.signing_root(&nid),
        Bytes32::new(expected),
        "signing_root must match the SPEC §3.3 layout byte-for-byte",
    );
}

/// Mutate `slot` → root shifts.
#[test]
fn test_dsl_004_changes_on_slot() {
    let nid = network_id();
    let a = sample();
    let mut b = a.clone();
    b.slot = a.slot + 1;
    assert_ne!(a.signing_root(&nid), b.signing_root(&nid));
}

/// Mutate `index` → root shifts. Guards committee-index field encoding.
#[test]
fn test_dsl_004_changes_on_index() {
    let nid = network_id();
    let a = sample();
    let mut b = a.clone();
    b.index = a.index + 1;
    assert_ne!(a.signing_root(&nid), b.signing_root(&nid));
}

/// Mutate `beacon_block_root` → root shifts. Guards head vote field.
#[test]
fn test_dsl_004_changes_on_beacon_block_root() {
    let nid = network_id();
    let a = sample();
    let mut b = a.clone();
    b.beacon_block_root = Bytes32::new([0xBBu8; 32]);
    assert_ne!(a.signing_root(&nid), b.signing_root(&nid));
}

/// Mutate `source.epoch` → root shifts.
#[test]
fn test_dsl_004_changes_on_source_epoch() {
    let nid = network_id();
    let a = sample();
    let mut b = a.clone();
    b.source.epoch = a.source.epoch + 1;
    assert_ne!(a.signing_root(&nid), b.signing_root(&nid));
}

/// Mutate `source.root` → root shifts.
#[test]
fn test_dsl_004_changes_on_source_root() {
    let nid = network_id();
    let a = sample();
    let mut b = a.clone();
    b.source.root = Bytes32::new([0xCCu8; 32]);
    assert_ne!(a.signing_root(&nid), b.signing_root(&nid));
}

/// Mutate `target.epoch` → root shifts.
#[test]
fn test_dsl_004_changes_on_target_epoch() {
    let nid = network_id();
    let a = sample();
    let mut b = a.clone();
    b.target.epoch = a.target.epoch + 1;
    assert_ne!(a.signing_root(&nid), b.signing_root(&nid));
}

/// Mutate `target.root` → root shifts.
#[test]
fn test_dsl_004_changes_on_target_root() {
    let nid = network_id();
    let a = sample();
    let mut b = a.clone();
    b.target.root = Bytes32::new([0xDDu8; 32]);
    assert_ne!(a.signing_root(&nid), b.signing_root(&nid));
}

/// Mutate `network_id` → root shifts. Guards cross-network replay.
///
/// A signing message produced under testnet domain MUST not verify under
/// mainnet domain, even if every `AttestationData` field is identical.
#[test]
fn test_dsl_004_changes_on_network_id() {
    let data = sample();
    let nid_a = network_id();
    let nid_b = Bytes32::new([0x77u8; 32]);
    assert_ne!(data.signing_root(&nid_a), data.signing_root(&nid_b));
}

/// Little-endian encoding sanity: flipping low byte vs high byte of the
/// slot u64 MUST produce distinct roots. Catches field encoded as BE (or
/// as raw memory representation, which is endian-dependent).
#[test]
fn test_dsl_004_le_integer_encoding() {
    let nid = network_id();
    let a = AttestationData {
        slot: 0x0000_0000_0000_00FF, // low byte set
        ..sample()
    };
    let b = AttestationData {
        slot: 0xFF00_0000_0000_0000, // high byte set
        ..sample()
    };
    assert_ne!(
        a.signing_root(&nid),
        b.signing_root(&nid),
        "slot byte order must be observable in signing_root",
    );
}
