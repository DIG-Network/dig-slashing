//! Requirement DSL-097: `SlashingProtection::record_proposal`
//! and `SlashingProtection::record_attestation` persist their
//! inputs into the corresponding watermark fields.
//!
//! Traces to: docs/resources/SPEC.md §14.1, §22.11.
//!
//! # Role
//!
//! DSL-094..096 use the watermark fields but rely on the record
//! primitives shipped alongside them as previews. DSL-097 pins
//! the record contract: what goes in must come out through the
//! accessors, and `last_attested_block_hash` must be canonicalised
//! to lowercase `0x`-prefixed hex so DSL-101 save/load and
//! DSL-095 case-insensitive compare both behave predictably.
//!
//! Save/load survival is covered by DSL-101 — this file asserts
//! only the in-memory contract.
//!
//! # Test matrix (maps to DSL-097 Test Plan)
//!
//!   1. `test_dsl_097_proposal_persist` — record_proposal(10)
//!      sets last_proposed_slot == 10; overwrites on re-record.
//!   2. `test_dsl_097_attestation_persist` — record_attestation
//!      (3, 5, hash) sets all three attested-fields.
//!   3. `test_dsl_097_hash_hex_format` — stored hash is `0x`
//!      prefix + exactly 64 lowercase hex chars, independent of
//!      input byte pattern.

use dig_protocol::Bytes32;
use dig_slashing::SlashingProtection;

/// DSL-097 row 1: `record_proposal` writes the slot field and
/// subsequent records overwrite — the watermark must reflect the
/// MOST RECENT record, not the max, to keep DSL-098/156 rewinds
/// semantically clean (rewinds move the watermark DOWN; record
/// moves it to whatever the caller asserts they just signed).
#[test]
fn test_dsl_097_proposal_persist() {
    let mut p = SlashingProtection::new();
    assert_eq!(p.last_proposed_slot(), 0, "fresh instance starts at slot 0");

    p.record_proposal(10);
    assert_eq!(
        p.last_proposed_slot(),
        10,
        "record_proposal(10) must write the slot field",
    );

    // Re-record overwrites — DSL-094 monotonic check is the caller's
    // responsibility; record_proposal itself is unconditional.
    p.record_proposal(42);
    assert_eq!(
        p.last_proposed_slot(),
        42,
        "subsequent record overwrites the prior watermark",
    );
}

/// DSL-097 row 2: `record_attestation` writes all three
/// attested-fields in a single call. Partial writes would leave
/// DSL-095/096 checks inconsistent (e.g. new epochs paired with a
/// stale hash) — this test pins the atomic-write contract.
#[test]
fn test_dsl_097_attestation_persist() {
    let mut p = SlashingProtection::new();
    assert_eq!(p.last_attested_source_epoch(), 0);
    assert_eq!(p.last_attested_target_epoch(), 0);
    assert!(p.last_attested_block_hash().is_none());

    let hash = Bytes32::new([0xCDu8; 32]);
    p.record_attestation(3, 5, &hash);

    assert_eq!(p.last_attested_source_epoch(), 3, "source epoch written");
    assert_eq!(p.last_attested_target_epoch(), 5, "target epoch written");
    assert!(
        p.last_attested_block_hash().is_some(),
        "block hash slot transitions from None to Some",
    );
}

/// DSL-097 row 3: the stored hash is canonicalised to the shape
/// `0x<64 lowercase hex chars>`. This is the invariant that DSL-095
/// case-insensitive compare and DSL-101 save/load both depend on.
///
/// Tested against two distinct byte patterns to prove the encoding
/// is not just "the zero fixture happened to round-trip": both the
/// all-`0xAB` fixture and a mixed-byte fixture must encode to the
/// expected hex string.
#[test]
fn test_dsl_097_hash_hex_format() {
    // Fixture 1: all-0xAB — tests that high-nibble / low-nibble
    // split writes 'a' + 'b' in that order (not 'b' + 'a').
    let mut p = SlashingProtection::new();
    let hash = Bytes32::new([0xABu8; 32]);
    p.record_attestation(1, 2, &hash);

    let stored = p
        .last_attested_block_hash()
        .expect("record_attestation must populate the hash slot");

    assert!(
        stored.starts_with("0x"),
        "hash must carry the `0x` prefix; got {stored:?}",
    );
    assert_eq!(
        stored.len(),
        2 + 64,
        "prefix + 2 hex chars per byte × 32 bytes = 66 chars total",
    );
    assert_eq!(
        stored, "0xabababababababababababababababababababababababababababababababab",
        "all-0xAB bytes must encode lowercase",
    );
    assert!(
        stored[2..].chars().all(|c| c.is_ascii_hexdigit()),
        "post-prefix chars must all be hex digits",
    );
    assert!(
        stored[2..].chars().all(|c| !c.is_ascii_uppercase()),
        "hex digits must be lowercase (DSL-095 eq_ignore_ascii_case \
         still works but the canonical on-disk form is lowercase)",
    );

    // Fixture 2: mixed bytes — proves the encoder walks every byte
    // and does not just memoise the first. Byte `i` maps to `ii`
    // (e.g. byte 0x01 → "01", byte 0xFE → "fe").
    let mut p2 = SlashingProtection::new();
    let mut mixed = [0u8; 32];
    for (i, byte) in mixed.iter_mut().enumerate() {
        *byte = i as u8;
    }
    let mixed_hash = Bytes32::new(mixed);
    p2.record_attestation(1, 2, &mixed_hash);

    let stored2 = p2
        .last_attested_block_hash()
        .expect("record_attestation must populate the hash slot");

    assert_eq!(
        stored2, "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "sequential-byte fixture must encode to the canonical lowercase hex",
    );
}
