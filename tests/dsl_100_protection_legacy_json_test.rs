//! Requirement DSL-100: legacy JSON files persisted by an older
//! `SlashingProtection` schema — one that predates the
//! `last_attested_block_hash` field — MUST load successfully with
//! the missing field defaulting to `None`.
//!
//! Traces to: docs/resources/SPEC.md §14.4, §22.11.
//!
//! # Role
//!
//! On-disk slashing-protection state is load-bearing: losing it is
//! equivalent to losing monotonic-slot / monotonic-(source, target)
//! guarantees, which in the worst case lets the running validator
//! self-slash on the next restart. We cannot afford a "schema
//! migration required — please delete your state" failure mode.
//!
//! The spec contract: adding a new nullable field must be a
//! BACKWARDS-COMPATIBLE migration. The `#[serde(default)]`
//! attribute on `last_attested_block_hash` is what makes that
//! work — missing field → `Option::default()` → `None`. Under the
//! default serde policy a missing `Option` field is a hard
//! deserialization error, so this is not free behaviour; DSL-100
//! pins it as an intentional guarantee.
//!
//! After a validator running the new schema performs ONE
//! `record_attestation`, the on-disk representation upgrades
//! transparently (next `save` emits the field).
//!
//! # Test matrix (maps to DSL-100 Test Plan)
//!
//!   1. `test_dsl_100_legacy_json_loads` — legacy JSON (no hash
//!      field, no `null`) deserialises cleanly; hash slot is None
//!   2. `test_dsl_100_upgrade_on_save` — after one
//!      `record_attestation` + re-serialise, the emitted JSON
//!      contains `last_attested_block_hash`
//!   3. `test_dsl_100_legacy_check_attestation_fresh_start` — a
//!      loaded-legacy instance treats itself as fresh: any
//!      attestation passes the surround + same-coord checks
//!      (defaulted 0/0/None state means no prior constraint)

use dig_protocol::Bytes32;
use dig_slashing::SlashingProtection;

/// DSL-100 row 1: legacy JSON without `last_attested_block_hash`
/// deserialises cleanly.
///
/// The legacy schema contains only the three numeric fields. This
/// test fabricates that exact shape directly as a raw JSON string
/// (NOT via serde_json::to_value of the current struct followed by
/// object-remove) so we are actually exercising the serde
/// deserialization path a legacy file would take, not a round-trip
/// quirk of the current type.
#[test]
fn test_dsl_100_legacy_json_loads() {
    let legacy = r#"{
        "last_proposed_slot": 7,
        "last_attested_source_epoch": 3,
        "last_attested_target_epoch": 5
    }"#;

    let loaded: SlashingProtection =
        serde_json::from_str(legacy).expect("legacy JSON must deserialise without error");

    assert_eq!(
        loaded.last_proposed_slot(),
        7,
        "numeric field survives legacy load",
    );
    assert_eq!(loaded.last_attested_source_epoch(), 3);
    assert_eq!(loaded.last_attested_target_epoch(), 5);
    assert!(
        loaded.last_attested_block_hash().is_none(),
        "missing hash field → Option::default() → None",
    );
}

/// DSL-100 row 2: transparent on-save upgrade.
///
/// After loading legacy JSON and performing a single
/// `record_attestation`, the re-serialised JSON contains the
/// `last_attested_block_hash` field with the 0x-hex string. The
/// next writer-side save therefore emits the new schema — no
/// migration tool required.
#[test]
fn test_dsl_100_upgrade_on_save() {
    let legacy = r#"{
        "last_proposed_slot": 0,
        "last_attested_source_epoch": 0,
        "last_attested_target_epoch": 0
    }"#;

    let mut loaded: SlashingProtection = serde_json::from_str(legacy).unwrap();
    loaded.record_attestation(2, 4, &Bytes32::new([0x99u8; 32]));

    let re_serialised =
        serde_json::to_string(&loaded).expect("current-schema instance must serialise");

    assert!(
        re_serialised.contains("last_attested_block_hash"),
        "re-serialised JSON must include the new field; got {re_serialised}",
    );
    // And it must be populated, not Null — record_attestation ran.
    assert!(
        !re_serialised.contains("\"last_attested_block_hash\":null"),
        "field must carry the lowercase-hex string, not null",
    );
}

/// Contract bullet 3: a legacy-loaded instance with missing hash
/// treats itself as fresh — any (source, target) attestation is
/// accepted because the defaulted state (0, 0, None) satisfies the
/// DSL-096 surround check (strict `<` on source means any source
/// ≥ 0 passes) and the DSL-095 same-coord branch never fires (no
/// stored hash to compare against unless coords also match 0,0).
///
/// Covers the boundary (0, 0) case explicitly: if a legacy file
/// happened to record source=0, target=0, a candidate at (0, 0)
/// would trigger DSL-095's coord-match branch — and with hash=None
/// that branch rejects the candidate. This is the ONE edge case
/// where a legacy load is more restrictive than a fresh new(), and
/// it is documented behaviour: the validator MUST re-attest at
/// non-zero epochs before the protection state matches a fresh
/// instance's permissiveness.
#[test]
fn test_dsl_100_legacy_check_attestation_fresh_start() {
    let legacy = r#"{
        "last_proposed_slot": 0,
        "last_attested_source_epoch": 0,
        "last_attested_target_epoch": 0
    }"#;
    let loaded: SlashingProtection = serde_json::from_str(legacy).unwrap();

    let h = Bytes32::new([0x11u8; 32]);

    // Any non-(0,0) attestation passes — nothing stored to conflict.
    assert!(loaded.check_attestation(1, 2, &h));
    assert!(loaded.check_attestation(10, 20, &h));

    // The (0,0) edge case: coord match + hash=None → DSL-095 rejects.
    // Documented, not a bug — a legacy file cannot prove the
    // validator hasn't already signed at epochs (0,0).
    assert!(
        !loaded.check_attestation(0, 0, &h),
        "legacy (0,0,None) + candidate (0,0) → DSL-095 rejects; \
         must re-attest at non-zero epochs first",
    );
}
