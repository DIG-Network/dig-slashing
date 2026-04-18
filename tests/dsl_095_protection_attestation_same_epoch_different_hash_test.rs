//! Requirement DSL-095: `SlashingProtection::check_attestation`
//! at the SAME `(source_epoch, target_epoch)` coordinates
//! allows only the SAME block hash as previously recorded.
//! Different hash → false (double-vote self-check). No prior
//! attestation at that pair → also false (cannot confirm
//! match).
//!
//! Traces to: docs/resources/SPEC.md §14.1, §22.11.
//!
//! # Test matrix (maps to DSL-095 Test Plan)
//!
//!   1. `test_dsl_095_same_hash_ok` — record + same-hash re-
//!      check → true (honest restart re-sign)
//!   2. `test_dsl_095_different_hash_fails` — record(h) +
//!      check(h') → false
//!   3. `test_dsl_095_case_insensitive` — `eq_ignore_ascii_case`
//!      behaviour
//!   4. `test_dsl_095_none_hash_fails` — setter-style coord
//!      collision with `last_attested_block_hash == None` →
//!      false

use dig_protocol::Bytes32;
use dig_slashing::SlashingProtection;

/// DSL-095 row 1: record then re-check same hash → true.
/// Honest restart case: validator re-signs its own attestation.
#[test]
fn test_dsl_095_same_hash_ok() {
    let mut p = SlashingProtection::new();
    let h = Bytes32::new([0xAAu8; 32]);
    p.record_attestation(5, 10, &h);

    assert!(p.check_attestation(5, 10, &h));
}

/// DSL-095 row 2: same (src, tgt) but DIFFERENT hash → false.
/// Canonical attester-double-vote self-check.
#[test]
fn test_dsl_095_different_hash_fails() {
    let mut p = SlashingProtection::new();
    let h1 = Bytes32::new([0xAAu8; 32]);
    let h2 = Bytes32::new([0xBBu8; 32]);
    p.record_attestation(5, 10, &h1);

    assert!(!p.check_attestation(5, 10, &h2));
}

/// DSL-095 row 3: case-insensitive hex comparison. Test by
/// mutating the stored hex to uppercase then checking with
/// lowercase — same bytes should still match.
#[test]
fn test_dsl_095_case_insensitive() {
    let mut p = SlashingProtection::new();
    let h = Bytes32::new([0xABu8; 32]);
    p.record_attestation(5, 10, &h);

    // Stored hex is lowercase by default.
    let stored = p.last_attested_block_hash().unwrap().to_owned();
    assert!(stored.starts_with("0x"));
    assert_eq!(
        stored,
        stored.to_ascii_lowercase(),
        "record writes lowercase hex",
    );

    // Roundtrip: check against the same bytes (which re-render
    // as the same lowercase hex) → matches regardless of
    // stored case.
    assert!(p.check_attestation(5, 10, &h));

    // Manually uppercase the stored hash to exercise the
    // case-insensitive comparison path.
    let mut raw = serde_json::to_value(&p).unwrap();
    raw["last_attested_block_hash"] = serde_json::Value::String(stored.to_ascii_uppercase());
    let p_upper: SlashingProtection = serde_json::from_value(raw).unwrap();
    assert!(
        p_upper.check_attestation(5, 10, &h),
        "uppercase-stored vs lowercase-candidate still matches",
    );
}

/// DSL-095 row 4: coord collision with `last_attested_block_hash
/// == None` → false. Only reachable by loading persisted state
/// where the hash slot is missing; default-constructed state
/// has `(src, tgt) == (0, 0)` and we check against `(5, 10)`
/// which mismatches the coordinates anyway, so we mutate the
/// stored coords via JSON roundtrip to hit the None branch
/// cleanly.
#[test]
fn test_dsl_095_none_hash_fails() {
    let p = SlashingProtection::new();
    // Inject (src=5, tgt=10) + None hash.
    let mut raw = serde_json::to_value(&p).unwrap();
    raw["last_attested_source_epoch"] = serde_json::Value::from(5u64);
    raw["last_attested_target_epoch"] = serde_json::Value::from(10u64);
    raw["last_attested_block_hash"] = serde_json::Value::Null;
    let p_none: SlashingProtection = serde_json::from_value(raw).unwrap();

    assert_eq!(p_none.last_attested_source_epoch(), 5);
    assert_eq!(p_none.last_attested_target_epoch(), 10);
    assert!(p_none.last_attested_block_hash().is_none());

    let h = Bytes32::new([0xAAu8; 32]);
    assert!(
        !p_none.check_attestation(5, 10, &h),
        "coord collision with None stored hash MUST fail",
    );
}
