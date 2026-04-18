//! Requirement DSL-101: `SlashingProtection::save(&PathBuf)` +
//! `SlashingProtection::load(&PathBuf)` MUST preserve every field
//! byte-exactly across a round-trip. Non-existent paths resolve
//! to `SlashingProtection::default()` so first-boot validators do
//! not need a bootstrap dance. Reload tolerates uppercase hex
//! (external validator-key tooling sometimes normalises to
//! uppercase), via DSL-095 case-insensitive compare.
//!
//! Traces to: docs/resources/SPEC.md §14.4, §22.11.
//!
//! # Role
//!
//! Closes Phase 5 Protection. This is the persistence guarantee
//! that makes every prior DSL in the phase (094..100) durable
//! across process restarts. Without save/load the in-memory
//! monotonic watermarks vanish on crash and the next boot signs
//! a slashable equivocation. The operation is intentionally
//! simple — one JSON file, pretty-printed — to keep the on-disk
//! format debuggable by operators.
//!
//! # Test matrix (maps to DSL-101 Test Plan)
//!
//!   1. `test_dsl_101_save_load_roundtrip` — full field-equality
//!      round-trip on a fully-populated instance
//!   2. `test_dsl_101_hash_hex_format` — emitted JSON contains the
//!      `0x` + 64 lowercase hex chars canonical form
//!   3. `test_dsl_101_case_insensitive_load` — hand-edit the on-
//!      disk file to uppercase hex; reload + re-check succeeds
//!      per DSL-095 case-insensitive compare semantics
//!   4. `test_dsl_101_load_missing_path_default` — non-existent
//!      path → `Ok(default())`, never an I/O error

use dig_protocol::Bytes32;
use dig_slashing::SlashingProtection;
use std::path::PathBuf;

/// Returns a unique path under the OS temp dir. Uses nanos to
/// avoid collisions across parallel tests sharing the same
/// process. Test caller is responsible for cleanup.
fn tmp_path(suffix: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut p = std::env::temp_dir();
    p.push(format!("dig_slashing_dsl_101_{nanos}_{suffix}.json"));
    p
}

/// RAII cleanup — ensures the temp file is removed even if the
/// assertions panic. Without this a flake in one test would leak
/// fixture files across runs and eventually shadow a later test.
struct TmpFile(PathBuf);
impl Drop for TmpFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// DSL-101 row 1: full roundtrip equality.
///
/// Populate every field via the public API, save, load, compare
/// via `PartialEq`. `SlashingProtection` derives Eq so this catches
/// ANY field drift including future fields added by later DSLs.
#[test]
fn test_dsl_101_save_load_roundtrip() {
    let tmp = TmpFile(tmp_path("roundtrip"));

    let mut original = SlashingProtection::new();
    original.record_proposal(42);
    original.record_attestation(7, 11, &Bytes32::new([0xCAu8; 32]));

    original
        .save(&tmp.0)
        .expect("save must succeed on a writable temp path");

    let loaded =
        SlashingProtection::load(&tmp.0).expect("load must succeed on a just-written file");

    assert_eq!(
        loaded, original,
        "whole-struct equality — every field must round-trip byte-exact",
    );
}

/// DSL-101 row 2: the emitted JSON file contains the `0x` +
/// 64-lowercase-hex canonical form. Pins the on-disk format so
/// downstream tooling (operators grepping for their own block
/// hash, cross-client portability with Ethereum-style key
/// management) stays stable.
///
/// Reads the file back as raw bytes and does a substring match,
/// NOT a serde round-trip — this is about wire format, not value
/// identity.
#[test]
fn test_dsl_101_hash_hex_format() {
    let tmp = TmpFile(tmp_path("hex_format"));

    let mut p = SlashingProtection::new();
    p.record_attestation(1, 2, &Bytes32::new([0xABu8; 32]));
    p.save(&tmp.0).expect("save");

    let raw = std::fs::read_to_string(&tmp.0).expect("read back");

    assert!(
        raw.contains("0xabababababababababababababababababababababababababababababababab"),
        "on-disk form must be 0x + 64 lowercase hex chars; got:\n{raw}",
    );
    // Also confirm no uppercase hex crept in — the canonical form
    // is lowercase and deviation here means the encoder changed
    // behaviour (which would break external tooling).
    assert!(
        !raw.contains("0xABABABABAB"),
        "on-disk form must not contain uppercase hex",
    );
}

/// DSL-101 row 3: if external tooling writes the file with
/// uppercase hex, reload + subsequent `check_attestation` must
/// still match the same block hash via DSL-095's
/// `eq_ignore_ascii_case` compare.
///
/// Proves the compose: wire-format tolerance (external tool
/// writes `0xABAB...`) + in-memory compare semantics (our stored
/// lowercase matches their uppercase) yield correct behaviour
/// across the full save-external-edit-load-check pipeline.
#[test]
fn test_dsl_101_case_insensitive_load() {
    let tmp = TmpFile(tmp_path("case_insensitive"));

    let original_hash = Bytes32::new([0xDEu8; 32]);
    let mut p = SlashingProtection::new();
    p.record_attestation(3, 4, &original_hash);
    p.save(&tmp.0).expect("save");

    // Simulate external tooling rewriting the file with uppercase
    // hex. Read → mutate the hex section → write.
    let raw = std::fs::read_to_string(&tmp.0).unwrap();
    let lowered = "0xdededededededededededededededededededededededededededededededede";
    let uppered = "0xDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE";
    assert!(
        raw.contains(lowered),
        "pre-mutation file must contain the original lowercase hash",
    );
    let mutated = raw.replace(lowered, uppered);
    std::fs::write(&tmp.0, mutated).unwrap();

    let reloaded = SlashingProtection::load(&tmp.0).expect("load after uppercase mutation");

    // Cross-check: DSL-095 coord-match + SAME-hash candidate → true
    // even though stored is now uppercase and candidate encodes
    // lowercase.
    assert!(
        reloaded.check_attestation(3, 4, &original_hash),
        "uppercase-stored + lowercase-candidate must still match",
    );
}

/// DSL-101 row 4: `load` on a non-existent path returns
/// `Ok(default())` — NOT an error. First-boot validators call
/// `load` before their state file exists; forcing them to handle
/// `NotFound` would multiply the number of code paths that need
/// to re-establish a fresh default.
#[test]
fn test_dsl_101_load_missing_path_default() {
    // NOT wrapped in TmpFile — the whole point is that the path
    // does NOT exist on disk.
    let missing = tmp_path("definitely_does_not_exist");
    assert!(
        !missing.exists(),
        "fixture precondition: path must be absent"
    );

    let loaded =
        SlashingProtection::load(&missing).expect("missing path must NOT raise an I/O error");

    assert_eq!(
        loaded,
        SlashingProtection::default(),
        "missing path → default instance",
    );
}
