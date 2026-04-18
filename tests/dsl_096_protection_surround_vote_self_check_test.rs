//! Requirement DSL-096: `SlashingProtection::check_attestation`
//! rejects attestations that would surround the stored prior
//! attestation. `would_surround` predicate:
//! `candidate_source < last_attested_source_epoch AND
//!  candidate_target > last_attested_target_epoch`.
//!
//! Traces to: docs/resources/SPEC.md §14.2, §22.11.
//!
//! # Role
//!
//! Mirror of DSL-015 verify-side predicate. Running-validator
//! self-check: never sign an attestation that would surround
//! one you already signed. Runs BEFORE the DSL-095 same-coord
//! branch so surround rejection short-circuits cheaply.
//!
//! # Test matrix (maps to DSL-096 Test Plan)
//!
//!   1. `test_dsl_096_surround_rejected` — prior (3,5) +
//!      candidate (2,6) → false
//!   2. `test_dsl_096_exact_match_passes_surround` — prior
//!      (3,5) + candidate (3,5) + same hash → true (falls
//!      through to DSL-095 same-hash allow)
//!   3. `test_dsl_096_flanking_ok` — prior (3,5) + candidate
//!      (5,7) → true
//!   4. `test_dsl_096_same_source_higher_target` — prior (3,5)
//!      + candidate (3,6) → true (equal source → not strict)

use dig_protocol::Bytes32;
use dig_slashing::SlashingProtection;

fn seed(src: u64, tgt: u64) -> (SlashingProtection, Bytes32) {
    let mut p = SlashingProtection::new();
    let h = Bytes32::new([0xAAu8; 32]);
    p.record_attestation(src, tgt, &h);
    (p, h)
}

/// DSL-096 row 1: classic surround → false. prior=(3,5);
/// candidate=(2,6) strictly surrounds.
#[test]
fn test_dsl_096_surround_rejected() {
    let (p, _) = seed(3, 5);
    let candidate_hash = Bytes32::new([0xBBu8; 32]);
    assert!(!p.check_attestation(2, 6, &candidate_hash));
}

/// DSL-096 row 2: candidate equals prior (src, tgt) — the
/// surround predicate is false (both coords equal, not strict).
/// Falls through to DSL-095; same hash → allowed.
#[test]
fn test_dsl_096_exact_match_passes_surround() {
    let (p, h) = seed(3, 5);
    assert!(
        p.check_attestation(3, 5, &h),
        "same (src, tgt) + same hash → allowed (DSL-095 re-sign)",
    );

    // Different hash at same (src, tgt) → DSL-095 rejects, but
    // DSL-096 does NOT — surround predicate was false.
    let different = Bytes32::new([0xBBu8; 32]);
    assert!(
        !p.check_attestation(3, 5, &different),
        "same (src, tgt) + different hash → DSL-095 rejects (not DSL-096)",
    );
}

/// DSL-096 row 3: flank → candidate strictly later on both
/// axes. Not a surround; allowed.
#[test]
fn test_dsl_096_flanking_ok() {
    let (p, _) = seed(3, 5);
    let candidate_hash = Bytes32::new([0xBBu8; 32]);
    assert!(p.check_attestation(5, 7, &candidate_hash));
    assert!(p.check_attestation(4, 10, &candidate_hash));
}

/// DSL-096 row 4: same source, higher target → not strict on
/// source → not a surround. Also covers lower source + same
/// target (strict on source but not on target).
#[test]
fn test_dsl_096_same_source_higher_target() {
    let (p, _) = seed(3, 5);
    let h = Bytes32::new([0xBBu8; 32]);

    // Same source, higher target.
    assert!(p.check_attestation(3, 6, &h));

    // Lower source, same target.
    assert!(p.check_attestation(2, 5, &h));

    // Lower source, lower target (double-vote but not surround).
    assert!(p.check_attestation(1, 4, &h));
}
