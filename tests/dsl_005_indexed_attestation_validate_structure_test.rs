//! Requirement DSL-005: `IndexedAttestation::validate_structure()` rejects
//! every structurally-invalid input before expensive aggregate BLS verify
//! (DSL-006) is ever attempted.
//!
//! Traces to: docs/resources/SPEC.md §3.3 (IndexedAttestation), §2.7
//! (MAX_VALIDATORS_PER_COMMITTEE, BLS_SIGNATURE_SIZE), §22.1 (catalogue row).
//!
//! # Why this matters
//!
//! `aggregate_verify` is the most expensive operation in slashing evidence
//! verification. A cheap structural guard (`validate_structure`) up front
//! prevents waste on malformed inputs AND anchors the soundness of the
//! intersection math (`AttesterSlashing::slashable_indices`, DSL-007)
//! which assumes strictly-ascending deduped indices.
//!
//! # Test matrix (maps to DSL-005 Test Plan)
//!
//!   1. `test_dsl_005_empty_indices_rejected`
//!   2. `test_dsl_005_over_cap_rejected` (2049 > MAX_VALIDATORS_PER_COMMITTEE)
//!   3. `test_dsl_005_at_cap_accepted` (exactly 2048 — boundary)
//!   4. `test_dsl_005_non_ascending_rejected`
//!   5. `test_dsl_005_duplicate_rejected`
//!   6. `test_dsl_005_bad_sig_width_too_short_rejected`
//!   7. `test_dsl_005_bad_sig_width_too_long_rejected`
//!   8. `test_dsl_005_valid_ascending_accepted`

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    MAX_VALIDATORS_PER_COMMITTEE, SlashingError,
};

/// Canonical `AttestationData` fixture — structural tests don't care about
/// its contents, only the outer `IndexedAttestation` layout.
fn sample_data() -> AttestationData {
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

/// Build an `IndexedAttestation` with the provided indices + a correctly
/// sized (96-byte) dummy signature. The signature bytes are arbitrary
/// because `validate_structure` is a length check — no crypto runs here.
fn build(indices: Vec<u32>) -> IndexedAttestation {
    IndexedAttestation {
        attesting_indices: indices,
        data: sample_data(),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    }
}

/// Helper: assert the returned error is `InvalidIndexedAttestation(_)` and
/// that its reason string contains a keyword from the expected failure mode.
///
/// The catch-all `_ =>` arm guards against future `SlashingError` variants
/// (DSL-011+) drifting into this helper's flow without an explicit update.
/// Today only one variant exists so clippy sees the arm as unreachable;
/// the `#[allow]` below silences that until new variants land.
#[allow(unreachable_patterns)]
fn assert_invalid(ia: IndexedAttestation, reason_keyword: &str) {
    let err = ia
        .validate_structure()
        .expect_err("structure must be rejected");
    match err {
        SlashingError::InvalidIndexedAttestation(msg) => {
            assert!(
                msg.to_lowercase().contains(reason_keyword),
                "error reason `{msg}` must mention `{reason_keyword}`",
            );
        }
        other => panic!("expected InvalidIndexedAttestation, got {other:?}"),
    }
}

/// DSL-005 row 1: empty indices rejected.
///
/// An IndexedAttestation with no attesters is never meaningful: there's
/// nothing to verify a signature against. Callers that somehow produce
/// one (bad deserialiser, malicious wire) must hit this guard.
#[test]
fn test_dsl_005_empty_indices_rejected() {
    assert_invalid(build(vec![]), "empty");
}

/// DSL-005 row 2: indices length over the committee cap is rejected.
///
/// `MAX_VALIDATORS_PER_COMMITTEE = 2048` (SPEC §2.7, Ethereum parity).
/// A sealed wire format with a larger committee is a protocol-level
/// violation. The check uses `>` so the exact cap is still valid (see
/// `test_dsl_005_at_cap_accepted`).
#[test]
fn test_dsl_005_over_cap_rejected() {
    let indices: Vec<u32> = (0..(MAX_VALIDATORS_PER_COMMITTEE as u32 + 1)).collect();
    assert_invalid(build(indices), "exceeds");
}

/// DSL-005 boundary: exactly `MAX_VALIDATORS_PER_COMMITTEE` is accepted.
///
/// Guards against an off-by-one — swapping `>` for `>=` would break this.
#[test]
fn test_dsl_005_at_cap_accepted() {
    let indices: Vec<u32> = (0..MAX_VALIDATORS_PER_COMMITTEE as u32).collect();
    let ia = build(indices);
    assert!(
        ia.validate_structure().is_ok(),
        "exactly MAX_VALIDATORS_PER_COMMITTEE must be accepted",
    );
}

/// DSL-005 row 3: non-ascending indices rejected.
///
/// The intersection math in `slashable_indices` (DSL-007) uses a two-pointer
/// sweep that assumes ascending input. A descending pair is a protocol
/// violation that would otherwise corrupt the intersection result.
#[test]
fn test_dsl_005_non_ascending_rejected() {
    assert_invalid(build(vec![3, 2, 1]), "ascending");
}

/// DSL-005 row 4: duplicate indices rejected.
///
/// Duplicates would inflate the effective-balance-per-attester math in
/// the intersection set (validators counted twice). The `a >= b` loop
/// catches both non-ascending AND duplicate in one pass; the reason
/// string mentions both cases.
#[test]
fn test_dsl_005_duplicate_rejected() {
    assert_invalid(build(vec![1, 1, 2]), "ascending");
}

/// DSL-005 row 5a: signature too short rejected.
#[test]
fn test_dsl_005_bad_sig_width_too_short_rejected() {
    let mut ia = build(vec![1, 2, 3]);
    ia.signature = vec![0u8; BLS_SIGNATURE_SIZE - 1];
    assert_invalid(ia, "signature");
}

/// DSL-005 row 5b: signature too long rejected.
///
/// Proves the check is an exact equality (`!=`), not a lower bound.
#[test]
fn test_dsl_005_bad_sig_width_too_long_rejected() {
    let mut ia = build(vec![1, 2, 3]);
    ia.signature = vec![0u8; BLS_SIGNATURE_SIZE + 1];
    assert_invalid(ia, "signature");
}

/// DSL-005 row 6: well-formed input returns `Ok(())`.
///
/// Ascending, deduped, within-cap indices + 96-byte signature = valid.
/// Single-element committees are also valid (no ordering to check).
#[test]
fn test_dsl_005_valid_ascending_accepted() {
    let ia = build(vec![1, 3, 5]);
    assert!(ia.validate_structure().is_ok());

    // Single-element committee — no adjacent pairs, so the ascending
    // loop is trivially satisfied.
    let single = build(vec![42]);
    assert!(single.validate_structure().is_ok());
}
