//! Requirement DSL-007: `AttesterSlashing::slashable_indices()` returns the
//! sorted (strictly ascending, deduped) set-intersection of the two
//! attestations' `attesting_indices`.
//!
//! Traces to: docs/resources/SPEC.md §3.4 (AttesterSlashing + helper),
//! §22.1 (catalogue row).
//!
//! # Role in the slashing pipeline
//!
//! `slashable_indices` is the per-validator fan-out for attester slashings:
//! every index in the result is a validator who signed BOTH attestations
//! and is therefore caught in a double-vote or surround-vote. The
//! `SlashingManager::submit_evidence` slash loop (DSL-022) iterates this
//! list; `verify_attester_slashing` (DSL-016) rejects empty results as
//! `EmptySlashableIntersection`.
//!
//! # Preconditions
//!
//! The two-pointer sweep assumes both index lists are already ascending
//! and deduped — the contract established by `IndexedAttestation::validate_structure`
//! (DSL-005). If either input is malformed, the result is deterministic
//! but may not be the "true" mathematical intersection; callers MUST
//! validate structure first.
//!
//! # Test matrix (maps to DSL-007 Test Plan)
//!
//!   1. `test_dsl_007_disjoint_empty`
//!   2. `test_dsl_007_full_overlap`
//!   3. `test_dsl_007_partial_overlap`
//!   4. `test_dsl_007_sorted_ascending` (invariant check)
//!   5. `test_dsl_007_deterministic` (idempotency)
//!   6. `test_dsl_007_empty_inputs` (edge: either side empty)
//!   7. `test_dsl_007_single_element_overlap`

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
};

/// Canonical `AttestationData` for fixtures — the helper is ordering-agnostic
/// so we can reuse one payload across both halves of each slashing.
fn sample_data() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
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

/// Build an `AttesterSlashing` with the provided two ascending+deduped
/// committee index lists. Dummy signatures; DSL-007 does not touch BLS.
fn build(a: Vec<u32>, b: Vec<u32>) -> AttesterSlashing {
    let mk = |indices: Vec<u32>| IndexedAttestation {
        attesting_indices: indices,
        data: sample_data(),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    AttesterSlashing {
        attestation_a: mk(a),
        attestation_b: mk(b),
    }
}

/// DSL-007 row 1: disjoint index lists produce an empty intersection.
///
/// Proves the helper returns a genuine empty vec (not, say, one of the
/// inputs by accident). Downstream, `verify_attester_slashing` (DSL-016)
/// translates this into `EmptySlashableIntersection`.
#[test]
fn test_dsl_007_disjoint_empty() {
    let s = build(vec![1, 2], vec![3, 4]);
    assert_eq!(s.slashable_indices(), Vec::<u32>::new());
}

/// DSL-007 row 2: identical inputs return the same index set.
///
/// The whole committee signed both attestations — every member is caught.
#[test]
fn test_dsl_007_full_overlap() {
    let s = build(vec![1, 2, 3], vec![1, 2, 3]);
    assert_eq!(s.slashable_indices(), vec![1, 2, 3]);
}

/// DSL-007 row 3: partial overlap returns exactly the intersection.
///
/// a = [1,2,3]; b = [2,3,4]; ∩ = [2,3]. Only members who appear in BOTH
/// lists are slashable — index 1 (only in a) and index 4 (only in b) are
/// not double-signers.
#[test]
fn test_dsl_007_partial_overlap() {
    let s = build(vec![1, 2, 3], vec![2, 3, 4]);
    assert_eq!(s.slashable_indices(), vec![2, 3]);
}

/// DSL-007 row 4: output invariant — strictly ascending, no duplicates.
///
/// Exercises a harder partial-overlap with interleaved gaps on both sides.
/// Verifies the two-pointer sweep doesn't accidentally emit duplicates
/// or miss order-preservation.
#[test]
fn test_dsl_007_sorted_ascending() {
    let s = build(vec![1, 3, 5, 7, 9], vec![2, 3, 5, 8, 9]);
    let out = s.slashable_indices();
    assert_eq!(out, vec![3, 5, 9]);
    // Invariant check independent of expected value: every consecutive
    // pair is strictly ascending.
    for w in out.windows(2) {
        assert!(
            w[0] < w[1],
            "slashable_indices must be strictly ascending, saw {:?}",
            w,
        );
    }
}

/// DSL-007 row 5: deterministic — repeated calls return byte-equal output.
///
/// Guards against accidental use of a hasher, iterator with undefined
/// order (e.g. `HashSet::iter`), or shared mutable state. The helper MUST
/// be a pure function of its inputs.
#[test]
fn test_dsl_007_deterministic() {
    let s = build(vec![1, 2, 3, 4], vec![2, 4, 6, 8]);
    let a = s.slashable_indices();
    let b = s.slashable_indices();
    let c = s.slashable_indices();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

/// DSL-007 edge: one side empty → empty intersection regardless of the other.
///
/// The two-pointer loop exits immediately when either side is exhausted,
/// so an empty input on either side returns `[]` without examining the
/// other. Prevents an off-by-one that would loop past `a.len()` / `b.len()`.
#[test]
fn test_dsl_007_empty_inputs() {
    let empty: Vec<u32> = Vec::new();
    assert_eq!(build(vec![], vec![1, 2, 3]).slashable_indices(), empty);
    assert_eq!(build(vec![1, 2, 3], vec![]).slashable_indices(), empty);
    assert_eq!(build(vec![], vec![]).slashable_indices(), empty);
}

/// DSL-007 edge: single-element overlap.
///
/// Smallest non-empty intersection possible. Guards against a subtle
/// advance-past-match bug that would drop the last match when both
/// pointers hit their final element simultaneously.
#[test]
fn test_dsl_007_single_element_overlap() {
    assert_eq!(build(vec![5], vec![5]).slashable_indices(), vec![5]);
    // Match at the tail of both sides.
    assert_eq!(build(vec![1, 5], vec![3, 5]).slashable_indices(), vec![5]);
}
