//! Requirement DSL-078: `ParticipationTracker::record_attestation`
//! applies `flags` to each validator in `attesting_indices` via
//! bit-OR into `current_epoch[idx]`. Additive, never overwrites.
//! Out-of-range indices return
//! `ParticipationError::IndexOutOfRange`. Does NOT advance
//! `current_epoch_number`.
//!
//! Traces to: docs/resources/SPEC.md §8.2, §22.9.
//!
//! # Role
//!
//! Opens the `ParticipationTracker` state machine. Called per
//! admitted attestation to accumulate flags. Subsequent rewards /
//! penalties read these bits at epoch rotation (DSL-080..086).
//!
//! # Test matrix (maps to DSL-078 Test Plan)
//!
//!   1. `test_dsl_078_flags_applied` — record SOURCE for 3
//!      indices → each has bit 0 set
//!   2. `test_dsl_078_additive_or` — SOURCE then TARGET on same
//!      index → both bits set
//!   3. `test_dsl_078_out_of_range_error` — idx ≥ validator_count
//!      → `IndexOutOfRange(idx)`
//!   4. `test_dsl_078_epoch_number_unchanged` — recording does
//!      NOT bump `current_epoch_number`

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, ParticipationError, ParticipationFlags, ParticipationTracker,
    TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};

fn sample_data() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0u8; 32]),
        source: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
        target: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
    }
}

fn flags_with(bits: &[u8]) -> ParticipationFlags {
    let mut f = ParticipationFlags::default();
    for b in bits {
        f.set(*b);
    }
    f
}

/// DSL-078 row 1: record SOURCE flag for 3 indices. Each index
/// ends up with bit 0 set; unrelated indices stay zero.
#[test]
fn test_dsl_078_flags_applied() {
    let mut t = ParticipationTracker::new(10, 5);
    let data = sample_data();
    let indices = vec![2u32, 4, 7];

    t.record_attestation(&data, &indices, flags_with(&[TIMELY_SOURCE_FLAG_INDEX]))
        .unwrap();

    for idx in &indices {
        let f = t.current_flags(*idx).unwrap();
        assert!(f.is_source_timely(), "idx={idx} must have SOURCE set");
        assert!(!f.is_target_timely());
        assert!(!f.is_head_timely());
    }
    // Unrelated indices untouched.
    for idx in [0u32, 1, 3, 5, 6, 8, 9] {
        assert_eq!(t.current_flags(idx).unwrap().0, 0);
    }
}

/// DSL-078 row 2: sequential records OR-merge bits. SOURCE then
/// TARGET on the same index → both bits set; neither overwrites
/// the other.
#[test]
fn test_dsl_078_additive_or() {
    let mut t = ParticipationTracker::new(10, 5);
    let data = sample_data();
    let indices = vec![3u32];

    t.record_attestation(&data, &indices, flags_with(&[TIMELY_SOURCE_FLAG_INDEX]))
        .unwrap();
    t.record_attestation(&data, &indices, flags_with(&[TIMELY_TARGET_FLAG_INDEX]))
        .unwrap();

    let f = t.current_flags(3).unwrap();
    assert!(f.is_source_timely(), "SOURCE preserved after TARGET record");
    assert!(f.is_target_timely(), "TARGET added");
    assert!(!f.is_head_timely(), "HEAD still zero");

    // Idempotent on repeat of the same flag.
    t.record_attestation(&data, &indices, flags_with(&[TIMELY_SOURCE_FLAG_INDEX]))
        .unwrap();
    let f = t.current_flags(3).unwrap();
    assert_eq!(f.0, 0b0000_0011, "bit-OR is idempotent on repeat");
}

/// DSL-078 row 3: idx == validator_count is out of range
/// (indices are 0-based), and anything beyond returns
/// `IndexOutOfRange(idx)`.
#[test]
fn test_dsl_078_out_of_range_error() {
    let mut t = ParticipationTracker::new(5, 5);
    let data = sample_data();
    let flags = flags_with(&[TIMELY_SOURCE_FLAG_INDEX]);

    // idx 5 is out of range for validator_count=5.
    let err = t.record_attestation(&data, &[5u32], flags).unwrap_err();
    assert_eq!(err, ParticipationError::IndexOutOfRange(5));

    // Mixed: leading in-range, then out-of-range. The error
    // SHOULD carry the FIRST offending index.
    let mut t2 = ParticipationTracker::new(5, 5);
    let err2 = t2
        .record_attestation(&data, &[1u32, 2, 99], flags)
        .unwrap_err();
    assert_eq!(err2, ParticipationError::IndexOutOfRange(99));
}

/// DSL-078 row 4: recording does NOT advance
/// `current_epoch_number`. Epoch advancement is DSL-080's job.
#[test]
fn test_dsl_078_epoch_number_unchanged() {
    let mut t = ParticipationTracker::new(10, 5);
    let data = sample_data();
    assert_eq!(t.current_epoch_number(), 5);

    t.record_attestation(
        &data,
        &[0u32, 3, 9],
        flags_with(&[TIMELY_SOURCE_FLAG_INDEX]),
    )
    .unwrap();
    assert_eq!(
        t.current_epoch_number(),
        5,
        "record_attestation must not touch current_epoch_number",
    );
}
