//! Requirement DSL-079: `ParticipationTracker::record_attestation`
//! MUST reject non-strictly-ascending `attesting_indices`.
//! Non-monotonic → `NonAscendingIndices`; duplicate →
//! `DuplicateIndex(idx)`. Structural check runs BEFORE the
//! bit-OR pass so malformed input never mutates state.
//!
//! Traces to: docs/resources/SPEC.md §8.2, §22.9.
//!
//! # Test matrix (maps to DSL-079 Test Plan)
//!
//!   1. `test_dsl_079_non_ascending_rejected` — `[3, 2, 1]`
//!   2. `test_dsl_079_duplicate_rejected` — `[1, 1, 2]`
//!   3. `test_dsl_079_single_element_ok` — `[1]` (no windows)
//!   4. `test_dsl_079_ascending_ok` — `[1, 2, 3]`

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, ParticipationError, ParticipationFlags, ParticipationTracker,
    TIMELY_SOURCE_FLAG_INDEX,
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

fn source_flag() -> ParticipationFlags {
    let mut f = ParticipationFlags::default();
    f.set(TIMELY_SOURCE_FLAG_INDEX);
    f
}

/// DSL-079 row 1: `[3, 2, 1]` → `NonAscendingIndices`. No state
/// mutation — all current flags stay at zero.
#[test]
fn test_dsl_079_non_ascending_rejected() {
    let mut t = ParticipationTracker::new(10, 0);
    let err = t
        .record_attestation(&sample_data(), &[3u32, 2, 1], source_flag())
        .unwrap_err();
    assert_eq!(err, ParticipationError::NonAscendingIndices);
    // No side effects.
    for idx in 0u32..10 {
        assert_eq!(t.current_flags(idx).unwrap().0, 0);
    }
}

/// DSL-079 row 2: `[1, 1, 2]` → `DuplicateIndex(1)`. Carries
/// the duplicated index for diagnostics.
#[test]
fn test_dsl_079_duplicate_rejected() {
    let mut t = ParticipationTracker::new(10, 0);
    let err = t
        .record_attestation(&sample_data(), &[1u32, 1, 2], source_flag())
        .unwrap_err();
    assert_eq!(err, ParticipationError::DuplicateIndex(1));
    // No mutation — even though idx 1 is in range, the
    // structural check trips before the OR pass.
    for idx in 0u32..10 {
        assert_eq!(t.current_flags(idx).unwrap().0, 0);
    }
}

/// DSL-079 row 3: single-element `[1]` — no `windows(2)` pairs
/// → structural check trivially passes → Ok with flag applied.
#[test]
fn test_dsl_079_single_element_ok() {
    let mut t = ParticipationTracker::new(10, 0);
    t.record_attestation(&sample_data(), &[1u32], source_flag())
        .unwrap();
    assert!(t.current_flags(1).unwrap().is_source_timely());
}

/// DSL-079 row 4: strictly-ascending `[1, 2, 3]` → Ok. Covers
/// the happy path; bit-OR pass runs.
#[test]
fn test_dsl_079_ascending_ok() {
    let mut t = ParticipationTracker::new(10, 0);
    t.record_attestation(&sample_data(), &[1u32, 2, 3], source_flag())
        .unwrap();
    for idx in [1u32, 2, 3] {
        assert!(t.current_flags(idx).unwrap().is_source_timely());
    }
}
