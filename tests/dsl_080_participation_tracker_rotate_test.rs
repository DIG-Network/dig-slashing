//! Requirement DSL-080: `ParticipationTracker::rotate_epoch`
//! swaps `current_epoch` into `previous_epoch`, resets
//! `current_epoch` to `validator_count` zero-initialised slots,
//! and updates `current_epoch_number`.
//!
//! Traces to: docs/resources/SPEC.md §8.2, §10, §22.9.
//!
//! # Role
//!
//! Epoch-boundary transition called by `run_epoch_boundary`
//! (SPEC §10). After rotation, reward / penalty computation
//! reads `previous_flags` from the just-moved buffer.
//!
//! # Test matrix (maps to DSL-080 Test Plan)
//!
//!   1. `test_dsl_080_swap` — pre-rotation current flags land
//!      in post-rotation previous
//!   2. `test_dsl_080_current_zeroed` — every post-rotation
//!      current slot is `ParticipationFlags(0)`
//!   3. `test_dsl_080_resize_to_validator_count` — new current
//!      length equals the rotated-in `validator_count`
//!   4. `test_dsl_080_epoch_number_updated` —
//!      `current_epoch_number == new_epoch`

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, ParticipationFlags, ParticipationTracker,
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

/// DSL-080 row 1: what was `current` before rotation becomes
/// `previous` after. Pre-populate current via
/// `record_attestation` then rotate.
#[test]
fn test_dsl_080_swap() {
    let mut t = ParticipationTracker::new(10, 4);
    let data = sample_data();

    t.record_attestation(
        &data,
        &[1u32, 3, 5],
        flags_with(&[TIMELY_SOURCE_FLAG_INDEX]),
    )
    .unwrap();
    t.record_attestation(
        &data,
        &[2u32, 5, 8],
        flags_with(&[TIMELY_TARGET_FLAG_INDEX]),
    )
    .unwrap();

    // Snapshot current pre-rotation per affected index.
    let pre_idx_1 = t.current_flags(1).unwrap();
    let pre_idx_5 = t.current_flags(5).unwrap();
    let pre_idx_8 = t.current_flags(8).unwrap();

    t.rotate_epoch(5, 10);

    assert_eq!(
        t.previous_flags(1).unwrap(),
        pre_idx_1,
        "previous[1] == pre-rotation current[1]",
    );
    assert_eq!(
        t.previous_flags(5).unwrap(),
        pre_idx_5,
        "previous[5] == pre-rotation current[5] (both SOURCE + TARGET)",
    );
    assert_eq!(t.previous_flags(8).unwrap(), pre_idx_8);
}

/// DSL-080 row 2: post-rotation `current_epoch` is all zero.
#[test]
fn test_dsl_080_current_zeroed() {
    let mut t = ParticipationTracker::new(8, 4);
    let data = sample_data();

    t.record_attestation(
        &data,
        &[0u32, 3, 7],
        flags_with(&[TIMELY_SOURCE_FLAG_INDEX]),
    )
    .unwrap();

    t.rotate_epoch(5, 8);

    for idx in 0u32..8 {
        assert_eq!(
            t.current_flags(idx).unwrap(),
            ParticipationFlags::default(),
            "idx={idx} must be zero after rotation",
        );
    }
}

/// DSL-080 row 3: `current.len() == validator_count` passed to
/// rotate_epoch. Covers growth + shrinkage.
#[test]
fn test_dsl_080_resize_to_validator_count() {
    let mut t = ParticipationTracker::new(5, 4);
    assert_eq!(t.validator_count(), 5);

    // Grow.
    t.rotate_epoch(5, 12);
    assert_eq!(t.validator_count(), 12);
    for idx in 0u32..12 {
        assert_eq!(t.current_flags(idx).unwrap(), ParticipationFlags::default());
    }

    // Shrink.
    t.rotate_epoch(6, 3);
    assert_eq!(t.validator_count(), 3);
    assert!(
        t.current_flags(3).is_none(),
        "idx 3 out of range after shrink"
    );
}

/// DSL-080 row 4: `current_epoch_number == new_epoch` after
/// rotation. Pre-rotation number is irrelevant.
#[test]
fn test_dsl_080_epoch_number_updated() {
    let mut t = ParticipationTracker::new(10, 4);
    assert_eq!(t.current_epoch_number(), 4);

    t.rotate_epoch(5, 10);
    assert_eq!(t.current_epoch_number(), 5);

    // Repeated rotation bumps further.
    t.rotate_epoch(12, 10);
    assert_eq!(t.current_epoch_number(), 12);
}
