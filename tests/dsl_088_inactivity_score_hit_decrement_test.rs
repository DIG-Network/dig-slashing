//! Requirement DSL-088: `InactivityScoreTracker::update_for_epoch`
//! decrements score by 1 (saturating at 0) for every validator
//! whose previous-epoch `TIMELY_TARGET` flag was set. Applies
//! in both stall and no-stall regimes.
//!
//! Traces to: docs/resources/SPEC.md §9.2, §22.10.
//!
//! # Test matrix (maps to DSL-088 Test Plan)
//!
//!   1. `test_dsl_088_hit_decrements` — score=5 + TARGET hit → 4
//!   2. `test_dsl_088_zero_saturates` — score=0 + TARGET hit → 0
//!   3. `test_dsl_088_in_stall_still_decrements` — stall=true +
//!      TARGET hit → score still decrements

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, InactivityScoreTracker, ParticipationFlags, ParticipationTracker,
    TIMELY_TARGET_FLAG_INDEX,
};

fn data_at_slot(slot: u64) -> AttestationData {
    AttestationData {
        slot,
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

fn target_flag() -> ParticipationFlags {
    let mut f = ParticipationFlags::default();
    f.set(TIMELY_TARGET_FLAG_INDEX);
    f
}

/// Build tracker with TARGET set for `hit_indices` in the
/// previous epoch.
fn participation_with_target_hits(
    validator_count: usize,
    hit_indices: &[u32],
) -> ParticipationTracker {
    let mut t = ParticipationTracker::new(validator_count, 0);
    if !hit_indices.is_empty() {
        t.record_attestation(&data_at_slot(0), hit_indices, target_flag())
            .unwrap();
    }
    t.rotate_epoch(1, validator_count);
    t
}

/// DSL-088 row 1: pre-score=5 + TARGET hit → post-score=4.
/// Unrelated indices stay unchanged.
#[test]
fn test_dsl_088_hit_decrements() {
    let mut scores = InactivityScoreTracker::new(4);
    scores.set_score(0, 5);
    scores.set_score(1, 10);
    scores.set_score(2, 0);
    scores.set_score(3, 7);

    let participation = participation_with_target_hits(4, &[0u32]);

    scores.update_for_epoch(&participation, false);

    assert_eq!(scores.score(0), Some(4), "hit → -1");
    assert_eq!(scores.score(1), Some(10), "no hit → unchanged");
    assert_eq!(scores.score(2), Some(0), "no hit → unchanged");
    assert_eq!(scores.score(3), Some(7), "no hit → unchanged");
}

/// DSL-088 row 2: score=0 + TARGET hit → 0 (saturating_sub).
#[test]
fn test_dsl_088_zero_saturates() {
    let mut scores = InactivityScoreTracker::new(2);
    scores.set_score(0, 0);

    let participation = participation_with_target_hits(2, &[0u32]);
    scores.update_for_epoch(&participation, false);

    assert_eq!(scores.score(0), Some(0), "saturating_sub pins at 0");
}

/// DSL-088 row 3: stall=true + TARGET hit → decrement still
/// fires. Hit decrement is regime-independent.
#[test]
fn test_dsl_088_in_stall_still_decrements() {
    let mut scores = InactivityScoreTracker::new(2);
    scores.set_score(0, 10);

    let participation = participation_with_target_hits(2, &[0u32]);

    // stall=true
    scores.update_for_epoch(&participation, true);
    assert_eq!(scores.score(0), Some(9));

    // Repeat to confirm monotonic decrement under stall.
    scores.update_for_epoch(&participation, true);
    assert_eq!(scores.score(0), Some(8));
}
