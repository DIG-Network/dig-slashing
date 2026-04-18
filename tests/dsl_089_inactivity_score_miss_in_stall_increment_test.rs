//! Requirement DSL-089: `update_for_epoch` increments the
//! inactivity score by `INACTIVITY_SCORE_BIAS` (=4) for each
//! validator that MISSED `TIMELY_TARGET` during a finality
//! stall. Outside the stall, missed targets do NOT increment.
//! Saturating at `u64::MAX`.
//!
//! Traces to: docs/resources/SPEC.md §9.2, §2.4, §22.10.
//!
//! # Test matrix (maps to DSL-089 Test Plan)
//!
//!   1. `test_dsl_089_miss_in_stall_increments` — miss + stall
//!      → score += 4
//!   2. `test_dsl_089_miss_no_stall_no_increment` — miss +
//!      no-stall → unchanged (DSL-090 global recovery lands
//!      separately)
//!   3. `test_dsl_089_saturates` — score = u64::MAX + miss +
//!      stall → u64::MAX (saturating_add pin)
//!   4. `test_dsl_089_linear_growth` — 10 consecutive misses in
//!      stall → score += 40

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, INACTIVITY_SCORE_BIAS, InactivityScoreTracker,
    ParticipationTracker,
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

/// Build participation with `hit_indices` TARGET-set in the
/// previous epoch. Other slots miss.
fn participation_with_target_hits(
    validator_count: usize,
    hit_indices: &[u32],
) -> ParticipationTracker {
    use dig_slashing::{ParticipationFlags, TIMELY_TARGET_FLAG_INDEX};
    let mut t = ParticipationTracker::new(validator_count, 0);
    if !hit_indices.is_empty() {
        let mut f = ParticipationFlags::default();
        f.set(TIMELY_TARGET_FLAG_INDEX);
        t.record_attestation(&data_at_slot(0), hit_indices, f)
            .unwrap();
    }
    t.rotate_epoch(1, validator_count);
    t
}

/// DSL-089 row 1: miss + stall → score += INACTIVITY_SCORE_BIAS.
/// Validator 0 misses, validator 1 hits; stall=true.
#[test]
fn test_dsl_089_miss_in_stall_increments() {
    assert_eq!(INACTIVITY_SCORE_BIAS, 4);

    let mut scores = InactivityScoreTracker::new(2);
    scores.set_score(0, 10);
    scores.set_score(1, 10);

    // Validator 1 hits target; validator 0 misses.
    let participation = participation_with_target_hits(2, &[1u32]);

    scores.update_for_epoch(&participation, true);

    assert_eq!(scores.score(0), Some(14), "miss+stall → +4");
    assert_eq!(scores.score(1), Some(9), "hit → -1 (DSL-088)");
}

/// DSL-089 row 2: miss + NO stall → score unchanged on the
/// miss branch. (DSL-090 global -16 recovery is separate —
/// not yet implemented, so scores stay put here.)
#[test]
fn test_dsl_089_miss_no_stall_no_increment() {
    let mut scores = InactivityScoreTracker::new(2);
    scores.set_score(0, 10);

    // No hits — validator 0 misses.
    let participation = participation_with_target_hits(2, &[]);

    scores.update_for_epoch(&participation, false);

    // Miss+no-stall does NOT fire the bias branch. DSL-090
    // global recovery (now active) subtracts
    // INACTIVITY_SCORE_RECOVERY_RATE (16); from 10 that
    // saturates to 0. The critical DSL-089 guarantee is
    // "score did NOT add 4" — i.e. no bias when stall is
    // false.
    assert!(
        scores.score(0).unwrap() <= 10,
        "miss without stall must not add INACTIVITY_SCORE_BIAS",
    );
}

/// DSL-089 row 3: score = u64::MAX + miss + stall → saturates.
#[test]
fn test_dsl_089_saturates() {
    let mut scores = InactivityScoreTracker::new(1);
    scores.set_score(0, u64::MAX);

    let participation = participation_with_target_hits(1, &[]);
    scores.update_for_epoch(&participation, true);

    assert_eq!(scores.score(0), Some(u64::MAX));
}

/// DSL-089 row 4: 10 consecutive update_for_epoch calls with
/// miss+stall each → score grows linearly by 40.
#[test]
fn test_dsl_089_linear_growth() {
    let mut scores = InactivityScoreTracker::new(1);
    scores.set_score(0, 0);

    let participation = participation_with_target_hits(1, &[]);

    for _ in 0..10 {
        scores.update_for_epoch(&participation, true);
    }

    assert_eq!(scores.score(0), Some(10 * INACTIVITY_SCORE_BIAS));
}
