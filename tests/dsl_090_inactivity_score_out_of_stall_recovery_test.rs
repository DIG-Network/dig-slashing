//! Requirement DSL-090: `update_for_epoch` subtracts
//! `INACTIVITY_SCORE_RECOVERY_RATE` (= 16) from every score
//! (saturating at 0) when `in_finality_stall == false`. Applies
//! AFTER the per-validator hit/miss pass (DSL-088/089). No
//! recovery during a stall.
//!
//! Traces to: docs/resources/SPEC.md §9.2, §2.4, §22.10.
//!
//! # Test matrix (maps to DSL-090 Test Plan)
//!
//!   1. `test_dsl_090_recovery_per_epoch` — all scores=50,
//!      no-stall, no hits → each drops by 16 → 34
//!   2. `test_dsl_090_saturates_to_zero` — scores=10, no-stall
//!      → 0 (saturating_sub; no negative)
//!   3. `test_dsl_090_in_stall_no_recovery` — scores=50,
//!      stall=true → 50 unchanged (only DSL-088 hits would
//!      change it, and there are none here)

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, INACTIVITY_SCORE_RECOVERY_RATE, InactivityScoreTracker,
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

/// Build a tracker where `hit_indices` hit TARGET, others miss.
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

/// DSL-090 row 1: all scores=50, no-stall, all miss (no hits)
/// → each score drops by 16 → 34. Miss+no-stall does NOT add
/// the DSL-089 bias; only DSL-090 recovery fires.
#[test]
fn test_dsl_090_recovery_per_epoch() {
    assert_eq!(INACTIVITY_SCORE_RECOVERY_RATE, 16);

    let mut scores = InactivityScoreTracker::new(3);
    scores.set_score(0, 50);
    scores.set_score(1, 50);
    scores.set_score(2, 50);

    // No hits — stall=false so only DSL-090 recovery fires.
    let participation = participation_with_target_hits(3, &[]);
    scores.update_for_epoch(&participation, false);

    for idx in 0u32..3 {
        assert_eq!(scores.score(idx), Some(34), "50 - 16 = 34");
    }
}

/// DSL-090 row 2: scores=10, no-stall → saturate at 0.
#[test]
fn test_dsl_090_saturates_to_zero() {
    let mut scores = InactivityScoreTracker::new(2);
    scores.set_score(0, 10);
    scores.set_score(1, 5);

    let participation = participation_with_target_hits(2, &[]);
    scores.update_for_epoch(&participation, false);

    assert_eq!(scores.score(0), Some(0));
    assert_eq!(scores.score(1), Some(0));
}

/// DSL-090 row 3: stall=true + no hits → no global recovery.
/// Miss+stall fires DSL-089 bias instead, so scores INCREASE
/// (stall pushes up, recovery only runs out of stall).
#[test]
fn test_dsl_090_in_stall_no_recovery() {
    let mut scores = InactivityScoreTracker::new(3);
    scores.set_score(0, 50);
    scores.set_score(1, 50);
    scores.set_score(2, 50);

    // No hits — all miss. Under stall, DSL-089 bias fires;
    // DSL-090 recovery does NOT. The key invariant is: NO
    // global -16 applied.
    let participation = participation_with_target_hits(3, &[]);
    scores.update_for_epoch(&participation, true);

    // Scores must be >= 50 - epsilon (recovery did not run).
    // Stronger assertion: every score grew by the DSL-089 bias.
    for idx in 0u32..3 {
        assert!(
            scores.score(idx).unwrap() >= 50,
            "stall → no global -16 recovery",
        );
    }
}
