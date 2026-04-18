//! Requirement DSL-084: when `in_finality_stall == true`,
//! `compute_flag_deltas` zeroes the `reward` field for every
//! validator. Penalties continue to apply.
//!
//! Traces to: docs/resources/SPEC.md §8.3, §22.9.
//!
//! # Role
//!
//! Mirrors Ethereum inactivity-leak semantics: while finality
//! is stalled, honest attesters stop being paid but missed
//! attestations continue to debit. Keeps the sanction pressure
//! on non-participants while removing the positive-sum reward
//! that would offset the leak.
//!
//! # Test matrix (maps to DSL-084 Test Plan)
//!
//!   1. `test_dsl_084_stall_rewards_zeroed` — all flags hit + stall
//!      → reward=0, penalty=0 (nothing to penalise)
//!   2. `test_dsl_084_stall_penalties_still_apply` — all missed +
//!      stall → reward=0, penalty = base * 40 / 64 (same as
//!      non-stall)
//!   3. `test_dsl_084_no_stall_normal` — all flags hit, no stall
//!      → reward = base * 54 / 64 (matches DSL-082 all-three row)

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, ParticipationFlags,
    ParticipationTracker, TIMELY_HEAD_FLAG_INDEX, TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT, WEIGHT_DENOMINATOR,
    base_reward, compute_flag_deltas,
};

const VALIDATOR_COUNT: usize = 4;
const TOTAL_ACTIVE: u64 = MIN_EFFECTIVE_BALANCE * VALIDATOR_COUNT as u64;

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

fn flags_with(bits: &[u8]) -> ParticipationFlags {
    let mut f = ParticipationFlags::default();
    for b in bits {
        f.set(*b);
    }
    f
}

struct FlatBalances;
impl EffectiveBalanceView for FlatBalances {
    fn get(&self, _: u32) -> u64 {
        MIN_EFFECTIVE_BALANCE
    }
    fn total_active(&self) -> u64 {
        TOTAL_ACTIVE
    }
}

fn tracker_with_prev_flags(bits: &[u8]) -> ParticipationTracker {
    let mut t = ParticipationTracker::new(VALIDATOR_COUNT, 4);
    if !bits.is_empty() {
        t.record_attestation(&data_at_slot(100), &[0u32], flags_with(bits))
            .unwrap();
    }
    t.rotate_epoch(5, VALIDATOR_COUNT);
    t
}

fn expected_base() -> u64 {
    base_reward(MIN_EFFECTIVE_BALANCE, TOTAL_ACTIVE)
}

/// DSL-084 row 1: all flags hit + `in_finality_stall = true`
/// → reward zeroed for EVERY validator. Penalty also zero
/// here because validator 0 missed nothing and the other
/// slots didn't attest at all (all three missed but stall
/// still zeroes nothing on the penalty side).
///
/// Wait — the other slots DO incur penalties even in stall.
/// This test focuses on validator 0 (all flags set → no
/// penalty). Stall → reward=0 AND penalty=0 for validator 0.
#[test]
fn test_dsl_084_stall_rewards_zeroed() {
    let t = tracker_with_prev_flags(&[
        TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
        TIMELY_HEAD_FLAG_INDEX,
    ]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE, true);

    assert_eq!(deltas[0].reward, 0, "stall zeroes reward on all-hit");
    assert_eq!(deltas[0].penalty, 0, "all flags hit → no penalty either");
}

/// DSL-084 row 2: all flags missed + stall → reward=0, penalty
/// = base * 40 / 64 (unchanged from non-stall DSL-083).
/// Validator 0 contributes the all-miss composite; stall
/// zeroes rewards but not penalties.
#[test]
fn test_dsl_084_stall_penalties_still_apply() {
    let t = tracker_with_prev_flags(&[]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE, true);

    let base = expected_base();
    let source_pen = base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR;
    let target_pen = base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR;
    let expected_penalty = source_pen + target_pen;

    for d in &deltas[..] {
        assert_eq!(d.reward, 0, "stall zeroes reward on all-miss");
        assert_eq!(
            d.penalty, expected_penalty,
            "all-miss penalty unchanged by stall",
        );
    }
}

/// DSL-084 row 3: all flags hit + NO stall → reward = base *
/// 54 / 64. Negative control — confirms rewards still flow
/// when the stall flag is false. Matches the DSL-082 all-three
/// row.
#[test]
fn test_dsl_084_no_stall_normal() {
    let t = tracker_with_prev_flags(&[
        TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
        TIMELY_HEAD_FLAG_INDEX,
    ]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE, false);

    let base = expected_base();
    let expected = base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR
        + base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR
        + base * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR;
    assert_eq!(deltas[0].reward, expected, "no stall → normal reward");
    assert_eq!(deltas[0].penalty, 0);
}
