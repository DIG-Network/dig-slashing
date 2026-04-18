//! Requirement DSL-082: `compute_flag_deltas` credits each
//! validator by `base_reward * weight / WEIGHT_DENOMINATOR` for
//! each flag hit in `previous_epoch`.
//!
//! Traces to: docs/resources/SPEC.md §8.3, §2.3, §22.9.
//!
//! # Weights (mainnet)
//!
//! | Flag          | Weight | Share   |
//! |---------------|--------|---------|
//! | TIMELY_SOURCE | 14/64  | 21.875% |
//! | TIMELY_TARGET | 26/64  | 40.625% |
//! | TIMELY_HEAD   | 14/64  | 21.875% |
//!
//! All three set → 54/64 ≈ 84.375%. The unassigned 2/64 slice
//! represents the unused sync-committee slot.
//!
//! # Test matrix (maps to DSL-082 Test Plan)
//!
//!   1. `test_dsl_082_source_only_reward`  — base * 14 / 64
//!   2. `test_dsl_082_target_only_reward`  — base * 26 / 64
//!   3. `test_dsl_082_head_only_reward`    — base * 14 / 64
//!   4. `test_dsl_082_all_three_reward`    — base * 54 / 64

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

/// Flat effective-balance view: every validator has
/// `MIN_EFFECTIVE_BALANCE`.
struct FlatBalances;
impl EffectiveBalanceView for FlatBalances {
    fn get(&self, _: u32) -> u64 {
        MIN_EFFECTIVE_BALANCE
    }
    fn total_active(&self) -> u64 {
        TOTAL_ACTIVE
    }
}

/// Populate `previous_epoch[0]` with `bits` and rotate so the
/// deltas compute from it.
fn tracker_with_prev_flags(bits: &[u8]) -> ParticipationTracker {
    let mut t = ParticipationTracker::new(VALIDATOR_COUNT, 4);
    // Flags land in current_epoch first; rotate moves them to
    // previous_epoch where compute_flag_deltas reads from.
    t.record_attestation(&data_at_slot(100), &[0u32], flags_with(bits))
        .unwrap();
    t.rotate_epoch(5, VALIDATOR_COUNT);
    t
}

fn expected_base() -> u64 {
    base_reward(MIN_EFFECTIVE_BALANCE, TOTAL_ACTIVE)
}

/// DSL-082 row 1: SOURCE only → reward = base * 14 / 64.
#[test]
fn test_dsl_082_source_only_reward() {
    let t = tracker_with_prev_flags(&[TIMELY_SOURCE_FLAG_INDEX]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE);

    let base = expected_base();
    let expected = base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR;
    assert_eq!(deltas[0].reward, expected);

    // Other validators with no flags → zero reward. Penalty
    // field may be non-zero once DSL-083 lands (SOURCE+TARGET
    // miss); DSL-082 tests assert reward only.
    for d in &deltas[1..] {
        assert_eq!(d.reward, 0);
    }
}

/// DSL-082 row 2: TARGET only → base * 26 / 64.
#[test]
fn test_dsl_082_target_only_reward() {
    let t = tracker_with_prev_flags(&[TIMELY_TARGET_FLAG_INDEX]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE);

    let base = expected_base();
    let expected = base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR;
    assert_eq!(deltas[0].reward, expected);
}

/// DSL-082 row 3: HEAD only → base * 14 / 64 (same weight as
/// SOURCE).
#[test]
fn test_dsl_082_head_only_reward() {
    let t = tracker_with_prev_flags(&[TIMELY_HEAD_FLAG_INDEX]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE);

    let base = expected_base();
    let expected = base * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR;
    assert_eq!(deltas[0].reward, expected);
}

/// DSL-082 row 4: all three flags → base * 54 / 64. Sum of the
/// three per-flag slices. The remaining 10/64 reward is
/// unassigned (sync-committee share Ethereum uses but DIG does
/// not).
#[test]
fn test_dsl_082_all_three_reward() {
    let t = tracker_with_prev_flags(&[
        TIMELY_SOURCE_FLAG_INDEX,
        TIMELY_TARGET_FLAG_INDEX,
        TIMELY_HEAD_FLAG_INDEX,
    ]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE);

    let base = expected_base();
    let source = base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR;
    let target = base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR;
    let head = base * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR;
    let expected = source + target + head;
    assert_eq!(deltas[0].reward, expected);

    // Hand-verified sum: 54/64 of base minus rounding slips.
    let sum_weights = TIMELY_SOURCE_WEIGHT + TIMELY_TARGET_WEIGHT + TIMELY_HEAD_WEIGHT;
    assert_eq!(sum_weights, 54, "mainnet weight sum");
}
