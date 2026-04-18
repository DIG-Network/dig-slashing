//! Requirement DSL-083: `compute_flag_deltas` debits each
//! validator by `base_reward * weight / WEIGHT_DENOMINATOR`
//! for each UNSET SOURCE or TARGET flag. HEAD miss is EXEMPT
//! (Ethereum Altair parity: head timing is too network-
//! dependent to fairly punish).
//!
//! Traces to: docs/resources/SPEC.md §8.3, §22.9.
//!
//! # Penalty table
//!
//! | Flag missed   | Penalty       |
//! |---------------|---------------|
//! | TIMELY_SOURCE | base * 14/64  |
//! | TIMELY_TARGET | base * 26/64  |
//! | TIMELY_HEAD   | 0 (exempt)    |
//!
//! All three missed → `base * 40 / 64`.
//!
//! # Test matrix (maps to DSL-083 Test Plan)
//!
//!   1. `test_dsl_083_source_miss_penalty`  — SOURCE unset;
//!      TARGET+HEAD set → penalty = base * 14 / 64
//!   2. `test_dsl_083_target_miss_penalty`  — TARGET unset →
//!      penalty = base * 26 / 64
//!   3. `test_dsl_083_head_miss_no_penalty` — HEAD unset;
//!      SOURCE+TARGET set → penalty == 0 (exempt)
//!   4. `test_dsl_083_all_miss_composite`   — no flags set →
//!      penalty = base * 40 / 64

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, EffectiveBalanceView, MIN_EFFECTIVE_BALANCE, ParticipationFlags,
    ParticipationTracker, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_SOURCE_WEIGHT,
    TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_WEIGHT, WEIGHT_DENOMINATOR, base_reward,
    compute_flag_deltas,
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

/// Populate `previous_epoch[0]` with `bits` then rotate so
/// `compute_flag_deltas` reads from it.
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

/// DSL-083 row 1: SOURCE missed (only TARGET+HEAD set) →
/// penalty = base * 14 / 64. TARGET + HEAD are set so only the
/// SOURCE-miss branch fires.
#[test]
fn test_dsl_083_source_miss_penalty() {
    let t = tracker_with_prev_flags(&[TIMELY_TARGET_FLAG_INDEX, TIMELY_HEAD_FLAG_INDEX]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE, false);

    let base = expected_base();
    let expected = base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR;
    assert_eq!(deltas[0].penalty, expected);
}

/// DSL-083 row 2: TARGET missed → penalty = base * 26 / 64.
#[test]
fn test_dsl_083_target_miss_penalty() {
    let t = tracker_with_prev_flags(&[TIMELY_SOURCE_FLAG_INDEX, TIMELY_HEAD_FLAG_INDEX]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE, false);

    let base = expected_base();
    let expected = base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR;
    assert_eq!(deltas[0].penalty, expected);
}

/// DSL-083 row 3: HEAD missed (SOURCE+TARGET set) → penalty =
/// 0. Head-miss exemption — timing too network-dependent.
#[test]
fn test_dsl_083_head_miss_no_penalty() {
    let t = tracker_with_prev_flags(&[TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE, false);

    assert_eq!(
        deltas[0].penalty, 0,
        "HEAD-miss is exempt — SOURCE+TARGET set → no penalty",
    );
}

/// DSL-083 row 4: all three missed → penalty = base * (14+26) / 64 =
/// base * 40 / 64. HEAD contributes 0 to the penalty even when
/// missed.
#[test]
fn test_dsl_083_all_miss_composite() {
    let t = tracker_with_prev_flags(&[]);
    let deltas = compute_flag_deltas(&t, &FlatBalances, TOTAL_ACTIVE, false);

    let base = expected_base();
    let source_pen = base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR;
    let target_pen = base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR;
    let expected = source_pen + target_pen;
    assert_eq!(deltas[0].penalty, expected);

    // Composite sum matches base * 40 / 64.
    assert_eq!(
        TIMELY_SOURCE_WEIGHT + TIMELY_TARGET_WEIGHT,
        40,
        "SPEC §8.3 composite penalty weight",
    );
}
