//! Requirement DSL-075: `classify_timeliness` sets the
//! `TIMELY_SOURCE` flag iff
//! `delay ∈ [MIN_ATTESTATION_INCLUSION_DELAY,
//! TIMELY_SOURCE_MAX_DELAY_SLOTS]` AND `source_is_justified`.
//!
//! Traces to: docs/resources/SPEC.md §8.1, §2.5, §22.9.
//!
//! # Predicate
//!
//! `delay = inclusion_slot.saturating_sub(data.slot)`
//! `TIMELY_SOURCE set ⟺ delay ∈ [1, 5] ∧ source_is_justified`
//!
//! # Test matrix (maps to DSL-075 Test Plan)
//!
//!   1. `test_dsl_075_delay_1_justified_set` — lower boundary
//!   2. `test_dsl_075_delay_5_justified_set` — upper boundary
//!   3. `test_dsl_075_delay_6_not_set` — past upper boundary
//!   4. `test_dsl_075_unjustified_not_set` — justification gate

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, MIN_ATTESTATION_INCLUSION_DELAY, ParticipationFlags,
    TIMELY_SOURCE_MAX_DELAY_SLOTS, classify_timeliness,
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

fn classify(delay: u64, source_is_justified: bool) -> ParticipationFlags {
    let data = data_at_slot(100);
    let inclusion_slot = 100 + delay;
    classify_timeliness(&data, inclusion_slot, source_is_justified, false, false)
}

/// DSL-075 row 1: `delay == 1` (= `MIN_ATTESTATION_INCLUSION_DELAY`)
/// + justified → `TIMELY_SOURCE` set.
#[test]
fn test_dsl_075_delay_1_justified_set() {
    assert_eq!(MIN_ATTESTATION_INCLUSION_DELAY, 1);
    let flags = classify(1, true);
    assert!(flags.is_source_timely(), "delay=1 + justified → SOURCE set");
}

/// DSL-075 row 2: `delay == 5` (= `TIMELY_SOURCE_MAX_DELAY_SLOTS`)
/// + justified → still set (closed boundary).
#[test]
fn test_dsl_075_delay_5_justified_set() {
    assert_eq!(TIMELY_SOURCE_MAX_DELAY_SLOTS, 5);
    let flags = classify(5, true);
    assert!(flags.is_source_timely(), "delay=5 at upper boundary set");
}

/// DSL-075 row 3: `delay == 6` → NOT set regardless of
/// justification state. Also covers `delay == 0` (below
/// `MIN_ATTESTATION_INCLUSION_DELAY`).
#[test]
fn test_dsl_075_delay_6_not_set() {
    assert!(
        !classify(6, true).is_source_timely(),
        "delay=6 past upper boundary → SOURCE not set",
    );
    assert!(
        !classify(0, true).is_source_timely(),
        "delay=0 below lower boundary → SOURCE not set",
    );
}

/// DSL-075 row 4: in-range delay + `source_is_justified = false`
/// → not set. Exercises the justification gate.
#[test]
fn test_dsl_075_unjustified_not_set() {
    for delay in 1..=5u64 {
        let flags = classify(delay, false);
        assert!(
            !flags.is_source_timely(),
            "delay={delay} + not justified → SOURCE not set",
        );
    }
}
