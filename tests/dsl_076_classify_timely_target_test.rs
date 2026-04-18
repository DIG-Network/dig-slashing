//! Requirement DSL-076: `classify_timeliness` sets the
//! `TIMELY_TARGET` flag iff
//! `delay ∈ [MIN_ATTESTATION_INCLUSION_DELAY,
//! TIMELY_TARGET_MAX_DELAY_SLOTS]` AND `is_canonical_target`.
//!
//! Traces to: docs/resources/SPEC.md §8.1, §2.5, §22.9.
//!
//! # Predicate
//!
//! `delay ∈ [1, 32] ∧ is_canonical_target ⟹ TIMELY_TARGET set`.
//!
//! Window is wider than `TIMELY_SOURCE` (1..=5) — an attestation
//! slightly slow to include can still credit the target vote.
//!
//! # Test matrix (maps to DSL-076 Test Plan)
//!
//!   1. `test_dsl_076_delay_1_canonical_set` — lower boundary
//!   2. `test_dsl_076_delay_32_boundary` — upper boundary (=SLOTS_PER_EPOCH)
//!   3. `test_dsl_076_delay_33_not_set` — past upper boundary
//!   4. `test_dsl_076_non_canonical_not_set` — canonicality gate

use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, Checkpoint, ParticipationFlags, TIMELY_TARGET_MAX_DELAY_SLOTS,
    classify_timeliness,
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

/// Classify with a specific delay + target canonicality signal.
/// `source_is_justified = false` so only the target leg drives
/// the outcome (confines the test to DSL-076 semantics).
/// `is_canonical_head = false` (DSL-077 not yet active).
fn classify(delay: u64, is_canonical_target: bool) -> ParticipationFlags {
    let data = data_at_slot(100);
    let inclusion_slot = 100 + delay;
    classify_timeliness(&data, inclusion_slot, false, is_canonical_target, false)
}

/// DSL-076 row 1: delay=1 + canonical target → TARGET set.
#[test]
fn test_dsl_076_delay_1_canonical_set() {
    assert!(classify(1, true).is_target_timely());
}

/// DSL-076 row 2: delay=32 (=`TIMELY_TARGET_MAX_DELAY_SLOTS`)
/// + canonical → still set (closed boundary).
#[test]
fn test_dsl_076_delay_32_boundary() {
    assert_eq!(TIMELY_TARGET_MAX_DELAY_SLOTS, 32);
    assert!(classify(32, true).is_target_timely());
}

/// DSL-076 row 3: delay=33 → not set. Also spot-check delay=0
/// (below lower boundary).
#[test]
fn test_dsl_076_delay_33_not_set() {
    assert!(!classify(33, true).is_target_timely());
    assert!(!classify(0, true).is_target_timely());
}

/// DSL-076 row 4: in-range delay + `is_canonical_target = false`
/// → not set. Exercises the canonicality gate.
#[test]
fn test_dsl_076_non_canonical_not_set() {
    for delay in [1u64, 10, 32] {
        assert!(
            !classify(delay, false).is_target_timely(),
            "delay={delay} + non-canonical → TARGET not set",
        );
    }
}
