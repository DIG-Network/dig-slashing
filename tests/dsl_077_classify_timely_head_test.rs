//! Requirement DSL-077: `classify_timeliness` sets the
//! `TIMELY_HEAD` flag iff `delay == MIN_ATTESTATION_INCLUSION_DELAY`
//! (= 1) AND `is_canonical_head`.
//!
//! Traces to: docs/resources/SPEC.md §8.1, §2.5, §22.9.
//!
//! # Predicate
//!
//! `delay == 1 ∧ is_canonical_head ⟹ TIMELY_HEAD set`.
//!
//! Strictest window of the three flags. Matches Ethereum's head
//! vote rule: inclusion in the very next block only.
//!
//! # Test matrix (maps to DSL-077 Test Plan)
//!
//!   1. `test_dsl_077_delay_1_canonical_set`
//!   2. `test_dsl_077_delay_2_not_set` — outside one-slot window
//!   3. `test_dsl_077_delay_0_not_set` — below lower boundary
//!   4. `test_dsl_077_non_canonical_not_set` — canonicality gate

use dig_protocol::Bytes32;
use dig_slashing::{AttestationData, Checkpoint, ParticipationFlags, classify_timeliness};

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

/// Isolate the HEAD check: `source_is_justified = false`,
/// `is_canonical_target = false` so only the head leg can set.
fn classify(delay: u64, is_canonical_head: bool) -> ParticipationFlags {
    let data = data_at_slot(100);
    let inclusion_slot = 100 + delay;
    classify_timeliness(&data, inclusion_slot, false, false, is_canonical_head)
}

/// DSL-077 row 1: delay=1 + canonical head → HEAD set.
#[test]
fn test_dsl_077_delay_1_canonical_set() {
    assert!(classify(1, true).is_head_timely());
}

/// DSL-077 row 2: delay=2 → not set. One-slot window is strict
/// equality, not a range.
#[test]
fn test_dsl_077_delay_2_not_set() {
    assert!(!classify(2, true).is_head_timely());
}

/// DSL-077 row 3: delay=0 → not set.
#[test]
fn test_dsl_077_delay_0_not_set() {
    assert!(!classify(0, true).is_head_timely());
}

/// DSL-077 row 4: delay=1 + `is_canonical_head = false` → not
/// set. Covers the canonicality gate.
#[test]
fn test_dsl_077_non_canonical_not_set() {
    assert!(!classify(1, false).is_head_timely());
}
