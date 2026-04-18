//! Requirement DSL-074: `ParticipationFlags(u8)` implements
//! `set(flag_index)` / `has(flag_index)` with the three Altair
//! bit positions and named accessors.
//!
//! Traces to: docs/resources/SPEC.md §3.10, §2.9, §22.9.
//!
//! # Role
//!
//! Opens Phase 3 Participation. Single-byte bitmask powers the
//! Altair-parity attestation-accounting pipeline (DSL-075..086).
//!
//! # Test matrix (maps to DSL-074 Test Plan)
//!
//!   1. `test_dsl_074_default_zero` — `Default::default()` → 0
//!   2. `test_dsl_074_set_bit_0` — `set(0)` then `has(0)` → true
//!   3. `test_dsl_074_set_bit_other_bits_untouched` — `set(0)`
//!      does not flip bit 1
//!   4. `test_dsl_074_idempotent` — `set(0)` twice is the same
//!      as once
//!   5. `test_dsl_074_accessor_names_match_has` — named
//!      accessors match `has(index)` for the three flags

use dig_slashing::{
    ParticipationFlags, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};

/// DSL-074 row 1: default is zero.
#[test]
fn test_dsl_074_default_zero() {
    let f = ParticipationFlags::default();
    assert_eq!(f.0, 0);
    assert!(!f.is_source_timely());
    assert!(!f.is_target_timely());
    assert!(!f.is_head_timely());
}

/// DSL-074 row 2: `set(0)` makes `has(0)` true.
#[test]
fn test_dsl_074_set_bit_0() {
    let mut f = ParticipationFlags::default();
    assert!(!f.has(0));
    f.set(0);
    assert!(f.has(0));
}

/// DSL-074 row 3: setting bit 0 does not touch bits 1, 2.
#[test]
fn test_dsl_074_set_bit_other_bits_untouched() {
    let mut f = ParticipationFlags::default();
    f.set(0);
    assert!(f.has(0));
    assert!(!f.has(1));
    assert!(!f.has(2));
    assert_eq!(f.0, 0b0000_0001);

    // Now set bit 2 — bit 1 must remain untouched.
    f.set(2);
    assert_eq!(f.0, 0b0000_0101);
    assert!(!f.has(1));
}

/// DSL-074 row 4: `set(i)` is idempotent.
#[test]
fn test_dsl_074_idempotent() {
    let mut f = ParticipationFlags::default();
    f.set(1);
    let once = f.0;
    f.set(1);
    assert_eq!(f.0, once, "set is idempotent on the same index");

    // Also across multiple distinct sets.
    f.set(0);
    f.set(0);
    f.set(2);
    f.set(2);
    assert_eq!(f.0, 0b0000_0111);
}

/// DSL-074 row 5: named accessors match `has(index)` for the
/// three canonical flag positions.
#[test]
fn test_dsl_074_accessor_names_match_has() {
    let mut f = ParticipationFlags::default();
    f.set(TIMELY_SOURCE_FLAG_INDEX);
    assert_eq!(f.is_source_timely(), f.has(TIMELY_SOURCE_FLAG_INDEX));
    assert!(f.is_source_timely());

    f.set(TIMELY_TARGET_FLAG_INDEX);
    assert_eq!(f.is_target_timely(), f.has(TIMELY_TARGET_FLAG_INDEX));
    assert!(f.is_target_timely());

    f.set(TIMELY_HEAD_FLAG_INDEX);
    assert_eq!(f.is_head_timely(), f.has(TIMELY_HEAD_FLAG_INDEX));
    assert!(f.is_head_timely());
}
