//! `ParticipationFlags` — 3-bit Ethereum-Altair-parity attestation
//! flag bitmask.
//!
//! Traces to: [SPEC §3.10, §2.9](../../../docs/resources/SPEC.md),
//! catalogue row
//! [DSL-074](../../../docs/requirements/domains/participation/specs/DSL-074.md).
//!
//! # Bit layout
//!
//! | Bit | Flag                | Set iff |
//! |-----|---------------------|---------|
//! | 0   | `TIMELY_SOURCE`     | attestation's source matches the finalised checkpoint AND inclusion within `SLOTS_PER_EPOCH` of the target |
//! | 1   | `TIMELY_TARGET`     | attestation's target matches the expected target root AND inclusion within `SLOTS_PER_EPOCH * SLOTS_PER_EPOCH` |
//! | 2   | `TIMELY_HEAD`       | inclusion delay == 1 |
//!
//! Bits 3–7 are RESERVED — consumers MUST NOT assume they are
//! zero across serialisation roundtrips (serde preserves the
//! full `u8`).

use serde::{Deserialize, Serialize};

use crate::constants::{
    TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};

/// Per-validator attestation-participation bitmask.
///
/// Implements [DSL-074](../../../docs/requirements/domains/participation/specs/DSL-074.md).
/// Traces to SPEC §3.10.
///
/// # Operations
///
/// - `set(flag_index)` — additive OR; idempotent.
/// - `has(flag_index)` — read.
/// - `is_source_timely` / `is_target_timely` / `is_head_timely`
///   — named accessors mirroring Ethereum Altair nomenclature
///   (spec §2.9).
///
/// # Design rationale
///
/// Using a single `u8` keeps the state tracker's per-validator
/// storage at 1 byte — critical for the `ParticipationTracker`
/// (DSL-078) which holds two epochs' worth of flags for every
/// validator in the active set (millions of entries at scale).
///
/// # Default
///
/// `ParticipationFlags::default()` → all bits zero. Matches a
/// validator that has not yet been credited with any flag in the
/// current epoch.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ParticipationFlags(pub u8);

impl ParticipationFlags {
    /// Additive OR-set of the bit at `flag_index`.
    ///
    /// Idempotent — calling `set(i)` twice leaves the bitmask
    /// unchanged. Other bits are preserved.
    ///
    /// # Panics
    ///
    /// Does NOT panic for `flag_index >= 8` — the shift wraps in
    /// release but evaluates to a no-op under valid protocol use
    /// (only three flags are defined). Callers SHOULD stick to
    /// the `TIMELY_*_FLAG_INDEX` constants.
    pub fn set(&mut self, flag_index: u8) {
        self.0 |= 1u8 << flag_index;
    }

    /// Read the bit at `flag_index`. `true` iff the flag was
    /// ever `set()`.
    #[must_use]
    pub fn has(&self, flag_index: u8) -> bool {
        (self.0 >> flag_index) & 1 == 1
    }

    /// Convenience: `has(TIMELY_SOURCE_FLAG_INDEX)`.
    #[must_use]
    pub fn is_source_timely(&self) -> bool {
        self.has(TIMELY_SOURCE_FLAG_INDEX)
    }

    /// Convenience: `has(TIMELY_TARGET_FLAG_INDEX)`.
    #[must_use]
    pub fn is_target_timely(&self) -> bool {
        self.has(TIMELY_TARGET_FLAG_INDEX)
    }

    /// Convenience: `has(TIMELY_HEAD_FLAG_INDEX)`.
    #[must_use]
    pub fn is_head_timely(&self) -> bool {
        self.has(TIMELY_HEAD_FLAG_INDEX)
    }
}
