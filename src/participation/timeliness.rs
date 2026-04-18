//! Attestation-timeliness classifier — populates the three
//! `ParticipationFlags` bits from the inclusion context.
//!
//! Traces to: [SPEC §8.1](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-075..077](../../../docs/requirements/domains/participation/specs/).
//!
//! # Role
//!
//! `classify_timeliness` is the single entry point that turns an
//! `AttestationData` + inclusion slot + fork-choice signals into
//! a `ParticipationFlags` bitmask. The three per-flag checks
//! (source timeliness, target canonicality + delay, head
//! inclusion delay) land incrementally:
//!
//!   - DSL-075: `TIMELY_SOURCE`
//!   - DSL-076: `TIMELY_TARGET`
//!   - DSL-077: `TIMELY_HEAD`
//!
//! The signature wires all three inputs up front so downstream
//! DSLs extend the body without breaking test fixtures written
//! against the earlier slice.

use crate::constants::{
    MIN_ATTESTATION_INCLUSION_DELAY, TIMELY_HEAD_FLAG_INDEX, TIMELY_SOURCE_FLAG_INDEX,
    TIMELY_SOURCE_MAX_DELAY_SLOTS, TIMELY_TARGET_FLAG_INDEX, TIMELY_TARGET_MAX_DELAY_SLOTS,
};
use crate::evidence::attestation_data::AttestationData;
use crate::participation::flags::ParticipationFlags;

/// Classify an attestation's participation flags at inclusion
/// time.
///
/// Implements [DSL-075](../../../docs/requirements/domains/participation/specs/DSL-075.md)
/// (source only — target/head flags land in DSL-076/077).
/// Traces to SPEC §8.1.
///
/// # Arguments
///
/// - `data` — attestation payload; `data.slot` is the origin
///   slot. `delay = inclusion_slot - data.slot` (saturating;
///   an inclusion-before-origin scenario collapses to 0, which
///   falls below `MIN_ATTESTATION_INCLUSION_DELAY` and therefore
///   contributes no flag).
/// - `inclusion_slot` — the slot of the block that included the
///   attestation.
/// - `source_is_justified` — fork-choice signal: did the
///   `data.source` checkpoint reach justification before the
///   inclusion slot? Only then does `TIMELY_SOURCE` credit.
/// - `is_canonical_target` — reserved for DSL-076. Ignored here.
/// - `is_canonical_head` — reserved for DSL-077. Ignored here.
///
/// # Returns
///
/// A fresh `ParticipationFlags` bitmask. Callers OR this into
/// their per-validator flag storage via
/// `ParticipationFlags::set`, or replace in full.
///
/// # TIMELY_SOURCE predicate (DSL-075)
///
/// Set iff:
///
/// ```text
/// delay in [MIN_ATTESTATION_INCLUSION_DELAY, TIMELY_SOURCE_MAX_DELAY_SLOTS]
///   AND source_is_justified
/// ```
///
/// Range is closed on both ends (`delay == 1` sets; `delay == 5`
/// sets; `delay == 6` does not).
#[must_use]
pub fn classify_timeliness(
    data: &AttestationData,
    inclusion_slot: u64,
    source_is_justified: bool,
    is_canonical_target: bool,
    is_canonical_head: bool,
) -> ParticipationFlags {
    let delay = inclusion_slot.saturating_sub(data.slot);
    let mut flags = ParticipationFlags::default();

    // DSL-075: TIMELY_SOURCE. Closed interval on both ends.
    if (MIN_ATTESTATION_INCLUSION_DELAY..=TIMELY_SOURCE_MAX_DELAY_SLOTS).contains(&delay)
        && source_is_justified
    {
        flags.set(TIMELY_SOURCE_FLAG_INDEX);
    }

    // DSL-076: TIMELY_TARGET. Wider window than source (1..=32)
    // plus the fork-choice canonicality signal.
    if (MIN_ATTESTATION_INCLUSION_DELAY..=TIMELY_TARGET_MAX_DELAY_SLOTS).contains(&delay)
        && is_canonical_target
    {
        flags.set(TIMELY_TARGET_FLAG_INDEX);
    }

    // DSL-077: TIMELY_HEAD. Strictest window — only delay == 1
    // (`MIN_ATTESTATION_INCLUSION_DELAY`) counts. Matches
    // Ethereum's head-vote rule: an attestation included in the
    // very next block after its origin slot can credit the head
    // vote iff the claimed head matches consensus.
    if delay == MIN_ATTESTATION_INCLUSION_DELAY && is_canonical_head {
        flags.set(TIMELY_HEAD_FLAG_INDEX);
    }

    flags
}
