//! Participation-flag accounting (Ethereum Altair parity).
//!
//! Traces to: [SPEC.md §3.10, §8](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-074..086](../../../docs/requirements/domains/participation/specs/).
//!
//! # Role
//!
//! Tracks the three Ethereum Altair participation flags
//! (`TIMELY_SOURCE`, `TIMELY_TARGET`, `TIMELY_HEAD`) per
//! validator per epoch. Drives Ethereum-parity reward + penalty
//! computation for attestation inclusion.
//!
//! # Scope (incremental)
//!
//! Module grows one DSL at a time. First commit lands DSL-074
//! (the `ParticipationFlags` bitmask type). Future DSLs add:
//!
//!   - DSL-075..077: `classify_timeliness`
//!   - DSL-078..080: `ParticipationTracker` state machine
//!   - DSL-081..086: reward / penalty deltas

pub mod flags;
pub mod timeliness;

pub use flags::ParticipationFlags;
pub use timeliness::classify_timeliness;
