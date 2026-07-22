//! Continuous inactivity accounting (Ethereum Bellatrix parity).
//!
//! Traces to: [SPEC §9](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-087..093](../../../docs/requirements/domains/inactivity/specs/).
//!
//! # Role
//!
//! Inactivity-leak regime detection + per-validator score
//! accumulation. Activates when finality stalls beyond
//! `MIN_EPOCHS_TO_INACTIVITY_PENALTY` and zero-resets scores
//! on recovery.
//!
//! # Surface
//!
//! The full inactivity stack is implemented:
//!
//!   - DSL-087: `in_finality_stall` threshold
//!   - DSL-088: `InactivityScoreTracker` storage
//!   - DSL-089: per-epoch accumulate
//!   - DSL-090: recovery reset
//!   - DSL-091: penalty formula
//!   - DSL-092: leak-only gate
//!   - DSL-093: score-vector resize

pub mod penalty;
pub mod score;

pub use penalty::in_finality_stall;
pub use score::InactivityScoreTracker;
