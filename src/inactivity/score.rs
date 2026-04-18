//! Per-validator inactivity-score tracker (Ethereum Bellatrix
//! parity).
//!
//! Traces to: [SPEC §9.2](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-088..093](../../../docs/requirements/domains/inactivity/specs/).
//!
//! # Role
//!
//! `InactivityScoreTracker` holds a `u64` score per validator.
//! `update_for_epoch` drives the Ethereum Bellatrix score
//! formula at each epoch boundary:
//!
//!   - DSL-088: hit → `-1` (saturating).
//!   - DSL-089: miss + stall → `+4`.
//!   - DSL-090: out-of-stall → global `-16` recovery.
//!
//! Score drives DSL-091 `inactivity_penalty(eff_bal, score)`
//! on finalisation.

use crate::participation::ParticipationTracker;

/// Per-validator inactivity-score store.
///
/// Implements DSL-088 (+ DSL-089/090 in later commits). Traces
/// to SPEC §9.2.
///
/// # Storage
///
/// `Vec<u64>` indexed by validator_index. Size fixed at
/// construction; caller resizes at validator-set growth via
/// future `resize` DSL.
///
/// # Default
///
/// `InactivityScoreTracker::new(n)` zero-initialises all slots.
#[derive(Debug, Clone)]
pub struct InactivityScoreTracker {
    scores: Vec<u64>,
}

impl InactivityScoreTracker {
    /// New tracker sized for `validator_count` validators with
    /// all scores at 0.
    #[must_use]
    pub fn new(validator_count: usize) -> Self {
        Self {
            scores: vec![0u64; validator_count],
        }
    }

    /// Read score at `validator_index`. `None` when out of
    /// range.
    #[must_use]
    pub fn score(&self, validator_index: u32) -> Option<u64> {
        self.scores.get(validator_index as usize).copied()
    }

    /// Number of validator slots tracked.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.scores.len()
    }

    /// Mutable score access for tests + DSL-089/090 rollout.
    pub fn set_score(&mut self, validator_index: u32, score: u64) -> bool {
        if let Some(s) = self.scores.get_mut(validator_index as usize) {
            *s = score;
            true
        } else {
            false
        }
    }

    /// Apply per-epoch score deltas based on the just-finished
    /// epoch's participation (read from
    /// `participation.previous_flags`).
    ///
    /// Implements [DSL-088](../../../docs/requirements/domains/inactivity/specs/DSL-088.md).
    /// DSL-089 (miss + stall → +4) and DSL-090 (global -16 out
    /// of stall) extend the body in later commits.
    ///
    /// # DSL-088 rule (hit decrement)
    ///
    /// For every validator whose previous-epoch flags had
    /// `TIMELY_TARGET` set, decrement the score by 1 saturating
    /// at 0. Applies in BOTH regimes (stall + no-stall) — timely
    /// target participation is the canonical signal for reducing
    /// inactivity score, and the `_in_finality_stall` argument
    /// is reserved (stored, not read) so future DSLs can pick
    /// it up without changing the caller signature.
    ///
    /// # Iteration
    ///
    /// Iterates `0..min(validator_count, participation.validator_count())`.
    /// A validator that is tracked here but missing from the
    /// participation tracker receives no delta (defensive: grow
    /// happens at the tracker boundary, not here).
    pub fn update_for_epoch(
        &mut self,
        participation: &ParticipationTracker,
        _in_finality_stall: bool,
    ) {
        let n = self.scores.len().min(participation.validator_count());
        for i in 0..n {
            let idx = i as u32;
            let flags = participation.previous_flags(idx).unwrap_or_default();
            if flags.is_target_timely() {
                // DSL-088: TIMELY_TARGET hit → -1 saturating.
                self.scores[i] = self.scores[i].saturating_sub(1);
            }
            // DSL-089: miss + stall → +4 (later commit).
            // DSL-090: out-of-stall global -16 recovery
            // (later commit).
        }
    }
}
