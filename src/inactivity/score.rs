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

use crate::constants::{INACTIVITY_SCORE_BIAS, INACTIVITY_SCORE_RECOVERY_RATE};
use crate::participation::ParticipationTracker;
use crate::traits::EffectiveBalanceView;

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
        in_finality_stall: bool,
    ) {
        let n = self.scores.len().min(participation.validator_count());
        for i in 0..n {
            let idx = i as u32;
            let flags = participation.previous_flags(idx).unwrap_or_default();
            if flags.is_target_timely() {
                // DSL-088: TIMELY_TARGET hit → -1 saturating.
                self.scores[i] = self.scores[i].saturating_sub(1);
            } else if in_finality_stall {
                // DSL-089: TIMELY_TARGET miss during finality
                // stall → += INACTIVITY_SCORE_BIAS (4),
                // saturating at u64::MAX. Outside a stall,
                // misses are absorbed by DSL-090 global
                // recovery instead of accumulating here.
                self.scores[i] = self.scores[i].saturating_add(INACTIVITY_SCORE_BIAS);
            }
        }

        // DSL-090: out-of-stall global recovery. Runs AFTER
        // the per-validator pass above so the hit decrement
        // (DSL-088) stacks with this global shrink. In-stall,
        // no global recovery — only DSL-088 hit decrement
        // fires.
        if !in_finality_stall {
            for score in &mut self.scores {
                *score = score.saturating_sub(INACTIVITY_SCORE_RECOVERY_RATE);
            }
        }
    }

    /// Compute per-validator inactivity-leak debits for the
    /// current epoch.
    ///
    /// Implements [DSL-091](../../../docs/requirements/domains/inactivity/specs/DSL-091.md).
    /// DSL-092 lands the in-stall penalty formula; for now the
    /// in-stall branch returns an empty vec, same as the
    /// out-of-stall branch.
    ///
    /// # Out-of-stall (DSL-091)
    ///
    /// `!in_finality_stall` → empty `Vec<(u32, u64)>`. Inactivity
    /// penalties NEVER charge validators outside a stall — DSL-090
    /// global recovery handles score decay and that is the only
    /// no-stall effect.
    ///
    /// # In-stall (DSL-092 — stub today)
    ///
    /// Returns empty until DSL-092 lands the formula
    /// `penalty_mojos = eff_bal * score /
    /// INACTIVITY_PENALTY_QUOTIENT`. Callers that iterate the
    /// return see zero entries either way; once DSL-092 ships,
    /// they'll receive one `(validator_index, penalty_mojos)`
    /// pair per validator whose score contributes.
    #[must_use]
    pub fn epoch_penalties(
        &self,
        _effective_balances: &dyn EffectiveBalanceView,
        in_finality_stall: bool,
    ) -> Vec<(u32, u64)> {
        if !in_finality_stall {
            return Vec::new();
        }
        // DSL-092 replaces this with the in-stall formula.
        Vec::new()
    }
}
