//! Ethereum-Altair-parity per-validator base reward formula
//! (DSL-081) and downstream flag-delta math (DSL-082..086).
//!
//! Traces to: [SPEC §8.3](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-081..086](../../../docs/requirements/domains/participation/specs/).
//!
//! # Scope (incremental)
//!
//! First commit lands `base_reward` (DSL-081). Later DSLs add:
//!
//!   - DSL-082: `compute_flag_deltas` reward on hit
//!   - DSL-083: penalty on miss (source + target; head exempt)
//!   - DSL-084: inactivity-leak bias
//!   - DSL-085: proposer-reward slice
//!   - DSL-086: epoch-boundary `apply_deltas`

use serde::{Deserialize, Serialize};

use crate::constants::{
    BASE_REWARD_FACTOR, TIMELY_HEAD_WEIGHT, TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT,
    WEIGHT_DENOMINATOR,
};
use crate::participation::tracker::ParticipationTracker;
use crate::traits::EffectiveBalanceView;

/// Ethereum Altair base reward per validator per epoch.
///
/// Implements [DSL-081](../../../docs/requirements/domains/participation/specs/DSL-081.md).
/// Traces to SPEC §8.3.
///
/// # Formula
///
/// ```text
/// base_reward = effective_balance * BASE_REWARD_FACTOR / isqrt(total_active_balance)
/// ```
///
/// Scales INVERSELY with the integer sqrt of total active
/// stake — smaller networks pay more per validator; larger
/// networks dilute the reward. Matches Ethereum mainnet
/// `get_base_reward` at parity.
///
/// # Overflow + saturation
///
/// Intermediate multiplication runs in `u128` to avoid overflow
/// on realistic stake sizes (32e9 mojos × 64 = 2^47, well within
/// u64 — but the generalised formula is `total_balance × factor`
/// which can push into the 2^70+ range at giant network scale).
/// Division truncates toward zero; `saturating_as_u64` caps the
/// return at `u64::MAX` for any extreme input.
///
/// # Zero guard
///
/// `total_active_balance == 0` → `isqrt == 0` → division would
/// panic. Guard returns 0: at network boot (no stakers), the
/// reward is genuinely undefined, and 0 is the least-surprising
/// value for consumers.
///
/// # Why u128 isqrt
///
/// `u128::isqrt` is stable since Rust 1.84 and produces the
/// exact integer sqrt without any dep. The SPEC pseudo-code uses
/// `num_integer::Roots::sqrt`; our stdlib form is equivalent and
/// avoids a crate pull for one call site.
#[must_use]
pub fn base_reward(effective_balance: u64, total_active_balance: u64) -> u64 {
    if total_active_balance == 0 {
        return 0;
    }
    let denom = (total_active_balance as u128).isqrt();
    if denom == 0 {
        return 0;
    }
    let num = (effective_balance as u128).saturating_mul(BASE_REWARD_FACTOR as u128);
    let result = num / denom;
    if result > u64::MAX as u128 {
        u64::MAX
    } else {
        result as u64
    }
}

/// Per-validator reward + penalty pair produced by
/// `compute_flag_deltas` at epoch boundary.
///
/// Traces to [SPEC §8.3](../../../docs/resources/SPEC.md),
/// catalogue row [DSL-082](../../../docs/requirements/domains/participation/specs/DSL-082.md).
///
/// Consumers apply `reward` as a credit and `penalty` as a debit
/// via `ValidatorEntry::credit_stake` / `slash_absolute`
/// respectively at the epoch boundary (DSL-086).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlagDelta {
    /// Validator the delta applies to.
    pub validator_index: u32,
    /// Mojos to credit. Sum of per-flag slices of the base
    /// reward — see DSL-082 for the weight table.
    pub reward: u64,
    /// Mojos to debit. Sum of per-miss penalties for SOURCE +
    /// TARGET flags. HEAD is exempt per DSL-083. Always 0 until
    /// DSL-083 populates it.
    pub penalty: u64,
}

/// Compute per-validator reward / penalty deltas for the
/// just-finished epoch (the one now in `tracker.previous_epoch`).
///
/// Implements [DSL-082](../../../docs/requirements/domains/participation/specs/DSL-082.md).
/// Traces to SPEC §8.3. Penalty field is 0 until DSL-083 lands
/// the miss-side math.
///
/// # Reward weights (DSL-082)
///
/// ```text
/// SOURCE hit → reward += base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR
/// TARGET hit → reward += base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR
/// HEAD   hit → reward += base * TIMELY_HEAD_WEIGHT   / WEIGHT_DENOMINATOR
/// ```
///
/// Mainnet weights: 14 / 26 / 14 (sum 54 / 64; the 2 unassigned
/// weights represent the unused sync-committee slot).
///
/// # Iteration
///
/// Iterates `0..tracker.validator_count()` in index order. One
/// `FlagDelta` per slot — even for validators with all-zero
/// flags, the delta IS emitted (with `reward == penalty == 0`)
/// so downstream apply code sees a deterministic per-validator
/// record count.
#[must_use]
pub fn compute_flag_deltas(
    tracker: &ParticipationTracker,
    effective_balances: &dyn EffectiveBalanceView,
    total_active_balance: u64,
) -> Vec<FlagDelta> {
    let n = tracker.validator_count();
    let mut out: Vec<FlagDelta> = Vec::with_capacity(n);
    for i in 0..n {
        let idx = i as u32;
        let eff_bal = effective_balances.get(idx);
        let base = base_reward(eff_bal, total_active_balance);
        let flags = tracker.previous_flags(idx).unwrap_or_default();
        let mut reward: u64 = 0;
        if flags.is_source_timely() {
            reward = reward.saturating_add(base * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR);
        }
        if flags.is_target_timely() {
            reward = reward.saturating_add(base * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR);
        }
        if flags.is_head_timely() {
            reward = reward.saturating_add(base * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR);
        }
        out.push(FlagDelta {
            validator_index: idx,
            reward,
            // DSL-083 populates this field.
            penalty: 0,
        });
    }
    out
}
