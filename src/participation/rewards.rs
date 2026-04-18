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

use crate::constants::BASE_REWARD_FACTOR;

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
