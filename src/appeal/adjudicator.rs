//! Appeal adjudicator — applies the economic consequences of a
//! sustained or rejected `AppealVerdict`.
//!
//! Traces to: [SPEC.md §6.5](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-064..073](../../../docs/requirements/domains/appeal/specs/).
//!
//! # Scope (incremental)
//!
//! The module grows one DSL at a time. First commit (DSL-064)
//! lands `adjudicate_sustained_revert_base_slash` — the
//! stake-restoration primitive. Future DSLs add:
//!
//!   - DSL-065: collateral revert
//!   - DSL-066: `restore_status`
//!   - DSL-067: reward clawback
//!   - DSL-068: reporter-bond 50/50 split
//!   - DSL-069: reporter penalty
//!   - DSL-070: status transition → `Reverted`
//!   - DSL-071: rejected → appellant bond 50/50 split
//!   - DSL-072: rejected → `ChallengeOpen` increment
//!   - DSL-073: clawback shortfall absorbed from bond
//!
//! Each DSL lands as a new free function here; a top-level
//! `adjudicate_appeal` dispatcher composes them once enough
//! slices exist to be worth orchestrating.

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::appeal::envelope::{SlashAppeal, SlashAppealPayload};
use crate::appeal::ground::AttesterAppealGround;
use crate::appeal::verdict::{AppealSustainReason, AppealVerdict};
use crate::constants::{PROPOSER_REWARD_QUOTIENT, WHISTLEBLOWER_REWARD_QUOTIENT};
use crate::pending::PendingSlash;
use crate::traits::{CollateralSlasher, RewardClawback, ValidatorView};

/// Outcome of a reward clawback pass.
///
/// Traces to [SPEC §12.2](../../../docs/resources/SPEC.md). Returned
/// by [`adjudicate_sustained_clawback_rewards`] so callers (the
/// top-level adjudicator dispatcher + DSL-073 bond-absorption
/// logic) can reason about the shortfall.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ClawbackResult {
    /// Recomputed whistleblower reward =
    /// `total_eff_bal_at_slash / WHISTLEBLOWER_REWARD_QUOTIENT`.
    pub wb_amount: u64,
    /// Recomputed proposer inclusion reward =
    /// `wb_amount / PROPOSER_REWARD_QUOTIENT`.
    pub prop_amount: u64,
    /// Mojos actually clawed back from the reporter's reward
    /// account. May be less than `wb_amount` if the reporter
    /// already withdrew (partial clawback — DSL-142 contract).
    pub wb_clawed: u64,
    /// Mojos actually clawed back from the proposer's reward
    /// account.
    pub prop_clawed: u64,
    /// `(wb_amount + prop_amount) - (wb_clawed + prop_clawed)`
    /// — the residual debt that DSL-073 absorbs from the
    /// forfeited reporter bond.
    pub shortfall: u64,
}

/// Revert base-slash amounts on a sustained appeal by calling
/// `ValidatorEntry::credit_stake(amount)` per affected index.
///
/// Implements [DSL-064](../../../docs/requirements/domains/appeal/specs/DSL-064.md).
/// Traces to SPEC §6.5.
///
/// # Verdict branching
///
/// - Rejected (any) → no-op, returns empty vec. Rejected appeals
///   do not revert anything; DSL-072 bumps `appeal_count`
///   instead.
/// - Sustained{ValidatorNotInIntersection} → revert ONLY the
///   named index from
///   `AttesterAppealGround::ValidatorNotInIntersection{ validator_index }`.
///   Other slashed validators keep their debit.
/// - Sustained{anything else} → revert EVERY validator listed in
///   `pending.base_slash_per_validator`. The ground was about the
///   evidence as a whole, so every affected validator is
///   rescued.
///
/// # Skip conditions
///
/// - Validator absent from `validator_set.get_mut(idx)` → skip
///   (defensive tolerance, same pattern as DSL-022
///   `submit_evidence`).
/// - Base-slash amount of `0` → credit is still called — consensus
///   observes the method-call pattern per SPEC §7.3.
///
/// # Returns
///
/// Vector of validator indices that were actually credited
/// (present in `base_slash_per_validator` AND in the validator
/// view). Callers (DSL-067 reward clawback, DSL-070 status
/// transition) use the list to restrict downstream side effects
/// to the same set.
///
/// # Determinism
///
/// Iteration order follows `base_slash_per_validator` which is
/// itself built in DSL-007 sorted-intersection order (attester)
/// or single-element (proposer/invalid-block) — already
/// deterministic.
#[must_use]
pub fn adjudicate_sustained_revert_base_slash(
    pending: &PendingSlash,
    appeal: &SlashAppeal,
    verdict: &AppealVerdict,
    validator_set: &mut dyn ValidatorView,
) -> Vec<u32> {
    // Rejected / any non-sustained branch is a no-op.
    let reason = match verdict {
        AppealVerdict::Sustained { reason } => *reason,
        AppealVerdict::Rejected { .. } => return Vec::new(),
    };

    // For the per-validator ValidatorNotInIntersection ground,
    // restrict reverts to the named index carried on the appeal
    // ground variant. For every other sustained ground, revert
    // the whole slashable set.
    let named_index = if matches!(reason, AppealSustainReason::ValidatorNotInIntersection) {
        named_validator_from_ground(appeal)
    } else {
        None
    };

    let mut reverted: Vec<u32> = Vec::new();
    for slash in &pending.base_slash_per_validator {
        if let Some(named) = named_index
            && slash.validator_index != named
        {
            continue;
        }
        if let Some(entry) = validator_set.get_mut(slash.validator_index) {
            entry.credit_stake(slash.base_slash_amount);
            reverted.push(slash.validator_index);
        }
    }
    reverted
}

/// Clear the `Slashed` flag on reverted validators by calling
/// `ValidatorEntry::restore_status()`.
///
/// Implements [DSL-066](../../../docs/requirements/domains/appeal/specs/DSL-066.md).
/// Traces to SPEC §6.5.
///
/// # Verdict branching
///
/// Same scope rules as DSL-064/065:
/// - Rejected → no-op, returns empty vec.
/// - Sustained{ValidatorNotInIntersection} → only the named
///   index from the attester ground.
/// - Any other Sustained → every validator in
///   `base_slash_per_validator`.
///
/// # Returns
///
/// Indices whose `restore_status()` call returned `true` — i.e.
/// the validator was actually in `Slashed` state and transitioned
/// to active. Indices that were never slashed (or were already
/// restored) are absent from the result.
///
/// # Idempotence
///
/// `ValidatorEntry::restore_status` is idempotent (DSL-133); a
/// repeat call on an already-active validator returns `false`
/// and does not appear in the result.
///
/// # Skip conditions
///
/// - Validator absent from `validator_set.get_mut(idx)` → skip
///   (defensive tolerance, same as DSL-064).
#[must_use]
pub fn adjudicate_sustained_restore_status(
    pending: &PendingSlash,
    appeal: &SlashAppeal,
    verdict: &AppealVerdict,
    validator_set: &mut dyn ValidatorView,
) -> Vec<u32> {
    let reason = match verdict {
        AppealVerdict::Sustained { reason } => *reason,
        AppealVerdict::Rejected { .. } => return Vec::new(),
    };

    let named_index = if matches!(reason, AppealSustainReason::ValidatorNotInIntersection) {
        named_validator_from_ground(appeal)
    } else {
        None
    };

    let mut restored: Vec<u32> = Vec::new();
    for slash in &pending.base_slash_per_validator {
        if let Some(named) = named_index
            && slash.validator_index != named
        {
            continue;
        }
        if let Some(entry) = validator_set.get_mut(slash.validator_index)
            && entry.restore_status()
        {
            restored.push(slash.validator_index);
        }
    }
    restored
}

/// Revert collateral debits on a sustained appeal by calling
/// `CollateralSlasher::credit` per reverted validator.
///
/// Implements [DSL-065](../../../docs/requirements/domains/appeal/specs/DSL-065.md).
/// Traces to SPEC §6.5.
///
/// # Verdict branching
///
/// Matches DSL-064's scope branching — `ValidatorNotInIntersection`
/// restricts to the named index, every other sustained reason
/// covers every slashed validator. Rejected is a no-op.
///
/// # Skip conditions
///
/// - `collateral: None` (light-client) → no calls at all, empty
///   returned. Credit is a full-node concern.
/// - `slash.collateral_slashed == 0` → skipped. No-op credits
///   would be observable in consensus auditing (DSL-025 pattern);
///   collateral revert is value-bearing only when a debit
///   actually occurred.
///
/// # Returns
///
/// Indices that were actually credited (present in the scope AND
/// had non-zero `collateral_slashed` AND a collateral slasher was
/// supplied). Downstream side effects that key off collateral
/// revert scope can use this list.
#[must_use]
pub fn adjudicate_sustained_revert_collateral(
    pending: &PendingSlash,
    appeal: &SlashAppeal,
    verdict: &AppealVerdict,
    collateral: Option<&mut dyn CollateralSlasher>,
) -> Vec<u32> {
    // Rejected branch → no-op.
    let reason = match verdict {
        AppealVerdict::Sustained { reason } => *reason,
        AppealVerdict::Rejected { .. } => return Vec::new(),
    };

    // No slasher → nothing to do (light-client / bootstrap path).
    let Some(slasher) = collateral else {
        return Vec::new();
    };

    let named_index = if matches!(reason, AppealSustainReason::ValidatorNotInIntersection) {
        named_validator_from_ground(appeal)
    } else {
        None
    };

    let mut credited: Vec<u32> = Vec::new();
    for slash in &pending.base_slash_per_validator {
        if let Some(named) = named_index
            && slash.validator_index != named
        {
            continue;
        }
        if slash.collateral_slashed == 0 {
            continue;
        }
        slasher.credit(slash.validator_index, slash.collateral_slashed);
        credited.push(slash.validator_index);
    }
    credited
}

/// Claw back the whistleblower + proposer rewards paid at
/// optimistic admission (DSL-025).
///
/// Implements [DSL-067](../../../docs/requirements/domains/appeal/specs/DSL-067.md).
/// Traces to SPEC §6.5, §12.2.
///
/// # Scope
///
/// Clawback is FULL on any sustained ground — including
/// `ValidatorNotInIntersection` (DSL-047). Rationale: the
/// rewards were paid to the reporter + proposer in exchange for
/// producing correct evidence. A sustained appeal, even a
/// per-validator one, proves the evidence was at least partially
/// wrong, so the admission-time rewards must unwind. Partial
/// per-validator clawback would complicate reasoning without
/// adding protection — DSL-047 is rare enough that full
/// clawback is the simplest honest disposition.
///
/// Rejected → no-op, returns a zero-filled `ClawbackResult`.
///
/// # Formula
///
/// `wb_amount = total_eff_bal_at_slash / WHISTLEBLOWER_REWARD_QUOTIENT`
/// `prop_amount = wb_amount / PROPOSER_REWARD_QUOTIENT`
///
/// Both amounts are RECOMPUTED from
/// `pending.base_slash_per_validator[*].effective_balance_at_slash`
/// — NOT read from the original `SlashingResult`. This keeps the
/// adjudicator self-contained and lets it ignore `SlashingResult`
/// drift. DSL-022 +DSL-025 uses the same formula, so numbers
/// agree by construction.
///
/// # Shortfall
///
/// `RewardClawback::claw_back` returns the mojos ACTUALLY clawed
/// back (DSL-142 contract). The principal may have already
/// withdrawn the reward. The shortfall
/// `(wb_amount + prop_amount) - (wb_clawed + prop_clawed)` is
/// returned for DSL-073 bond-absorption.
///
/// # Call pattern
///
/// Two `claw_back` calls issued unconditionally, matching the
/// admission-side two-call `RewardPayout::pay` pattern (DSL-025).
/// Consensus auditors rely on the deterministic call shape.
#[must_use]
pub fn adjudicate_sustained_clawback_rewards(
    pending: &PendingSlash,
    verdict: &AppealVerdict,
    reward_clawback: &mut dyn RewardClawback,
    proposer_puzzle_hash: Bytes32,
) -> ClawbackResult {
    // Rejected branch → no-op. Zero-filled result signals
    // "no clawback was attempted".
    if matches!(verdict, AppealVerdict::Rejected { .. }) {
        return ClawbackResult {
            wb_amount: 0,
            prop_amount: 0,
            wb_clawed: 0,
            prop_clawed: 0,
            shortfall: 0,
        };
    }

    let total_eff_bal: u64 = pending
        .base_slash_per_validator
        .iter()
        .map(|p| p.effective_balance_at_slash)
        .sum();
    let wb_amount = total_eff_bal / WHISTLEBLOWER_REWARD_QUOTIENT;
    let prop_amount = wb_amount / PROPOSER_REWARD_QUOTIENT;

    let wb_clawed = reward_clawback.claw_back(pending.evidence.reporter_puzzle_hash, wb_amount);
    let prop_clawed = reward_clawback.claw_back(proposer_puzzle_hash, prop_amount);

    let expected = wb_amount + prop_amount;
    let got = wb_clawed + prop_clawed;
    let shortfall = expected.saturating_sub(got);

    ClawbackResult {
        wb_amount,
        prop_amount,
        wb_clawed,
        prop_clawed,
        shortfall,
    }
}

/// Extract the named `validator_index` from an attester
/// `ValidatorNotInIntersection` ground. Returns `None` if the
/// appeal payload is not an attester ground (programmer error —
/// the caller has already matched on the sustain reason, so the
/// verdict and payload SHOULD match).
fn named_validator_from_ground(appeal: &SlashAppeal) -> Option<u32> {
    match &appeal.payload {
        SlashAppealPayload::Attester(a) => match a.ground {
            AttesterAppealGround::ValidatorNotInIntersection { validator_index } => {
                Some(validator_index)
            }
            _ => None,
        },
        SlashAppealPayload::Proposer(_) | SlashAppealPayload::InvalidBlock(_) => None,
    }
}
