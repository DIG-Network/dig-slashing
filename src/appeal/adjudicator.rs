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

use crate::appeal::envelope::{SlashAppeal, SlashAppealPayload};
use crate::appeal::ground::AttesterAppealGround;
use crate::appeal::verdict::{AppealSustainReason, AppealVerdict};
use crate::pending::PendingSlash;
use crate::traits::{CollateralSlasher, ValidatorView};

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
