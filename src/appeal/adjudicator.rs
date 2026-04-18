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

use std::collections::BTreeMap;

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::appeal::envelope::{SlashAppeal, SlashAppealPayload};
use crate::appeal::ground::AttesterAppealGround;
use crate::appeal::verdict::{AppealSustainReason, AppealVerdict};
use crate::bonds::{BondError, BondEscrow, BondTag};
use crate::constants::{
    APPELLANT_BOND_MOJOS, BOND_AWARD_TO_WINNER_BPS, BPS_DENOMINATOR, INVALID_BLOCK_BASE_BPS,
    MIN_SLASHING_PENALTY_QUOTIENT, PROPOSER_REWARD_QUOTIENT, REPORTER_BOND_MOJOS,
    WHISTLEBLOWER_REWARD_QUOTIENT,
};
use crate::pending::{AppealAttempt, AppealOutcome, PendingSlash, PendingSlashStatus};
use crate::traits::{
    CollateralSlasher, EffectiveBalanceView, RewardClawback, RewardPayout, ValidatorView,
};

/// Aggregate result of an appeal adjudication pass.
///
/// Traces to [DSL-164](../../../docs/requirements/domains/appeal/specs/DSL-164.md).
/// Produced by the (future) top-level `adjudicate_appeal`
/// dispatcher that composes the per-DSL slice functions in this
/// module. Consumed by:
///
///   - Audit logs — full reproduction of what happened on a sustained
///     or rejected appeal.
///   - RPC responses — telemetry consumers query via serde_json.
///   - Test fixtures — the serde contract (DSL-164) lets tests
///     construct an `AppealAdjudicationResult` directly without
///     driving the full pipeline.
///
/// # Field grouping
///
/// - `appeal_hash`, `evidence_hash` — identity fields.
/// - `outcome` — Won / Lost{reason_hash} / Pending. Uses
///   `AppealOutcome` (the per-attempt lifecycle enum) rather than
///   `AppealVerdict` because the result feeds into
///   `AppealAttempt::outcome` on the pending slash's history.
/// - Sustained branch: `reverted_stake_mojos`,
///   `reverted_collateral_mojos`, `clawback_shortfall`,
///   `reporter_bond_forfeited`, `appellant_award_mojos`,
///   `reporter_penalty_mojos`. Populated on Won outcomes.
/// - Rejected branch: `appellant_bond_forfeited`,
///   `reporter_award_mojos`. Populated on Lost outcomes.
/// - `burn_amount` — residual burn applicable to BOTH branches
///   (sustained = shortfall not absorbed, rejected = bond split
///   residue).
///
/// Fields not applicable to a given branch are `0` or empty vec
/// by construction — the serde contract preserves this shape
/// (DSL-164 test pins zero + empty preservation).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppealAdjudicationResult {
    /// Hash of the adjudicated appeal (DSL-159).
    pub appeal_hash: Bytes32,
    /// Evidence hash the appeal targeted (DSL-002).
    pub evidence_hash: Bytes32,
    /// Per-attempt outcome recorded into `appeal_history`.
    pub outcome: AppealOutcome,
    /// `(validator_index, stake_mojos_credited)` pairs for a
    /// sustained appeal (DSL-064). Empty on rejection.
    pub reverted_stake_mojos: Vec<(u32, u64)>,
    /// `(validator_index, collateral_mojos_credited)` pairs for a
    /// sustained appeal (DSL-065). Empty on rejection or when
    /// the collateral slasher is disabled.
    pub reverted_collateral_mojos: Vec<(u32, u64)>,
    /// Residual debt after `adjudicate_sustained_clawback_rewards`
    /// (DSL-067). Absorbed from `reporter_bond_forfeited` per
    /// DSL-073.
    pub clawback_shortfall: u64,
    /// Reporter bond forfeited on sustained appeal (DSL-068).
    pub reporter_bond_forfeited: u64,
    /// Appellant award routed by DSL-068 (50% of forfeited
    /// reporter bond).
    pub appellant_award_mojos: u64,
    /// Reporter penalty scheduled by DSL-069.
    pub reporter_penalty_mojos: u64,
    /// Appellant bond forfeited on rejected appeal (DSL-071).
    pub appellant_bond_forfeited: u64,
    /// Reporter award routed by DSL-071 (50% of forfeited
    /// appellant bond).
    pub reporter_award_mojos: u64,
    /// Residual burn applicable to both sustained and rejected
    /// paths (unrecovered bond residue).
    pub burn_amount: u64,
}

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

/// Outcome of a forfeited-bond 50/50 split.
///
/// Traces to [SPEC §6.5](../../../docs/resources/SPEC.md). Produced by
/// DSL-068 (sustained → reporter's bond forfeited to appellant +
/// burn) and will be reused by DSL-071 (rejected → appellant's
/// bond forfeited to reporter + burn) with different field
/// interpretations.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BondSplitResult {
    /// Mojos actually forfeited from escrow (return value of
    /// `BondEscrow::forfeit`). May be less than the requested
    /// amount if the escrow's ledger disagrees — treat as the
    /// authoritative value for the split math.
    pub forfeited: u64,
    /// Award routed to the winning party's puzzle hash. For
    /// DSL-068 sustained appeals this is the appellant's share.
    /// Computed as `forfeited * BOND_AWARD_TO_WINNER_BPS /
    /// BPS_DENOMINATOR` with integer division (truncation).
    pub winner_award: u64,
    /// Burn amount = `forfeited - winner_award`. Rounding slips
    /// flow here so the split is always exactly equal to the
    /// forfeited total (no mojo accounting drift).
    pub burn: u64,
}

/// Forfeit the reporter's bond on a sustained appeal and split
/// the proceeds 50/50 between the appellant and the burn bucket.
///
/// Implements [DSL-068](../../../docs/requirements/domains/appeal/specs/DSL-068.md).
/// Traces to SPEC §6.5, §2.6.
///
/// # Pipeline
///
/// 1. `bond_escrow.forfeit(reporter_idx, REPORTER_BOND_MOJOS,
///    Reporter(evidence_hash))` — authoritative forfeit amount.
/// 2. `winner_award = forfeited * BOND_AWARD_TO_WINNER_BPS /
///    BPS_DENOMINATOR` (integer division — odd mojos round toward
///    the burn bucket).
/// 3. `burn = forfeited - winner_award` — conservation by
///    construction.
/// 4. `reward_payout.pay(appellant_puzzle_hash, winner_award)` —
///    unconditional (emit even on zero award for auditability).
///
/// # Rejected branch
///
/// No-op, returns a zero-filled `BondSplitResult`. Rejected
/// appeals forfeit the APPELLANT's bond (DSL-071) via a mirror
/// function, not this one.
///
/// # Integer-division rounding
///
/// - `forfeited = 1` → `award = 0, burn = 1`
/// - `forfeited = 2` → `award = 1, burn = 1`
/// - `forfeited = 3` → `award = 1, burn = 2`
///
/// Floor rounding on the winner's side; burn absorbs the
/// remainder. Matches the SPEC §2.6 reference.
///
/// # Errors
///
/// Propagates `BondError` from the escrow's `forfeit` call. The
/// caller (top-level adjudicator) MUST decide whether to abort
/// or continue — adjudication is transactional at the manager
/// boundary, so partial application on an escrow failure would
/// leave inconsistent state.
pub fn adjudicate_sustained_forfeit_reporter_bond(
    pending: &PendingSlash,
    appeal: &SlashAppeal,
    verdict: &AppealVerdict,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
) -> Result<BondSplitResult, BondError> {
    if matches!(verdict, AppealVerdict::Rejected { .. }) {
        return Ok(BondSplitResult {
            forfeited: 0,
            winner_award: 0,
            burn: 0,
        });
    }

    let forfeited = bond_escrow.forfeit(
        pending.evidence.reporter_validator_index,
        REPORTER_BOND_MOJOS,
        BondTag::Reporter(pending.evidence_hash),
    )?;
    let winner_award = forfeited * BOND_AWARD_TO_WINNER_BPS / BPS_DENOMINATOR;
    let burn = forfeited - winner_award;

    // Audit-visible two-call shape: the pay() always fires, even
    // on zero award — mirrors the admission-side pay() pattern
    // from DSL-025.
    reward_payout.pay(appeal.appellant_puzzle_hash, winner_award);

    Ok(BondSplitResult {
        forfeited,
        winner_award,
        burn,
    })
}

/// Outcome of the reporter-penalty step on a sustained appeal.
///
/// Traces to [SPEC §6.5](../../../docs/resources/SPEC.md). Reports
/// the index + amount debited from the reporter so the top-level
/// adjudicator + downstream correlation-window bookkeeping (DSL-030
/// at finalisation) have everything they need.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ReporterPenalty {
    /// Validator index of the reporter that filed the appealed
    /// evidence.
    pub reporter_index: u32,
    /// `EffectiveBalanceView::get(idx)` captured at adjudication
    /// time. Stored so the DSL-030 correlation-penalty formula
    /// can read the same value later without re-reading state
    /// (which may drift across further epochs).
    pub effective_balance_at_slash: u64,
    /// Mojos debited via `ValidatorEntry::slash_absolute`. Follows
    /// the InvalidBlock base formula:
    /// `max(eff_bal * INVALID_BLOCK_BASE_BPS / BPS_DENOMINATOR,
    /// eff_bal / MIN_SLASHING_PENALTY_QUOTIENT)`.
    pub penalty_mojos: u64,
}

/// Slash the reporter that filed the sustained-appeal-losing
/// evidence.
///
/// Implements [DSL-069](../../../docs/requirements/domains/appeal/specs/DSL-069.md).
/// Traces to SPEC §6.5.
///
/// # Formula
///
/// Mirrors the DSL-022 InvalidBlock base-slash branch exactly:
///
/// ```text
/// penalty = max(
///     eff_bal * INVALID_BLOCK_BASE_BPS / BPS_DENOMINATOR,
///     eff_bal / MIN_SLASHING_PENALTY_QUOTIENT,
/// )
/// ```
///
/// The reporter staked reputation by filing evidence; a sustained
/// appeal proves the evidence was at least partially wrong, so
/// they absorb the protocol's standard penalty for filing a
/// false invalid-block report.
///
/// # Correlation-window bookkeeping
///
/// Inserts `(current_epoch, reporter_index) → eff_bal` into
/// `slashed_in_window`. At finalisation (DSL-030) that entry
/// contributes to the `cohort_sum` used to amplify correlated
/// slashes — i.e. if the reporter also got slashed through the
/// normal channel in the same correlation window, the
/// proportional-slashing multiplier activates against both.
///
/// # Skip conditions
///
/// - Rejected verdict → returns `None`, no side effects.
/// - Reporter absent from `validator_set.get_mut` → returns
///   `None`. Defensive tolerance for an already-exited reporter;
///   consensus never needs to slash a validator that no longer
///   exists.
pub fn adjudicate_sustained_reporter_penalty(
    pending: &PendingSlash,
    verdict: &AppealVerdict,
    validator_set: &mut dyn ValidatorView,
    effective_balances: &dyn EffectiveBalanceView,
    slashed_in_window: &mut BTreeMap<(u64, u32), u64>,
    current_epoch: u64,
) -> Option<ReporterPenalty> {
    if matches!(verdict, AppealVerdict::Rejected { .. }) {
        return None;
    }
    let reporter_index = pending.evidence.reporter_validator_index;
    let eff_bal = effective_balances.get(reporter_index);
    let bps_term = eff_bal * u64::from(INVALID_BLOCK_BASE_BPS) / BPS_DENOMINATOR;
    let floor_term = eff_bal / MIN_SLASHING_PENALTY_QUOTIENT;
    let penalty_mojos = std::cmp::max(bps_term, floor_term);

    let entry = validator_set.get_mut(reporter_index)?;
    entry.slash_absolute(penalty_mojos, current_epoch);
    slashed_in_window.insert((current_epoch, reporter_index), eff_bal);

    Some(ReporterPenalty {
        reporter_index,
        effective_balance_at_slash: eff_bal,
        penalty_mojos,
    })
}

/// Outcome of the clawback-shortfall-into-burn absorption step.
///
/// Traces to [SPEC §6.5](../../../docs/resources/SPEC.md). Produced
/// by [`adjudicate_absorb_clawback_shortfall`] — combines DSL-067
/// `ClawbackResult::shortfall` with DSL-068 `BondSplitResult::burn`
/// to produce the authoritative burn leg plus a residue flag.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ShortfallAbsorption {
    /// Unrecovered reward debt rolled over from the DSL-067
    /// clawback — `(wb+prop) - (wb_clawed+prop_clawed)`. Added to
    /// the DSL-068 burn leg.
    pub clawback_shortfall: u64,
    /// Original burn from the DSL-068 50/50 split (`forfeited -
    /// winner_award`). Kept separately so auditors can derive
    /// the absorption path without recomputing.
    pub original_burn: u64,
    /// `original_burn + clawback_shortfall`. May exceed the
    /// forfeited bond if the shortfall is very large — the
    /// excess surfaces as `residue`.
    pub final_burn: u64,
    /// `final_burn.saturating_sub(forfeited)` — mojos the
    /// protocol cannot burn from the bond because the bond ran
    /// out. Adjudication proceeds; consumers SHOULD log the
    /// residue (`tracing::warn!` or similar) for offline audit.
    ///
    /// Zero when the bond is sufficient (the common case).
    pub residue: u64,
}

/// Absorb DSL-067 clawback shortfall into the DSL-068 burn leg.
///
/// Implements [DSL-073](../../../docs/requirements/domains/appeal/specs/DSL-073.md).
/// Traces to SPEC §6.5.
///
/// # Math
///
/// ```text
/// shortfall      = clawback.shortfall
/// original_burn  = bond_split.burn
/// final_burn     = original_burn + shortfall
/// residue        = saturating_sub(final_burn, bond_split.forfeited)
/// ```
///
/// When `residue == 0`, the forfeited bond fully covers the
/// reward-debt shortfall + the normal burn share. When `residue >
/// 0`, the bond is insufficient — adjudication still succeeds
/// (per SPEC acceptance "adjudication proceeds") and the residue
/// surfaces for consumers to emit a warn-level log.
///
/// # Zero-shortfall path
///
/// Returns `final_burn == original_burn`, `residue == 0`. No
/// change from the DSL-068 math — consumers can treat the return
/// as "use `final_burn` for the burn bucket; `residue` is purely
/// telemetry".
///
/// # Why not `tracing::warn!` here
///
/// SPEC suggests logging via `tracing::warn!`, but adding a
/// `tracing` dep just for one call inflates the crate footprint.
/// Residue is surfaced as a struct field instead; downstream
/// callers that already pull tracing can emit the warn
/// themselves.
#[must_use]
pub fn adjudicate_absorb_clawback_shortfall(
    clawback: &ClawbackResult,
    bond_split: &BondSplitResult,
) -> ShortfallAbsorption {
    let clawback_shortfall = clawback.shortfall;
    let original_burn = bond_split.burn;
    let final_burn = original_burn.saturating_add(clawback_shortfall);
    let residue = final_burn.saturating_sub(bond_split.forfeited);
    ShortfallAbsorption {
        clawback_shortfall,
        original_burn,
        final_burn,
        residue,
    }
}

/// Transition a rejected appeal's `PendingSlash` to / through
/// `ChallengeOpen` and record the losing attempt in
/// `appeal_history`.
///
/// Implements [DSL-072](../../../docs/requirements/domains/appeal/specs/DSL-072.md).
/// Traces to SPEC §6.5.
///
/// # Status transition
///
/// - `Accepted` → `ChallengeOpen { first_appeal_filed_epoch:
///   appeal.filed_epoch, appeal_count: 1 }`.
/// - `ChallengeOpen { first, count }` →
///   `ChallengeOpen { first, count + 1 }` (first preserved).
/// - `Reverted` / `Finalised` → unreachable (DSL-060/061 reject
///   terminal-state appeals); defensive no-op here.
///
/// # History append
///
/// Pushes `AppealAttempt { outcome: Lost { reason_hash }, .. }`.
/// `reason_hash` is a caller-supplied digest of the adjudicator's
/// reason bytes — used downstream for audit / analytics; the
/// crate does not prescribe a specific hasher.
///
/// # Sustained branch
///
/// No-op — sustained appeals transition to `Reverted` via DSL-070
/// instead.
///
/// # Preserves first-filed epoch
///
/// The `first_appeal_filed_epoch` on `ChallengeOpen` is the
/// epoch of the FIRST appeal ever filed against this slash; it
/// is never rewritten by subsequent rejections. Downstream
/// analytics use it to reconstruct the challenge timeline.
pub fn adjudicate_rejected_challenge_open(
    pending: &mut PendingSlash,
    appeal: &SlashAppeal,
    verdict: &AppealVerdict,
    reason_hash: Bytes32,
) {
    if matches!(verdict, AppealVerdict::Sustained { .. }) {
        return;
    }
    let new_status = match pending.status {
        PendingSlashStatus::Accepted => PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch: appeal.filed_epoch,
            appeal_count: 1,
        },
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch,
            appeal_count,
        } => PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch,
            appeal_count: appeal_count.saturating_add(1),
        },
        // Terminal states — DSL-060/061 already rejected; keep
        // status unchanged as a defensive no-op.
        PendingSlashStatus::Reverted { .. } | PendingSlashStatus::Finalised { .. } => {
            pending.status
        }
    };
    pending.status = new_status;
    pending.appeal_history.push(AppealAttempt {
        appeal_hash: appeal.hash(),
        appellant_index: appeal.appellant_index,
        filed_epoch: appeal.filed_epoch,
        outcome: AppealOutcome::Lost { reason_hash },
        bond_mojos: APPELLANT_BOND_MOJOS,
    });
}

/// Forfeit the appellant's bond on a rejected appeal and split
/// the proceeds 50/50 between the reporter and the burn bucket.
///
/// Implements [DSL-071](../../../docs/requirements/domains/appeal/specs/DSL-071.md).
/// Traces to SPEC §6.5. Mirror of DSL-068 with the losing party
/// (appellant) and winning party (reporter) swapped.
///
/// # Pipeline
///
/// 1. `bond_escrow.forfeit(appellant_idx, APPELLANT_BOND_MOJOS,
///    Appellant(appeal.hash()))` — returns the authoritative
///    forfeit amount.
/// 2. `winner_award = forfeited * BOND_AWARD_TO_WINNER_BPS /
///    BPS_DENOMINATOR` (integer division; floor toward reporter,
///    remainder to burn — identical rounding table to DSL-068).
/// 3. `burn = forfeited - winner_award` (conservation by
///    construction).
/// 4. `reward_payout.pay(reporter_puzzle_hash, winner_award)` —
///    unconditional.
///
/// # Sustained branch
///
/// No-op, returns zero-filled `BondSplitResult`. Sustained
/// appeals forfeit the REPORTER's bond via DSL-068, not the
/// appellant's.
///
/// # Result interpretation
///
/// Reuses [`BondSplitResult`]. The `winner_award` field is the
/// reporter's share on this rejected-path call (vs. the
/// appellant's share on a sustained-path DSL-068 call). The
/// struct shape is identical so downstream serialisation
/// (DSL-164 `AppealAdjudicationResult`) can carry either
/// outcome without branching on the variant.
pub fn adjudicate_rejected_forfeit_appellant_bond(
    pending: &PendingSlash,
    appeal: &SlashAppeal,
    verdict: &AppealVerdict,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
) -> Result<BondSplitResult, BondError> {
    if matches!(verdict, AppealVerdict::Sustained { .. }) {
        return Ok(BondSplitResult {
            forfeited: 0,
            winner_award: 0,
            burn: 0,
        });
    }

    let forfeited = bond_escrow.forfeit(
        appeal.appellant_index,
        APPELLANT_BOND_MOJOS,
        BondTag::Appellant(appeal.hash()),
    )?;
    let winner_award = forfeited * BOND_AWARD_TO_WINNER_BPS / BPS_DENOMINATOR;
    let burn = forfeited - winner_award;

    // Mirror DSL-068's unconditional pay — emits even on zero
    // award so the two-call shape is audit-deterministic
    // regardless of split outcome.
    reward_payout.pay(pending.evidence.reporter_puzzle_hash, winner_award);

    Ok(BondSplitResult {
        forfeited,
        winner_award,
        burn,
    })
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

/// Transition a `PendingSlash` to the `Reverted` terminal state
/// and record the winning appeal in `appeal_history`.
///
/// Implements [DSL-070](../../../docs/requirements/domains/appeal/specs/DSL-070.md).
/// Traces to SPEC §6.5.
///
/// # Mutation order
///
/// 1. `pending.appeal_history.push(AppealAttempt { outcome: Won,
///    .. })` — the attempt is recorded BEFORE the status flips
///    so observers reading status and history together see
///    consistent state (DSL-161 serde roundtrip implicitly
///    validates this pairing).
/// 2. `pending.status = Reverted { winning_appeal_hash,
///    reverted_at_epoch: current_epoch }` — terminal state;
///    `submit_appeal` rejects subsequent attempts via DSL-060.
///
/// # Rejected branch
///
/// No-op — rejected appeals do not transition the pending slash.
/// DSL-072 handles the rejected-path bookkeeping (appeal_count
/// bump + ChallengeOpen).
///
/// # Bond amount recorded
///
/// The `AppealAttempt::bond_mojos` field stores
/// `APPELLANT_BOND_MOJOS` — the amount actually locked by
/// DSL-062. Downstream auditors (DSL-073, adjudication result
/// serialisation) read this to route the forfeited/refunded
/// amount correctly.
pub fn adjudicate_sustained_status_reverted(
    pending: &mut PendingSlash,
    appeal: &SlashAppeal,
    verdict: &AppealVerdict,
    current_epoch: u64,
) {
    if matches!(verdict, AppealVerdict::Rejected { .. }) {
        return;
    }
    let appeal_hash = appeal.hash();
    pending.appeal_history.push(AppealAttempt {
        appeal_hash,
        appellant_index: appeal.appellant_index,
        filed_epoch: appeal.filed_epoch,
        outcome: AppealOutcome::Won,
        bond_mojos: APPELLANT_BOND_MOJOS,
    });
    pending.status = PendingSlashStatus::Reverted {
        winning_appeal_hash: appeal_hash,
        reverted_at_epoch: current_epoch,
    };
}

/// Top-level appeal adjudication dispatcher.
///
/// Implements [DSL-167](../../../docs/requirements/domains/appeal/specs/DSL-167.md).
/// Traces to SPEC §6.5.
///
/// # Role
///
/// Composes the 10 DSL-064..073 slice functions into one
/// end-to-end adjudication pass. Embedders call this ONCE per
/// verdict and receive a fully-populated `AppealAdjudicationResult`
/// (DSL-164) with economic effects already applied to the
/// injected trait impls. `pending.status` + `appeal_history` are
/// mutated exactly once per call (append one `AppealAttempt`).
///
/// # Signatures
///
/// All trait-object arguments are `&mut dyn` / `&dyn`; scalar
/// arguments are small by-value. `Option<&mut dyn CollateralSlasher>`
/// mirrors the DSL-139 default contract — light-client embedders
/// pass `None` and the dispatcher skips collateral-side work.
///
/// `slashed_in_window` is exposed explicitly because the DSL-069
/// reporter-penalty slice records into it. Embedders typically
/// pass `manager.slashed_in_window_mut()` (a future pub accessor);
/// tests pass a local `BTreeMap` and inspect it post-call.
///
/// # Sustained branch (fixed order)
///
/// 1. Revert base slash (DSL-064) → `reverted_stake_mojos`
/// 2. Revert collateral (DSL-065) → `reverted_collateral_mojos`
/// 3. Restore status (DSL-066)
/// 4. Clawback rewards (DSL-067) → `clawback_shortfall`
/// 5. Forfeit reporter bond + winner award (DSL-068) →
///    `reporter_bond_forfeited`, `appellant_award_mojos`,
///    preliminary `burn_amount`
/// 6. Absorb clawback shortfall (DSL-073) → final `burn_amount`
/// 7. Reporter penalty (DSL-069) → `reporter_penalty_mojos`
/// 8. Status transition to Reverted + history append (DSL-070)
///
/// # Rejected branch (fixed order)
///
/// 1. Forfeit appellant bond + reporter award (DSL-071) →
///    `appellant_bond_forfeited`, `reporter_award_mojos`,
///    `burn_amount`
/// 2. ChallengeOpen transition + history append (DSL-072)
///
/// # Errors
///
/// Propagates `BondError` from the forfeit calls. On error,
/// earlier side effects (stake credits, status restore) have
/// already run — the caller is responsible for transactional
/// rollback at the manager boundary. The dispatcher does NOT
/// attempt recovery.
///
/// # Outcome
///
/// `result.outcome == verdict.to_appeal_outcome()` (DSL-171
/// canonical mapping). Never `Pending`.
#[allow(clippy::too_many_arguments)]
pub fn adjudicate_appeal(
    verdict: AppealVerdict,
    pending: &mut PendingSlash,
    appeal: &SlashAppeal,
    validator_set: &mut dyn ValidatorView,
    effective_balances: &dyn EffectiveBalanceView,
    collateral: Option<&mut dyn CollateralSlasher>,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
    reward_clawback: &mut dyn RewardClawback,
    slashed_in_window: &mut BTreeMap<(u64, u32), u64>,
    proposer_puzzle_hash: Bytes32,
    reason_hash: Bytes32,
    current_epoch: u64,
) -> Result<crate::appeal::adjudicator::AppealAdjudicationResult, BondError> {
    let outcome = verdict.to_appeal_outcome();
    let appeal_hash = appeal.hash();
    let evidence_hash = pending.evidence_hash;

    match verdict {
        AppealVerdict::Sustained { .. } => {
            // Slice 1 — revert base slash. Returns reverted indices
            // so we can project per-index amounts without re-scanning
            // `pending.base_slash_per_validator`.
            let reverted_idx =
                adjudicate_sustained_revert_base_slash(pending, appeal, &verdict, validator_set);
            let reverted_stake_mojos: Vec<(u32, u64)> = pending
                .base_slash_per_validator
                .iter()
                .filter(|p| reverted_idx.contains(&p.validator_index))
                .map(|p| (p.validator_index, p.base_slash_amount))
                .collect();

            // Slice 2 — revert collateral (optional slasher).
            // Pass the Option by value; slice takes
            // `Option<&mut dyn CollateralSlasher>` directly so the
            // dispatcher hands over the borrow verbatim rather than
            // reborrowing through `as_deref_mut` (which fails
            // lifetime inference on trait-objects).
            let collateral_idx =
                adjudicate_sustained_revert_collateral(pending, appeal, &verdict, collateral);
            let reverted_collateral_mojos: Vec<(u32, u64)> = pending
                .base_slash_per_validator
                .iter()
                .filter(|p| collateral_idx.contains(&p.validator_index))
                .map(|p| (p.validator_index, p.collateral_slashed))
                .collect();

            // Slice 3 — restore status (result vec intentionally
            // discarded; presence of the call is the contract).
            let _restored =
                adjudicate_sustained_restore_status(pending, appeal, &verdict, validator_set);

            // Slice 4 — clawback rewards.
            let clawback = adjudicate_sustained_clawback_rewards(
                pending,
                &verdict,
                reward_clawback,
                proposer_puzzle_hash,
            );

            // Slice 5 — forfeit reporter bond (may fail).
            let bond_split = adjudicate_sustained_forfeit_reporter_bond(
                pending,
                appeal,
                &verdict,
                bond_escrow,
                reward_payout,
            )?;

            // Slice 6 — absorb shortfall into burn.
            let absorb = adjudicate_absorb_clawback_shortfall(&clawback, &bond_split);

            // Slice 7 — reporter penalty.
            let rp = adjudicate_sustained_reporter_penalty(
                pending,
                &verdict,
                validator_set,
                effective_balances,
                slashed_in_window,
                current_epoch,
            );
            let reporter_penalty_mojos = rp.map(|r| r.penalty_mojos).unwrap_or(0);

            // Slice 8 — status transition + history append.
            adjudicate_sustained_status_reverted(pending, appeal, &verdict, current_epoch);

            Ok(AppealAdjudicationResult {
                appeal_hash,
                evidence_hash,
                outcome,
                reverted_stake_mojos,
                reverted_collateral_mojos,
                clawback_shortfall: clawback.shortfall,
                reporter_bond_forfeited: bond_split.forfeited,
                appellant_award_mojos: bond_split.winner_award,
                reporter_penalty_mojos,
                appellant_bond_forfeited: 0,
                reporter_award_mojos: 0,
                burn_amount: absorb.final_burn,
            })
        }
        AppealVerdict::Rejected { .. } => {
            // Slice R1 — forfeit appellant bond (may fail).
            let bond_split = adjudicate_rejected_forfeit_appellant_bond(
                pending,
                appeal,
                &verdict,
                bond_escrow,
                reward_payout,
            )?;

            // Slice R2 — ChallengeOpen transition + history append.
            adjudicate_rejected_challenge_open(pending, appeal, &verdict, reason_hash);

            Ok(AppealAdjudicationResult {
                appeal_hash,
                evidence_hash,
                outcome,
                reverted_stake_mojos: Vec::new(),
                reverted_collateral_mojos: Vec::new(),
                clawback_shortfall: 0,
                reporter_bond_forfeited: 0,
                appellant_award_mojos: 0,
                reporter_penalty_mojos: 0,
                appellant_bond_forfeited: bond_split.forfeited,
                reporter_award_mojos: bond_split.winner_award,
                burn_amount: bond_split.burn,
            })
        }
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
