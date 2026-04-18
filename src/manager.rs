//! Slashing-lifecycle manager: optimistic admission, appeal windows,
//! and finalisation.
//!
//! Traces to: [SPEC.md §7](../docs/resources/SPEC.md), catalogue rows
//! [DSL-022..033](../docs/requirements/domains/lifecycle/specs/) plus
//! the Phase-10 gap fills (DSL-146..152).
//!
//! # Scope (incremental)
//!
//! This module grows one DSL at a time. The shipped surface right now
//! covers only DSL-022 — the base-slash formula applied per slashable
//! validator in `submit_evidence`. Subsequent DSLs add:
//!
//!   - bond escrow (DSL-023),
//!   - `PendingSlash` book + status (DSL-024, DSL-146..150),
//!   - reward routing + correlation penalty (DSL-025, DSL-030),
//!   - finalisation + duplicate-rejection / capacity checks
//!     (DSL-029..033, DSL-026..028),
//!   - reorg rewind (DSL-129, DSL-130).
//!
//! Each addition lands as a method on `SlashingManager` or a new field
//! in `SlashingResult`; the DSL-022 surface remains byte-stable across
//! commits.

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::constants::{BPS_DENOMINATOR, MIN_SLASHING_PENALTY_QUOTIENT};
use crate::error::SlashingError;
use crate::evidence::envelope::SlashingEvidence;
use crate::evidence::verify::verify_evidence;
use crate::traits::{EffectiveBalanceView, ValidatorView};

/// Per-validator record produced by `submit_evidence`.
///
/// Traces to [SPEC §3.9](../../docs/resources/SPEC.md). Reversible on
/// sustained appeal (DSL-064 credits `base_slash_amount` back); joined
/// by a correlation penalty on finalisation (DSL-030).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PerValidatorSlash {
    /// Index of the slashed validator.
    pub validator_index: u32,
    /// Base slash amount in mojos debited via
    /// `ValidatorEntry::slash_absolute`. Equals
    /// `max(eff_bal * base_bps / 10_000, eff_bal / 32)`.
    pub base_slash_amount: u64,
    /// `EffectiveBalanceView::get(idx)` captured at submission. Stored
    /// so the adjudicator / correlation-penalty math can reproduce the
    /// formula without re-reading state (which may drift after further
    /// epochs).
    pub effective_balance_at_slash: u64,
}

/// Aggregate result of a `submit_evidence` call.
///
/// Traces to [SPEC §3.9](../../docs/resources/SPEC.md). Fields other
/// than `per_validator` land as their owning DSLs ship; they are
/// present here with `0` / empty defaults so callers can destructure
/// without a compile break when those DSLs land.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct SlashingResult {
    /// One entry per accused index actually debited. Already-slashed
    /// validators (DSL-162) are silently skipped and do NOT appear.
    pub per_validator: Vec<PerValidatorSlash>,
    /// Whistleblower reward in mojos. Populated by DSL-025.
    pub whistleblower_reward: u64,
    /// Proposer inclusion reward in mojos. Populated by DSL-025.
    pub proposer_reward: u64,
    /// Burn amount in mojos. Populated by DSL-025.
    pub burn_amount: u64,
    /// Reporter bond escrowed in mojos. Populated by DSL-023.
    pub reporter_bond_escrowed: u64,
    /// Hash of the stored `PendingSlash` record. Populated by DSL-024.
    pub pending_slash_hash: Bytes32,
}

/// Top-level slashing lifecycle manager.
///
/// Traces to [SPEC §7](../docs/resources/SPEC.md). Owns the
/// processed-hash dedup map, the pending-slash book, and correlation-
/// window counters — all of which land in subsequent DSL commits. For
/// DSL-022 the manager holds only the `current_epoch` field, which is
/// consumed when calling `ValidatorEntry::slash_absolute`.
#[derive(Debug, Clone, Default)]
pub struct SlashingManager {
    /// Current epoch the manager is running in. Used as the `epoch`
    /// argument to `slash_absolute` so debits are timestamped with the
    /// admission epoch, not the offense epoch (the two may differ by
    /// up to `SLASH_LOOKBACK_EPOCHS`).
    current_epoch: u64,
}

impl SlashingManager {
    /// New manager at `current_epoch`. Further state (processed map,
    /// pending book) lands in DSL-148.
    #[must_use]
    pub fn new(current_epoch: u64) -> Self {
        Self { current_epoch }
    }

    /// Current epoch accessor.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Optimistic-admission entry point for validator slashing evidence.
    ///
    /// Implements the base-slash branch of
    /// [DSL-022](../../docs/requirements/domains/lifecycle/specs/DSL-022.md).
    /// Traces to SPEC §7.3 step 5, §4.
    ///
    /// # Pipeline (DSL-022 scope only)
    ///
    /// 1. `verify_evidence(...)` → `VerifiedEvidence` (DSL-011..020).
    ///    Failure propagates as `SlashingError`.
    /// 2. For each slashable index:
    ///    - `eff_bal = effective_balances.get(idx)`
    ///    - `bps_term = eff_bal * base_bps / BPS_DENOMINATOR`
    ///    - `floor_term = eff_bal / MIN_SLASHING_PENALTY_QUOTIENT`
    ///    - `base_slash = max(bps_term, floor_term)`
    ///    - Skip iff `validator_set.get(idx).is_slashed()` OR index
    ///      absent from the view (defensive tolerance per SPEC §7.3).
    ///    - Otherwise `validator_set.get_mut(idx).slash_absolute(
    ///      base_slash, self.current_epoch)`.
    ///    - Record a `PerValidatorSlash`.
    /// 3. Return `SlashingResult { per_validator, .. }` — bond /
    ///    reward / pending-slash fields are `0` / empty until their
    ///    own DSLs land.
    ///
    /// # Deviations from SPEC signature
    ///
    /// SPEC §7.3 lists additional parameters (`CollateralSlasher`,
    /// `BondEscrow`, `RewardPayout`, `ProposerView`) that are
    /// consumed by DSL-023..025. Signature grows incrementally — each
    /// future DSL adds the trait it needs.
    pub fn submit_evidence(
        &mut self,
        evidence: SlashingEvidence,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        network_id: &Bytes32,
    ) -> Result<SlashingResult, SlashingError> {
        // Verify first — no state mutation on rejection.
        let verified = verify_evidence(&evidence, validator_set, network_id, self.current_epoch)?;

        let base_bps = u64::from(verified.offense_type.base_penalty_bps());
        let mut per_validator: Vec<PerValidatorSlash> = Vec::new();

        for &idx in &verified.slashable_validator_indices {
            // Snapshot effective balance BEFORE any mutation — the
            // formula must run on the balance at admission time, not
            // after slash_absolute has debited it.
            let eff_bal = effective_balances.get(idx);

            // Skip already-slashed (DSL-162) AND indices that drifted
            // out of the view between verify + submit. Both are silent
            // skips: per-validator record omitted.
            let should_skip = match validator_set.get(idx) {
                Some(entry) => entry.is_slashed(),
                None => true,
            };
            if should_skip {
                continue;
            }

            // base_slash = max(eff_bal * base_bps / 10_000, eff_bal / 32).
            // Order-of-operations: multiply before divide to keep
            // precision; `eff_bal * base_bps` fits in u64 for any
            // realistic effective balance (max eff_bal is ~32e9
            // mojos; times 500 is 1.6e13, far below u64::MAX).
            let bps_term = eff_bal.saturating_mul(base_bps) / BPS_DENOMINATOR;
            let floor_term = eff_bal / MIN_SLASHING_PENALTY_QUOTIENT;
            let base_slash = bps_term.max(floor_term);

            // Debit. `slash_absolute` is saturating (DSL-131), so this
            // never drives balance negative.
            validator_set
                .get_mut(idx)
                .expect("checked Some above")
                .slash_absolute(base_slash, self.current_epoch);

            per_validator.push(PerValidatorSlash {
                validator_index: idx,
                base_slash_amount: base_slash,
                effective_balance_at_slash: eff_bal,
            });
        }

        Ok(SlashingResult {
            per_validator,
            ..Default::default()
        })
    }
}
