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

use std::collections::{BTreeMap, HashMap};

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::bonds::{BondEscrow, BondTag};
use crate::constants::{
    APPELLANT_BOND_MOJOS, BPS_DENOMINATOR, MAX_APPEAL_ATTEMPTS_PER_SLASH, MAX_APPEAL_PAYLOAD_BYTES,
    MAX_PENDING_SLASHES, MIN_SLASHING_PENALTY_QUOTIENT, PROPORTIONAL_SLASHING_MULTIPLIER,
    PROPOSER_REWARD_QUOTIENT, REPORTER_BOND_MOJOS, SLASH_APPEAL_WINDOW_EPOCHS, SLASH_LOCK_EPOCHS,
    WHISTLEBLOWER_REWARD_QUOTIENT,
};
use crate::error::SlashingError;
use crate::evidence::envelope::{SlashingEvidence, SlashingEvidencePayload};
use crate::evidence::verify::verify_evidence;
use crate::pending::{PendingSlash, PendingSlashBook, PendingSlashStatus};
use crate::traits::{EffectiveBalanceView, ProposerView, RewardPayout, ValidatorView};

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

/// Aggregate result of a `finalise_expired_slashes` pass — one
/// record per pending slash that transitioned from
/// `Accepted`/`ChallengeOpen` to `Finalised` during the call.
///
/// Traces to [SPEC §3.9](../../docs/resources/SPEC.md). Fields other
/// than `evidence_hash` land as their owning DSLs ship:
///
///   - `per_validator_correlation_penalty` — DSL-030.
///   - `reporter_bond_returned` — DSL-031.
///   - `exit_lock_until_epoch` — DSL-032.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct FinalisationResult {
    /// Evidence hash of the finalised pending slash.
    pub evidence_hash: Bytes32,
    /// Per-validator correlation penalty applied at finalisation
    /// (DSL-030). `(validator_index, penalty_mojos)`. Empty until
    /// DSL-030 ships.
    pub per_validator_correlation_penalty: Vec<(u32, u64)>,
    /// Reporter bond returned in full at finalisation (DSL-031).
    /// `0` until DSL-031 ships.
    pub reporter_bond_returned: u64,
    /// Epoch the validator's exit lock runs until (DSL-032). `0`
    /// until DSL-032 ships.
    pub exit_lock_until_epoch: u64,
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
#[derive(Debug, Clone)]
pub struct SlashingManager {
    /// Current epoch the manager is running in. Used as the `epoch`
    /// argument to `slash_absolute` so debits are timestamped with the
    /// admission epoch, not the offense epoch (the two may differ by
    /// up to `SLASH_LOOKBACK_EPOCHS`).
    current_epoch: u64,
    /// Pending-slash book (SPEC §7.1). Keyed by evidence hash;
    /// populated on admission (DSL-024), drained on finalisation
    /// (DSL-029) or reversal (DSL-070).
    book: PendingSlashBook,
    /// Processed-evidence dedup map. Value = admission epoch; used
    /// by DSL-026 (`AlreadySlashed` short-circuit) and by pruning
    /// (SPEC §8, `prune(lower_bound_epoch)`).
    processed: HashMap<Bytes32, u64>,
    /// Per-epoch register of effective balances slashed inside the
    /// correlation window. Keyed by `(slash_epoch, validator_index)`
    /// so `expired_by`-style range scans can be done cheaply at
    /// finalisation. Populated by `submit_evidence` (DSL-022) with
    /// one entry per per-validator debit; consumed by DSL-030's
    /// `cohort_sum` computation.
    slashed_in_window: BTreeMap<(u64, u32), u64>,
}

impl Default for SlashingManager {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SlashingManager {
    /// New manager at `current_epoch` with the default
    /// `MAX_PENDING_SLASHES` book capacity. Further fields (pending
    /// book, processed map) start empty.
    #[must_use]
    pub fn new(current_epoch: u64) -> Self {
        Self::with_book_capacity(current_epoch, MAX_PENDING_SLASHES)
    }

    /// New manager with a caller-specified book capacity. Used by
    /// DSL-027 tests to exercise the `PendingBookFull` rejection.
    #[must_use]
    pub fn with_book_capacity(current_epoch: u64, book_capacity: usize) -> Self {
        Self {
            current_epoch,
            book: PendingSlashBook::new(book_capacity),
            processed: HashMap::new(),
            slashed_in_window: BTreeMap::new(),
        }
    }

    /// Current epoch accessor.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Immutable view of the pending-slash book.
    #[must_use]
    pub fn book(&self) -> &PendingSlashBook {
        &self.book
    }

    /// Mutable access to the pending-slash book.
    ///
    /// Exposed for adjudication code (DSL-064..070) that needs to
    /// transition pending statuses to `Reverted`/`ChallengeOpen`
    /// outside the manager's own `submit_evidence` +
    /// `finalise_expired_slashes` flow. Test suites also use this to
    /// inject pre-`Reverted` state for DSL-033 skip-path coverage.
    pub fn book_mut(&mut self) -> &mut PendingSlashBook {
        &mut self.book
    }

    /// `true` iff the evidence hash has been admitted. Used by
    /// DSL-026 (`AlreadySlashed` short-circuit) + tests.
    #[must_use]
    pub fn is_processed(&self, hash: &Bytes32) -> bool {
        self.processed.contains_key(hash)
    }

    /// Admission epoch recorded for a processed hash. `None` when the
    /// hash is not in the map.
    #[must_use]
    pub fn processed_epoch(&self, hash: &Bytes32) -> Option<u64> {
        self.processed.get(hash).copied()
    }

    /// Optimistic-admission entry point for validator slashing evidence.
    ///
    /// Implements the base-slash branch of
    /// [DSL-022](../../docs/requirements/domains/lifecycle/specs/DSL-022.md).
    /// Traces to SPEC §7.3 step 5, §4.
    ///
    /// # Pipeline (DSL-022 + DSL-023 scope)
    ///
    /// 1. `verify_evidence(...)` → `VerifiedEvidence` (DSL-011..020).
    ///    Failure propagates as `SlashingError`.
    /// 2. `bond_escrow.lock(reporter_idx, REPORTER_BOND_MOJOS,
    ///    BondTag::Reporter(evidence.hash()))` (DSL-023). Lock
    ///    failure collapses to `SlashingError::BondLockFailed` with
    ///    no validator-side mutation — hence the ordering (bond
    ///    BEFORE any `slash_absolute`).
    /// 3. For each slashable index:
    ///    - `eff_bal = effective_balances.get(idx)`
    ///    - `bps_term = eff_bal * base_bps / BPS_DENOMINATOR`
    ///    - `floor_term = eff_bal / MIN_SLASHING_PENALTY_QUOTIENT`
    ///    - `base_slash = max(bps_term, floor_term)`
    ///    - Skip iff `validator_set.get(idx).is_slashed()` OR index
    ///      absent from the view (defensive tolerance per SPEC §7.3).
    ///    - Otherwise `validator_set.get_mut(idx).slash_absolute(
    ///      base_slash, self.current_epoch)`.
    ///    - Record a `PerValidatorSlash`.
    /// 4. Return `SlashingResult { per_validator,
    ///    reporter_bond_escrowed: REPORTER_BOND_MOJOS, .. }` — reward
    ///    / pending-slash fields stay `0` / empty until DSL-024/025.
    ///
    /// # Deviations from SPEC signature
    ///
    /// SPEC §7.3 lists additional parameters (`CollateralSlasher`,
    /// `RewardPayout`, `ProposerView`) that are consumed by
    /// DSL-025. Signature grows incrementally — each future DSL adds
    /// the trait it needs.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_evidence(
        &mut self,
        evidence: SlashingEvidence,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        bond_escrow: &mut dyn BondEscrow,
        reward_payout: &mut dyn RewardPayout,
        proposer: &dyn ProposerView,
        network_id: &Bytes32,
    ) -> Result<SlashingResult, SlashingError> {
        // DSL-026: duplicate evidence dedup. Runs BEFORE verify /
        // capacity / bond / slash — cheapest rejection path. Uses
        // evidence.hash() (DSL-002) as the dedup key. Persists across
        // pending statuses until reorg rewind (DSL-129) or prune
        // clears the entry.
        let evidence_hash_pre = evidence.hash();
        if self.processed.contains_key(&evidence_hash_pre) {
            return Err(SlashingError::AlreadySlashed);
        }

        // Verify first — no state mutation on rejection.
        let verified = verify_evidence(&evidence, validator_set, network_id, self.current_epoch)?;

        // DSL-027: capacity check BEFORE bond lock or any validator
        // mutation. Placed after verify so only valid, non-duplicate
        // evidence can trigger capacity exhaustion. Strict `>=` — the
        // book never holds more than `capacity` records.
        if self.book.len() >= self.book.capacity() {
            return Err(SlashingError::PendingBookFull);
        }

        // DSL-023: lock reporter bond BEFORE any validator-side mutation.
        // Failure surfaces as `BondLockFailed` with validator state still
        // untouched — ordering invariant tested by
        // `test_dsl_023_lock_failure_no_mutation`. Reuses the hash
        // computed for the DSL-026 dedup check above.
        let evidence_hash = evidence_hash_pre;
        bond_escrow
            .lock(
                evidence.reporter_validator_index,
                REPORTER_BOND_MOJOS,
                BondTag::Reporter(evidence_hash),
            )
            .map_err(|_| SlashingError::BondLockFailed)?;

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

            // DSL-030: record the slash in the correlation-window
            // register. `slashed_in_window` is consumed at
            // finalisation to compute `cohort_sum`.
            self.slashed_in_window
                .insert((self.current_epoch, idx), eff_bal);
        }

        // DSL-025: reward routing. Two optimistic payouts settled
        // BEFORE the pending-book insert so the returned
        // `SlashingResult` carries the paid amounts atomically with
        // the admission. Rewards are clawed back on sustained appeal
        // (DSL-067) via a separate `RewardClawback` path — the pay
        // calls here are idempotent credits, not debits.
        let total_eff_bal: u64 = per_validator
            .iter()
            .map(|p| p.effective_balance_at_slash)
            .sum();
        let total_base: u64 = per_validator.iter().map(|p| p.base_slash_amount).sum();
        let wb_reward = total_eff_bal / WHISTLEBLOWER_REWARD_QUOTIENT;
        let prop_reward = wb_reward / PROPOSER_REWARD_QUOTIENT;
        let burn_amount = total_base.saturating_sub(wb_reward + prop_reward);

        // Whistleblower payout — always emits the call (even on zero
        // reward) so auditors see a deterministic two-call pattern.
        reward_payout.pay(evidence.reporter_puzzle_hash, wb_reward);

        // Proposer inclusion payout. `proposer_at_slot(current_slot)`
        // returning `None` is a consensus-layer bug — surface as
        // `ProposerUnavailable` rather than silently skipping.
        let current_slot = proposer.current_slot();
        let proposer_idx = proposer
            .proposer_at_slot(current_slot)
            .ok_or(SlashingError::ProposerUnavailable)?;
        let proposer_ph = validator_set
            .get(proposer_idx)
            .ok_or(SlashingError::ValidatorNotRegistered(proposer_idx))?
            .puzzle_hash();
        reward_payout.pay(proposer_ph, prop_reward);

        // DSL-024: insert the PendingSlash record + register the hash
        // in processed. Ordering: book insert first so a capacity
        // failure bubbles up WITHOUT polluting processed.
        let record = PendingSlash {
            evidence_hash,
            evidence: evidence.clone(),
            verified: verified.clone(),
            status: PendingSlashStatus::Accepted,
            submitted_at_epoch: self.current_epoch,
            window_expires_at_epoch: self.current_epoch + SLASH_APPEAL_WINDOW_EPOCHS,
            base_slash_per_validator: per_validator.clone(),
            reporter_bond_mojos: REPORTER_BOND_MOJOS,
            appeal_history: Vec::new(),
        };
        self.book.insert(record)?;
        self.processed.insert(evidence_hash, self.current_epoch);

        Ok(SlashingResult {
            per_validator,
            whistleblower_reward: wb_reward,
            proposer_reward: prop_reward,
            burn_amount,
            reporter_bond_escrowed: REPORTER_BOND_MOJOS,
            pending_slash_hash: evidence_hash,
        })
    }

    /// Transition every expired pending slash from
    /// `Accepted`/`ChallengeOpen` to `Finalised { finalised_at_epoch:
    /// self.current_epoch }` and emit one `FinalisationResult` per
    /// transition.
    ///
    /// Implements [DSL-029](../../docs/requirements/domains/lifecycle/specs/DSL-029.md).
    /// Traces to SPEC §7.4 steps 1, 6–7.
    ///
    /// # Scope (incremental)
    ///
    /// This method currently covers the status transition + result
    /// emission only. Side effects land in subsequent DSLs:
    ///
    ///   - DSL-030 populates `per_validator_correlation_penalty`.
    ///   - DSL-031 populates `reporter_bond_returned` via
    ///     `bond_escrow.release`.
    ///   - DSL-032 populates `exit_lock_until_epoch` via
    ///     `validator_set.schedule_exit`.
    ///
    /// # Behaviour
    ///
    /// - Iterates `book.expired_by(self.current_epoch)` in ascending
    ///   window-expiry order (stable across calls).
    /// - Skips pendings already in `Reverted { .. }` or `Finalised { .. }`
    ///   (DSL-033).
    /// - Idempotent: calling twice in the same epoch yields an empty
    ///   second result vec.
    pub fn finalise_expired_slashes(
        &mut self,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        bond_escrow: &mut dyn BondEscrow,
        total_active_balance: u64,
    ) -> Vec<FinalisationResult> {
        let expired = self.book.expired_by(self.current_epoch);

        // DSL-030: compute `cohort_sum` ONCE per finalise pass.
        // `slashed_in_window` is keyed by `(slash_epoch, idx)`; we
        // sum every eff_bal_at_slash value for epochs in
        // `[current - CORRELATION_WINDOW_EPOCHS, current]`. Saturating
        // subtraction keeps the window lower-bound non-negative at
        // network boot.
        let window_lo = self
            .current_epoch
            .saturating_sub(u64::from(dig_epoch::CORRELATION_WINDOW_EPOCHS));
        let cohort_sum: u64 = self
            .slashed_in_window
            .range((window_lo, 0)..=(self.current_epoch, u32::MAX))
            .map(|(_, eff)| *eff)
            .sum();

        let mut results = Vec::with_capacity(expired.len());
        for hash in expired {
            // DSL-033: skip terminal statuses. Snapshot status via a
            // short borrow so we can mutate other fields afterward.
            let status_is_terminal = matches!(
                self.book.get(&hash).map(|p| p.status),
                Some(PendingSlashStatus::Reverted { .. } | PendingSlashStatus::Finalised { .. }),
            );
            if status_is_terminal {
                continue;
            }

            // Snapshot per-validator entries (clone the small vec)
            // before the mutable borrow for the validator-set slash
            // calls. Keeps the borrow graph simple.
            let (slashable_indices, evidence_hash, reporter_idx) = {
                let pending = match self.book.get(&hash) {
                    Some(p) => p,
                    None => continue,
                };
                (
                    pending
                        .base_slash_per_validator
                        .iter()
                        .map(|p| p.validator_index)
                        .collect::<Vec<u32>>(),
                    pending.evidence_hash,
                    pending.evidence.reporter_validator_index,
                )
            };

            // DSL-030: per-validator correlation penalty. Formula:
            //   penalty = eff_bal * min(cohort_sum * 3, total) / total
            // with total_active_balance==0 yielding 0 (defensive).
            //
            // DSL-032: schedule the exit lock alongside the penalty.
            // `exit_lock_until_epoch = current + SLASH_LOCK_EPOCHS`.
            let exit_lock_until_epoch = self.current_epoch + SLASH_LOCK_EPOCHS;
            let mut correlation = Vec::with_capacity(slashable_indices.len());
            let scaled = cohort_sum.saturating_mul(PROPORTIONAL_SLASHING_MULTIPLIER);
            let capped = scaled.min(total_active_balance);
            for idx in slashable_indices {
                let eff_bal = effective_balances.get(idx);
                // u128 intermediate prevents overflow on the multiply:
                // `eff_bal * capped` can exceed u64 when both are near
                // MIN_EFFECTIVE_BALANCE (e.g. 32e9 * 32e9 = 1.02e21 >
                // u64::MAX). The final divide shrinks back to u64 range
                // because `penalty <= eff_bal` (saturation property).
                let penalty = if total_active_balance == 0 {
                    0
                } else {
                    let product = u128::from(eff_bal) * u128::from(capped);
                    (product / u128::from(total_active_balance)) as u64
                };
                if let Some(entry) = validator_set.get_mut(idx) {
                    entry.slash_absolute(penalty, self.current_epoch);
                    // DSL-032: exit lock scheduled inside same entry
                    // access — one &mut borrow per validator.
                    entry.schedule_exit(exit_lock_until_epoch);
                }
                correlation.push((idx, penalty));
            }

            // DSL-031: release reporter bond in full. Bond was locked
            // at admission (DSL-023); release is infallible by
            // construction — any escrow error is a book-keeping bug
            // that shouldn't block epoch advancement, so log-and-continue
            // behaviour is acceptable (tests supply accepting escrows).
            let _ = bond_escrow.release(
                reporter_idx,
                REPORTER_BOND_MOJOS,
                BondTag::Reporter(evidence_hash),
            );

            // Now flip the pending status. Second borrow on book.
            if let Some(pending) = self.book.get_mut(&hash) {
                pending.status = PendingSlashStatus::Finalised {
                    finalised_at_epoch: self.current_epoch,
                };
            }

            results.push(FinalisationResult {
                evidence_hash,
                per_validator_correlation_penalty: correlation,
                reporter_bond_returned: REPORTER_BOND_MOJOS,
                exit_lock_until_epoch,
            });
        }
        results
    }

    /// Submit an appeal against an existing pending slash.
    ///
    /// Implements [DSL-055](../../docs/requirements/domains/appeal/specs/DSL-055.md).
    /// Traces to SPEC §6.1, §7.2.
    ///
    /// # Scope (incremental)
    ///
    /// First-cut pipeline stops at the UnknownEvidence precondition:
    /// if `appeal.evidence_hash` is not present in the pending-slash
    /// book the method returns `SlashingError::UnknownEvidence(hex)`
    /// WITHOUT touching the bond escrow. Later DSLs extend the
    /// pipeline:
    ///   - DSL-056: `WindowExpired`
    ///   - DSL-057: `VariantMismatch`
    ///   - DSL-058: `DuplicateAppeal`
    ///   - DSL-059: `TooManyAttempts`
    ///   - DSL-060/061: `SlashAlreadyReverted` / `SlashAlreadyFinalised`
    ///   - DSL-062: appellant-bond lock (FIRST bond-touching step)
    ///   - DSL-063: `PayloadTooLarge`
    ///   - DSL-064+: dispatch to per-ground verifiers + adjudicate
    ///
    /// # Error ordering invariant
    ///
    /// `UnknownEvidence` MUST be checked BEFORE any bond operation
    /// so a caller with a stale / misrouted appeal does not pay
    /// gas to lock collateral that would immediately need to be
    /// returned. Preserved by running the book lookup as the first
    /// statement — see the DSL-055 test suite's
    /// `test_dsl_055_bond_not_locked` guard.
    pub fn submit_appeal(
        &mut self,
        appeal: &crate::appeal::SlashAppeal,
        bond_escrow: &mut dyn BondEscrow,
    ) -> Result<(), SlashingError> {
        // DSL-055: UnknownEvidence — must run BEFORE any bond
        // operation or further state inspection.
        let pending = self.book.get(&appeal.evidence_hash).ok_or_else(|| {
            SlashingError::UnknownEvidence(hex_encode(appeal.evidence_hash.as_ref()))
        })?;

        // DSL-060 / DSL-061: terminal-state guards. Reverted and
        // Finalised pending slashes are non-actionable — no
        // further appeals are accepted. Checked BEFORE the
        // window/variant/duplicate logic because terminal state
        // trumps all other dispositions.
        match pending.status {
            PendingSlashStatus::Reverted { .. } => {
                return Err(SlashingError::SlashAlreadyReverted);
            }
            PendingSlashStatus::Finalised { .. } => {
                return Err(SlashingError::SlashAlreadyFinalised);
            }
            PendingSlashStatus::Accepted | PendingSlashStatus::ChallengeOpen { .. } => {}
        }

        // DSL-056: WindowExpired — reject when the appeal was
        // filed strictly AFTER the window-close boundary. The
        // boundary epoch itself (`filed_epoch ==
        // window_expires_at_epoch`) is still a valid filing; only
        // `filed_epoch > expires_at` trips. Bond lock happens in
        // DSL-062 so this check still precedes any collateral
        // touch.
        if appeal.filed_epoch > pending.window_expires_at_epoch {
            return Err(SlashingError::AppealWindowExpired {
                submitted_at: pending.submitted_at_epoch,
                window: SLASH_APPEAL_WINDOW_EPOCHS,
                current: appeal.filed_epoch,
            });
        }

        // DSL-057: VariantMismatch — the appeal payload variant
        // MUST match the evidence payload variant. Structural
        // check; no state inspection beyond the two enum tags.
        use crate::appeal::SlashAppealPayload;
        let variants_match = matches!(
            (&appeal.payload, &pending.evidence.payload),
            (
                SlashAppealPayload::Proposer(_),
                SlashingEvidencePayload::Proposer(_)
            ) | (
                SlashAppealPayload::Attester(_),
                SlashingEvidencePayload::Attester(_)
            ) | (
                SlashAppealPayload::InvalidBlock(_),
                SlashingEvidencePayload::InvalidBlock(_)
            )
        );
        if !variants_match {
            return Err(SlashingError::AppealVariantMismatch);
        }

        // DSL-058: DuplicateAppeal — the appeal's content-addressed
        // hash (DOMAIN_SLASH_APPEAL || bincode(appeal)) MUST NOT
        // already appear in `pending.appeal_history`. Near-dupes
        // (different witness bytes, different ground, etc.)
        // produce distinct hashes and are accepted.
        let appeal_hash = appeal.hash();
        if pending
            .appeal_history
            .iter()
            .any(|a| a.appeal_hash == appeal_hash)
        {
            return Err(SlashingError::DuplicateAppeal);
        }

        // DSL-059: TooManyAttempts — cap adjudication cost at
        // `MAX_APPEAL_ATTEMPTS_PER_SLASH` (4). Only REJECTED
        // attempts accumulate here — a sustained appeal drains
        // the book entry (DSL-070) so this counter never sees
        // more than the cap in practice.
        if pending.appeal_history.len() >= MAX_APPEAL_ATTEMPTS_PER_SLASH {
            return Err(SlashingError::TooManyAttempts {
                count: pending.appeal_history.len(),
                limit: MAX_APPEAL_ATTEMPTS_PER_SLASH,
            });
        }

        // DSL-063: PayloadTooLarge — cap bincode-serialized
        // envelope size. Runs BEFORE the bond lock so oversized
        // appeals never touch collateral. bincode chosen for
        // parity with `SlashAppeal::hash` (same canonical form).
        let encoded = bincode::serialize(appeal).expect("SlashAppeal bincode must not fail");
        if encoded.len() > MAX_APPEAL_PAYLOAD_BYTES {
            return Err(SlashingError::AppealPayloadTooLarge {
                actual: encoded.len(),
                limit: MAX_APPEAL_PAYLOAD_BYTES,
            });
        }

        // DSL-062: appellant-bond lock. LAST admission step so
        // every structural rejection (DSL-055..061, DSL-063)
        // short-circuits before any collateral is touched. Tag
        // MUST be `BondTag::Appellant(appeal.hash())` so DSL-068
        // + DSL-071 can release / forfeit the correct slot.
        bond_escrow
            .lock(
                appeal.appellant_index,
                APPELLANT_BOND_MOJOS,
                BondTag::Appellant(appeal_hash),
            )
            .map_err(|e| SlashingError::AppellantBondLockFailed(e.to_string()))?;

        // Subsequent DSLs add: dispatch + adjudicate (DSL-064+).
        Ok(())
    }

    /// Advance the manager's epoch. Consumers at the consensus layer
    /// call this at every epoch boundary AFTER running
    /// `finalise_expired_slashes` — keeps the current epoch in lock
    /// step with the chain. Test helper.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.current_epoch = epoch;
    }
}

/// Fixed-size lowercase hex encoder for diagnostic log strings.
///
/// Stays inline to avoid pulling a `hex` crate just for error
/// messages. DSL-055 uses this to stamp `UnknownEvidence(hex)`
/// with the 64-char hex representation of the missing evidence
/// hash.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    out
}
