# Optimistic Slashing Lifecycle — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Section 7

---

## &sect;1 Optimistic Admission (`submit_evidence`)

<a id="DSL-022"></a>**DSL-022** `SlashingManager::submit_evidence()` MUST compute, for every validator index in `VerifiedEvidence::slashable_validator_indices`, a base slash amount of `base_slash = max(eff_bal * base_penalty_bps / 10_000, eff_bal / MIN_SLASHING_PENALTY_QUOTIENT)` where `eff_bal = EffectiveBalanceView::get(idx)`, `base_penalty_bps = OffenseType::base_penalty_bps()`, and `MIN_SLASHING_PENALTY_QUOTIENT = 32`. The computed amount MUST be debited from the validator via `ValidatorEntry::slash_absolute(base_slash, current_epoch)`.
> **Spec:** [`DSL-022.md`](specs/DSL-022.md)

<a id="DSL-023"></a>**DSL-023** `SlashingManager::submit_evidence()` MUST escrow `REPORTER_BOND_MOJOS` from the reporter by calling `BondEscrow::lock(reporter_idx, REPORTER_BOND_MOJOS, BondTag::Reporter(evidence_hash))` before any validator state mutation. The returned `SlashingResult::reporter_bond_escrowed` MUST equal `REPORTER_BOND_MOJOS`.
> **Spec:** [`DSL-023.md`](specs/DSL-023.md)

<a id="DSL-024"></a>**DSL-024** `SlashingManager::submit_evidence()` MUST insert a `PendingSlash` record into the `PendingSlashBook` with `status = PendingSlashStatus::Accepted`, `submitted_at_epoch = current_epoch`, and `window_expires_at_epoch = current_epoch + SLASH_APPEAL_WINDOW_EPOCHS`. The `evidence_hash` MUST be indexed in `processed` and the `base_slash_per_validator` vector MUST contain one `PerValidatorSlash` entry per slashed validator.
> **Spec:** [`DSL-024.md`](specs/DSL-024.md)

<a id="DSL-025"></a>**DSL-025** `SlashingManager::submit_evidence()` MUST compute `wb_reward = total_effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT` and `prop_reward = wb_reward / PROPOSER_REWARD_QUOTIENT`, then route payments via `RewardPayout::pay(reporter_puzzle_hash, wb_reward)` and `RewardPayout::pay(block_proposer_puzzle_hash, prop_reward)`. The block-proposer puzzle hash MUST be obtained through `ProposerView::proposer_at_slot(current_slot)` followed by `ValidatorView::get(idx).puzzle_hash()`. `burn_amount` MUST equal `total_base_slash - wb_reward - prop_reward`.
> **Spec:** [`DSL-025.md`](specs/DSL-025.md)

<a id="DSL-026"></a>**DSL-026** `SlashingManager::submit_evidence()` MUST return `Err(SlashingError::AlreadySlashed)` when the computed `evidence.hash()` is already present in the `processed` map, before verification or bond lock. No validator state MUST be mutated on this path.
> **Spec:** [`DSL-026.md`](specs/DSL-026.md)

<a id="DSL-027"></a>**DSL-027** `SlashingManager::submit_evidence()` MUST return `Err(SlashingError::PendingBookFull)` when `PendingSlashBook::len() >= MAX_PENDING_SLASHES` at admission time. No bond MUST be locked and no validator state MUST be mutated on this path.
> **Spec:** [`DSL-027.md`](specs/DSL-027.md)

<a id="DSL-028"></a>**DSL-028** `SlashingManager::submit_evidence()` MUST return `Err(SlashingError::BondLockFailed)` when `BondEscrow::lock()` returns `Err(BondError::InsufficientBalance)` because the reporter's post-slash stake is below `REPORTER_BOND_MOJOS`. No validator state MUST be mutated and no `PendingSlash` MUST be inserted on this path.
> **Spec:** [`DSL-028.md`](specs/DSL-028.md)

---

## &sect;2 Finalisation (`finalise_expired_slashes`)

<a id="DSL-029"></a>**DSL-029** `SlashingManager::finalise_expired_slashes()` MUST iterate every `evidence_hash` returned by `PendingSlashBook::expired_by(current_epoch)` and transition entries whose status is `Accepted` or `ChallengeOpen` to `PendingSlashStatus::Finalised { finalised_at_epoch: current_epoch }`. A `FinalisationResult` MUST be returned for every transitioned entry.
> **Spec:** [`DSL-029.md`](specs/DSL-029.md)

<a id="DSL-030"></a>**DSL-030** `SlashingManager::finalise_expired_slashes()` MUST, for every validator in a finalised pending slash, compute `correlation_penalty = eff_bal * min(cohort_sum * PROPORTIONAL_SLASHING_MULTIPLIER, total_active_balance) / total_active_balance` where `cohort_sum` is the sum of `eff_bal_at_slash` over entries in `slashed_in_window` whose epoch lies in `[current_epoch - CORRELATION_WINDOW_EPOCHS, current_epoch]`, and debit the result via `ValidatorEntry::slash_absolute(correlation_penalty, current_epoch)`.
> **Spec:** [`DSL-030.md`](specs/DSL-030.md)

<a id="DSL-031"></a>**DSL-031** `SlashingManager::finalise_expired_slashes()` MUST release the reporter bond in full by calling `BondEscrow::release(reporter_idx, REPORTER_BOND_MOJOS, BondTag::Reporter(evidence_hash))`. The returned `FinalisationResult::reporter_bond_returned` MUST equal `REPORTER_BOND_MOJOS`.
> **Spec:** [`DSL-031.md`](specs/DSL-031.md)

<a id="DSL-032"></a>**DSL-032** `SlashingManager::finalise_expired_slashes()` MUST schedule an exit lock on every slashed validator by calling `ValidatorEntry::schedule_exit(current_epoch + SLASH_LOCK_EPOCHS)`. The returned `FinalisationResult::exit_lock_until_epoch` MUST equal `current_epoch + SLASH_LOCK_EPOCHS`.
> **Spec:** [`DSL-032.md`](specs/DSL-032.md)

<a id="DSL-033"></a>**DSL-033** `SlashingManager::finalise_expired_slashes()` MUST skip any pending slash whose status is already `PendingSlashStatus::Reverted { .. }` or `PendingSlashStatus::Finalised { .. }`. No validator state MUST be mutated, no bond MUST be released, and no `FinalisationResult` MUST be emitted for skipped entries.
> **Spec:** [`DSL-033.md`](specs/DSL-033.md)

---

## &sect;3 PendingSlashBook Basic Ops

<a id="DSL-146"></a>**DSL-146** `PendingSlashBook::new(capacity)`, `insert`, `get`, `get_mut`, `remove`, `len` MUST form a consistent map-like contract: insert increments len, get returns the inserted record, remove returns the owned record and decrements len, get on unknown hash returns None.
> **Spec:** [`DSL-146.md`](specs/DSL-146.md)

<a id="DSL-147"></a>**DSL-147** `PendingSlashBook::expired_by(current_epoch)` MUST return evidence hashes whose `window_expires_at_epoch < current_epoch` AND whose status is `Accepted` or `ChallengeOpen`. Entries at the exact boundary (`window_expires_at_epoch == current_epoch`) are NOT returned. Entries with `Reverted`/`Finalised` status are excluded.
> **Spec:** [`DSL-147.md`](specs/DSL-147.md)

---

## &sect;4 SlashingManager Construction + Query

<a id="DSL-148"></a>**DSL-148** `SlashingManager::new(current_epoch)` MUST initialise empty `processed`, empty `PendingSlashBook`, empty `slashed_in_window`, with `current_epoch` set to the supplied value. `set_epoch(epoch)` MUST update `current_epoch`.
> **Spec:** [`DSL-148.md`](specs/DSL-148.md)

<a id="DSL-149"></a>**DSL-149** `SlashingManager::is_slashed(idx, validator_set)` MUST return `validator_set.get(idx)?.is_slashed()`, falling back to `false` for unknown indices. Read-only.
> **Spec:** [`DSL-149.md`](specs/DSL-149.md)

<a id="DSL-150"></a>**DSL-150** `SlashingManager::is_processed(hash)`, `pending(hash)`, and `prune(before_epoch)` MUST implement the query + maintenance contract: is_processed reads `processed`; pending returns `Option<&PendingSlash>`; prune drops `processed` and `slashed_in_window` entries older than `before_epoch` but leaves the `PendingSlashBook` untouched.
> **Spec:** [`DSL-150.md`](specs/DSL-150.md)

---

## &sect;5 Correlation Penalty Clamp + Short-Circuits

<a id="DSL-151"></a>**DSL-151** The correlation-penalty formula (DSL-030) MUST clamp `cohort_sum * PROPORTIONAL_SLASHING_MULTIPLIER` to `total_active_balance` via `min`, ensuring per-validator correlation penalty never exceeds `eff_bal`. Saturating multiplication MUST be used to prevent u64 overflow. `total_active_balance == 0` MUST be guarded (correlation penalty returns 0).
> **Spec:** [`DSL-151.md`](specs/DSL-151.md)

<a id="DSL-152"></a>**DSL-152** `submit_evidence` MUST propagate the `ReporterIsAccused` check from `verify_evidence` (DSL-012) BEFORE any bond lock, reward payout, state mutation, or PendingSlash insertion. No validator state, bond, or reward MUST be touched when this error is returned.
> **Spec:** [`DSL-152.md`](specs/DSL-152.md)
