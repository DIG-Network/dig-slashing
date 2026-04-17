# Traits — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 12, 15

Contracts for external-state traits `dig-slashing` consumes but does NOT implement. `ValidatorView`, `EffectiveBalanceView`, `PublicKeyLookup`, `CollateralSlasher`, `BondEscrow`, `RewardPayout`, `RewardClawback`, `JustificationView`, `ProposerView`, `InvalidBlockOracle`. Implementations live downstream (`dig-consensus`, `dig-collateral`, reward-distribution crate). This domain pins the contract obligations via the crate's mock-driven tests under `src/tests/`.

---

## &sect;1 ValidatorView + ValidatorEntry

<a id="DSL-131"></a>**DSL-131** `ValidatorEntry::slash_absolute(amount_mojos, epoch)` MUST saturate at the validator's current stake — if `amount_mojos > stake`, debit equals `stake`. Returns mojos actually debited.
> **Spec:** [`DSL-131.md`](specs/DSL-131.md)

<a id="DSL-132"></a>**DSL-132** `ValidatorEntry::credit_stake(amount_mojos)` MUST add `amount_mojos` to the validator's current stake. Returns mojos actually credited. Used by the adjudicator (DSL-064) and reorg rewind (DSL-129).
> **Spec:** [`DSL-132.md`](specs/DSL-132.md)

<a id="DSL-133"></a>**DSL-133** `ValidatorEntry::restore_status()` MUST clear a `Slashed` status back to `Active`. Returns `true` iff the status changed. Idempotent: calling on an already-active validator returns `false`.
> **Spec:** [`DSL-133.md`](specs/DSL-133.md)

<a id="DSL-134"></a>**DSL-134** `ValidatorEntry::is_active_at_epoch(epoch)` MUST return `true` iff `activation_epoch <= epoch < exit_epoch`. Boundary semantics: `activation_epoch` is active; `exit_epoch` is NOT active.
> **Spec:** [`DSL-134.md`](specs/DSL-134.md)

<a id="DSL-135"></a>**DSL-135** `ValidatorEntry::schedule_exit(exit_lock_until_epoch)` MUST persist the exit-lock epoch. Subsequent exit-related queries observe this value. Called by `finalise_expired_slashes` (DSL-032).
> **Spec:** [`DSL-135.md`](specs/DSL-135.md)

<a id="DSL-136"></a>**DSL-136** `ValidatorView::get(idx)` MUST return `Some(&dyn ValidatorEntry)` for every live validator index and `None` for indices outside `0..validator_set.len()`. `get_mut` mirrors the contract.
> **Spec:** [`DSL-136.md`](specs/DSL-136.md)

---

## &sect;2 EffectiveBalanceView + PublicKeyLookup

<a id="DSL-137"></a>**DSL-137** `EffectiveBalanceView::get(idx)` MUST return the validator's effective balance in mojos. `EffectiveBalanceView::total_active()` MUST return the sum of all active validators' effective balances. Consistency: `total_active() >= sum over active validators of get(idx)`.
> **Spec:** [`DSL-137.md`](specs/DSL-137.md)

<a id="DSL-138"></a>**DSL-138** `PublicKeyLookup::pubkey_of(idx)` MUST return the validator's BLS public key. Blanket impl for `&dyn ValidatorView` delegates to `ValidatorEntry::public_key`.
> **Spec:** [`DSL-138.md`](specs/DSL-138.md)

---

## &sect;3 CollateralSlasher

<a id="DSL-139"></a>**DSL-139** `CollateralSlasher::slash(idx, amount, epoch)` and `credit(idx, amount)` MUST be symmetric: `credit` after `slash` returns collateral to the validator's account. `slash` returning `Err(CollateralError::NoCollateral)` is a soft failure — not propagated as a verify error.
> **Spec:** [`DSL-139.md`](specs/DSL-139.md)

---

## &sect;4 Bonds + Rewards

<a id="DSL-140"></a>**DSL-140** `BondEscrow::escrowed(principal_idx, tag)` MUST return the currently-escrowed mojos for `(principal_idx, tag)`. Returns 0 for unknown tags (never panics).
> **Spec:** [`DSL-140.md`](specs/DSL-140.md)

<a id="DSL-141"></a>**DSL-141** `RewardPayout::pay(principal_ph, amount)` MUST credit the reward account addressed by `principal_ph`. Implementations MAY coalesce repeated pays to the same address into a single coin; `dig-slashing` does not observe the on-chain representation.
> **Spec:** [`DSL-141.md`](specs/DSL-141.md)

<a id="DSL-142"></a>**DSL-142** `RewardClawback::claw_back(principal_ph, amount)` MUST attempt to deduct `amount` from the principal's reward account and return the mojos actually deducted (0..=amount). Partial return indicates the principal already withdrew.
> **Spec:** [`DSL-142.md`](specs/DSL-142.md)

---

## &sect;5 Fork-Choice Oracles

<a id="DSL-143"></a>**DSL-143** `JustificationView` MUST expose `current_justified_checkpoint`, `previous_justified_checkpoint`, `finalized_checkpoint`, `canonical_block_root_at_slot(slot)`, `canonical_target_root_for_epoch(epoch)`. Every method is a read against consensus state; no mutation.
> **Spec:** [`DSL-143.md`](specs/DSL-143.md)

<a id="DSL-144"></a>**DSL-144** `ProposerView::proposer_at_slot(slot)` MUST return `Some(validator_index)` for committed slots and `None` for uncommitted / future slots. `current_slot()` returns the current L2 slot.
> **Spec:** [`DSL-144.md`](specs/DSL-144.md)

<a id="DSL-145"></a>**DSL-145** `InvalidBlockOracle::re_execute(header, witness)` MUST be deterministic: identical `(header, witness)` inputs produce identical `ExecutionOutcome`. No I/O, no RNG. Consumed by DSL-049/051 invalid-block appeal verifiers.
> **Spec:** [`DSL-145.md`](specs/DSL-145.md)
