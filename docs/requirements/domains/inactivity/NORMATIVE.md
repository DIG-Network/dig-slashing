# Inactivity Accounting — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Section 9 (Inactivity Accounting), Section 2.4 (Inactivity Constants), Section 3.10 (InactivityScoreTracker)

Inactivity is **not** an event-driven slashable offense. It is **continuous per-epoch accounting** modelled after Ethereum's Altair/Bellatrix inactivity-leak mechanism. Penalties are debited each epoch from `InactivityScoreTracker` during the epoch-boundary sequence, never through `SlashingManager`. All score arithmetic MUST use saturating operations (`saturating_add`, `saturating_sub`) so that scores never under- or over-flow `u64`.

---

## &sect;1 Finality-Stall Detection

<a id="DSL-087"></a>**DSL-087** The free function `in_finality_stall(current_epoch: u64, finalized_epoch: u64) -> bool` MUST return `true` if and only if `current_epoch.saturating_sub(finalized_epoch) > MIN_EPOCHS_TO_INACTIVITY_PENALTY` (the constant equals `4`). The comparison MUST use strict `>`, not `>=`, matching Ethereum `process_inactivity_updates`.
> **Spec:** [`DSL-087.md`](specs/DSL-087.md)

---

## &sect;2 Score Update

<a id="DSL-088"></a>**DSL-088** `InactivityScoreTracker::update_for_epoch` MUST decrement a validator's score by `1` (saturating) for every entry in `previous_epoch_participation` whose `ParticipationFlags::is_target_timely()` returns `true`. This decrement MUST be applied irrespective of the value of `in_finality_stall` (target-timely is always rewarded by a score drop).
> **Spec:** [`DSL-088.md`](specs/DSL-088.md)

<a id="DSL-089"></a>**DSL-089** `InactivityScoreTracker::update_for_epoch` MUST increment a validator's score by `INACTIVITY_SCORE_BIAS` (= `4`) using `saturating_add` when `ParticipationFlags::is_target_timely()` is `false` **and** `in_finality_stall` is `true`. Out of stall, a target miss MUST NOT increment the score.
> **Spec:** [`DSL-089.md`](specs/DSL-089.md)

<a id="DSL-090"></a>**DSL-090** When `in_finality_stall` is `false`, `InactivityScoreTracker::update_for_epoch` MUST additionally apply a global recovery step that decrements every validator's score by `INACTIVITY_SCORE_RECOVERY_RATE` (= `16`) using `saturating_sub`. This recovery MUST run after the per-validator pass so that it applies to all entries uniformly.
> **Spec:** [`DSL-090.md`](specs/DSL-090.md)

---

## &sect;3 Per-Epoch Penalty

<a id="DSL-091"></a>**DSL-091** `InactivityScoreTracker::epoch_penalties` MUST return an empty `Vec<(u32, u64)>` whenever `in_finality_stall` is `false`. No inactivity penalty is ever assessed outside a finality stall.
> **Spec:** [`DSL-091.md`](specs/DSL-091.md)

<a id="DSL-092"></a>**DSL-092** When `in_finality_stall` is `true`, `InactivityScoreTracker::epoch_penalties` MUST compute the per-validator penalty as `effective_balance * score / INACTIVITY_PENALTY_QUOTIENT` (= `effective_balance * score / 16_777_216`) using integer division. Only validators with a non-zero penalty MUST appear in the returned `Vec<(validator_index, mojos)>`. Validators whose score is `0` or whose computed penalty truncates to `0` MUST be omitted.
> **Spec:** [`DSL-092.md`](specs/DSL-092.md)

---

## &sect;4 Resize

<a id="DSL-093"></a>**DSL-093** `InactivityScoreTracker::resize_for(validator_count)` MUST grow the internal `scores` vector to `validator_count` entries when `validator_count > scores.len()`. All newly-appended entries MUST be initialised to `0`. Existing entries MUST retain their prior values (no reset on grow). The method MUST be idempotent when `validator_count == scores.len()`.
> **Spec:** [`DSL-093.md`](specs/DSL-093.md)

---

## &sect;5 Reorg

<a id="DSL-155"></a>**DSL-155** `InactivityScoreTracker::rewind_on_reorg(depth)` MUST restore per-validator scores from an internal ring-buffer snapshot at `current_epoch - depth`. Ring-buffer depth MUST be `CORRELATION_WINDOW_EPOCHS` (36). `depth == 0` MUST be a no-op.
> **Spec:** [`DSL-155.md`](specs/DSL-155.md)
