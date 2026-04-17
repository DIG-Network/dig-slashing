# Participation & Rewards — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 8, 3.10, 2.3, 2.5

Ethereum Altair-parity attestation participation accounting. Three flags per validator per epoch (`TIMELY_SOURCE`, `TIMELY_TARGET`, `TIMELY_HEAD`) drive rewards and penalties via the base-reward formula. DIG does NOT ship a sync committee; 2 of 64 weight units are reserved but unassigned.

---

## &sect;1 ParticipationFlags

<a id="DSL-074"></a>**DSL-074** `ParticipationFlags::set(flag_index)` MUST set bit `flag_index` (0=SOURCE, 1=TARGET, 2=HEAD). `ParticipationFlags::has(flag_index)` MUST return `true` iff that bit is set. Other bits MUST remain unchanged.
> **Spec:** [`DSL-074.md`](specs/DSL-074.md)

---

## &sect;2 Timeliness Classification

<a id="DSL-075"></a>**DSL-075** `classify_timeliness` MUST set `TIMELY_SOURCE` iff `delay ∈ [MIN_ATTESTATION_INCLUSION_DELAY, TIMELY_SOURCE_MAX_DELAY_SLOTS]` (= `[1, 5]`) AND `source_is_justified` is true.
> **Spec:** [`DSL-075.md`](specs/DSL-075.md)

<a id="DSL-076"></a>**DSL-076** `classify_timeliness` MUST set `TIMELY_TARGET` iff `delay ∈ [MIN_ATTESTATION_INCLUSION_DELAY, TIMELY_TARGET_MAX_DELAY_SLOTS]` (= `[1, 32]`) AND `target_is_canonical` is true.
> **Spec:** [`DSL-076.md`](specs/DSL-076.md)

<a id="DSL-077"></a>**DSL-077** `classify_timeliness` MUST set `TIMELY_HEAD` iff `delay == MIN_ATTESTATION_INCLUSION_DELAY` (= 1) AND `head_is_canonical` is true.
> **Spec:** [`DSL-077.md`](specs/DSL-077.md)

---

## &sect;3 ParticipationTracker

<a id="DSL-078"></a>**DSL-078** `ParticipationTracker::record_attestation(data, attesting_indices, flags)` MUST set `flags` into `current_epoch[idx]` for each `idx` in `attesting_indices`. `record_attestation` MUST be additive (`|=`), not overwriting.
> **Spec:** [`DSL-078.md`](specs/DSL-078.md)

<a id="DSL-079"></a>**DSL-079** `ParticipationTracker::record_attestation` MUST return `Err(ParticipationError::NonAscendingIndices)` when the `attesting_indices` are not strictly ascending, and `Err(ParticipationError::DuplicateIndex)` on duplicates.
> **Spec:** [`DSL-079.md`](specs/DSL-079.md)

<a id="DSL-080"></a>**DSL-080** `ParticipationTracker::rotate_epoch(new_epoch, validator_count)` MUST swap `previous_epoch` and `current_epoch`, then zero and resize `current_epoch` to `validator_count`. `current_epoch_number` MUST become `new_epoch`.
> **Spec:** [`DSL-080.md`](specs/DSL-080.md)

---

## &sect;4 Base Reward + Flag Deltas

<a id="DSL-081"></a>**DSL-081** `base_reward(effective_balance, total_active_balance)` MUST compute `effective_balance * BASE_REWARD_FACTOR / integer_sqrt(total_active_balance)` using `num_integer::Roots::sqrt`. The function MUST saturate at `u64::MAX`.
> **Spec:** [`DSL-081.md`](specs/DSL-081.md)

<a id="DSL-082"></a>**DSL-082** `compute_flag_deltas` MUST award `base_reward * TIMELY_SOURCE_WEIGHT / WEIGHT_DENOMINATOR` to `reward` when SOURCE is set; `base_reward * TIMELY_TARGET_WEIGHT / WEIGHT_DENOMINATOR` when TARGET is set; `base_reward * TIMELY_HEAD_WEIGHT / WEIGHT_DENOMINATOR` when HEAD is set.
> **Spec:** [`DSL-082.md`](specs/DSL-082.md)

<a id="DSL-083"></a>**DSL-083** `compute_flag_deltas` MUST add the per-flag reward to `penalty` when SOURCE is UNSET AND when TARGET is UNSET. It MUST NOT penalise HEAD misses (head-flag miss carries no penalty — Ethereum parity).
> **Spec:** [`DSL-083.md`](specs/DSL-083.md)

<a id="DSL-084"></a>**DSL-084** `compute_flag_deltas` MUST zero `reward` for every validator when `in_finality_stall == true`. Penalties MUST still be computed normally (leak suppresses rewards only).
> **Spec:** [`DSL-084.md`](specs/DSL-084.md)

---

## &sect;5 Proposer Inclusion Reward

<a id="DSL-085"></a>**DSL-085** `proposer_inclusion_reward(attester_base_reward)` MUST compute `attester_base_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT)` = `base * 8 / 56` using integer arithmetic.
> **Spec:** [`DSL-085.md`](specs/DSL-085.md)

---

## &sect;6 Weight Denominator (No Sync Committee)

<a id="DSL-086"></a>**DSL-086** `WEIGHT_DENOMINATOR` MUST equal 64. Assigned weights (`TIMELY_SOURCE_WEIGHT` + `TIMELY_TARGET_WEIGHT` + `TIMELY_HEAD_WEIGHT` + `PROPOSER_WEIGHT` = 14 + 26 + 14 + 8 = 62) MUST sum to at most 62. The remaining 2 units MUST remain unassigned (DIG does NOT ship sync committees).
> **Spec:** [`DSL-086.md`](specs/DSL-086.md)

---

## &sect;7 Reorg + Serde

<a id="DSL-153"></a>**DSL-153** `ParticipationTracker::rewind_on_reorg(depth, validator_count)` MUST restore previous/current flag arrays from an internal ring-buffer snapshot at `current_epoch - depth`. `current_epoch_number` MUST decrement by `depth`. Arrays MUST be resized to `validator_count`. `depth == 0` MUST be a no-op. Reorgs deeper than `CORRELATION_WINDOW_EPOCHS` are guarded at `rewind_all_on_reorg` (DSL-130).
> **Spec:** [`DSL-153.md`](specs/DSL-153.md)

<a id="DSL-154"></a>**DSL-154** `ParticipationFlags(u8)` MUST round-trip byte-exactly through `bincode` and `serde_json` serialisation, for all 0..=7 bit patterns, individually and in `Vec<ParticipationFlags>`.
> **Spec:** [`DSL-154.md`](specs/DSL-154.md)
