# Slashing Protection — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 14, 3.10

`SlashingProtection` is a validator-local JSON watermark file. Not on-chain state. Prevents a restarting or rolled-back validator from self-slashing by double-proposing, double-voting, or surround-voting.

---

## &sect;1 Monotonicity Checks

<a id="DSL-094"></a>**DSL-094** `SlashingProtection::check_proposal_slot(slot)` MUST return `true` iff `slot > self.last_proposed_slot`. After `record_proposal(slot)`, `check_proposal_slot(slot)` and `check_proposal_slot(lower_slot)` MUST return `false`.
> **Spec:** [`DSL-094.md`](specs/DSL-094.md)

<a id="DSL-095"></a>**DSL-095** `SlashingProtection::check_attestation(source, target, block_hash)` MUST return `false` when `source == self.last_attested_source_epoch AND target == self.last_attested_target_epoch` but `block_hash != self.last_attested_block_hash`.
> **Spec:** [`DSL-095.md`](specs/DSL-095.md)

<a id="DSL-096"></a>**DSL-096** `SlashingProtection::check_attestation` MUST return `false` when `would_surround(candidate_source, candidate_target)` is true. `would_surround` returns `true` iff `candidate_source < last_attested_source_epoch AND candidate_target > last_attested_target_epoch`.
> **Spec:** [`DSL-096.md`](specs/DSL-096.md)

---

## &sect;2 Recording

<a id="DSL-097"></a>**DSL-097** `record_proposal(slot)` MUST set `last_proposed_slot = slot`. `record_attestation(source, target, hash)` MUST set `last_attested_source_epoch = source`, `last_attested_target_epoch = target`, and `last_attested_block_hash = Some(0x<hex>)`.
> **Spec:** [`DSL-097.md`](specs/DSL-097.md)

---

## &sect;3 Tip Reconciliation

<a id="DSL-098"></a>**DSL-098** `rewind_attestation_to_epoch(new_tip_epoch)` MUST set `last_attested_block_hash = None` and lower `last_attested_target_epoch` and `last_attested_source_epoch` to values no greater than `new_tip_epoch`.
> **Spec:** [`DSL-098.md`](specs/DSL-098.md)

<a id="DSL-099"></a>**DSL-099** `reconcile_with_chain_tip(tip_slot, tip_epoch)` MUST rewind BOTH the proposal watermark (via `rewind_proposal_to_slot(tip_slot)`) AND the attestation watermark (via `rewind_attestation_to_epoch(tip_epoch)`).
> **Spec:** [`DSL-099.md`](specs/DSL-099.md)

---

## &sect;4 Persistence

<a id="DSL-100"></a>**DSL-100** Legacy JSON files missing the `last_attested_block_hash` field MUST load successfully with `last_attested_block_hash = None` via `#[serde(default)]`.
> **Spec:** [`DSL-100.md`](specs/DSL-100.md)

<a id="DSL-101"></a>**DSL-101** `SlashingProtection::save` followed by `SlashingProtection::load` MUST round-trip all fields byte-exactly. `last_attested_block_hash` MUST be encoded as `0x<lowercase_hex>` and compared case-insensitively on load.
> **Spec:** [`DSL-101.md`](specs/DSL-101.md)

---

## &sect;5 Proposal Rewind Helper

<a id="DSL-156"></a>**DSL-156** `SlashingProtection::rewind_proposal_to_slot(new_tip_slot)` MUST lower `last_proposed_slot` to `new_tip_slot` iff the current value exceeds it. No-op otherwise. Idempotent. Called by `reconcile_with_chain_tip` (DSL-099) and `rewind_all_on_reorg` (DSL-130).
> **Spec:** [`DSL-156.md`](specs/DSL-156.md)
