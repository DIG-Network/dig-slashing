# Bonds & Rewards Routing — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 12, 2.6

`BondEscrow` is the trait through which `dig-slashing` locks, releases, and forfeits reporter/appellant stake. Implementations live downstream in `dig-collateral` or a dedicated bond-escrow crate. This domain defines the contract + constants.

---

## &sect;1 BondEscrow Trait Contract

<a id="DSL-121"></a>**DSL-121** `BondEscrow::lock(principal_idx, amount, tag)` MUST return `Err(BondError::InsufficientBalance { have, need })` when the principal's available stake is strictly less than `amount`. A successful lock MUST mark the bond visible to `escrowed(principal_idx, tag)` at the locked amount.
> **Spec:** [`DSL-121.md`](specs/DSL-121.md)

<a id="DSL-122"></a>**DSL-122** `BondEscrow::forfeit(principal_idx, amount, tag)` MUST return `Ok(forfeited_mojos)` equal to the currently-escrowed amount for `(principal_idx, tag)`, and MUST zero the tag's escrow.
> **Spec:** [`DSL-122.md`](specs/DSL-122.md)

<a id="DSL-123"></a>**DSL-123** `BondEscrow::release(principal_idx, amount, tag)` MUST credit the full escrowed amount back to the principal's stake and zero the tag.
> **Spec:** [`DSL-123.md`](specs/DSL-123.md)

---

## &sect;2 Bond Sizes

<a id="DSL-124"></a>**DSL-124** `REPORTER_BOND_MOJOS` MUST equal `MIN_EFFECTIVE_BALANCE / 64`. Submit_evidence MUST lock this amount against the reporter validator's stake.
> **Spec:** [`DSL-124.md`](specs/DSL-124.md)

<a id="DSL-125"></a>**DSL-125** `APPELLANT_BOND_MOJOS` MUST equal `MIN_EFFECTIVE_BALANCE / 64`. Submit_appeal MUST lock this amount against the appellant validator's stake.
> **Spec:** [`DSL-125.md`](specs/DSL-125.md)

---

## &sect;3 Bond Award Split

<a id="DSL-126"></a>**DSL-126** `BOND_AWARD_TO_WINNER_BPS` MUST equal 5_000 (50%). On any adjudication (Sustained or Rejected), `winner_award = forfeited_bond * 5_000 / BPS_DENOMINATOR`; the remaining `forfeited_bond - winner_award` MUST be burned.
> **Spec:** [`DSL-126.md`](specs/DSL-126.md)

---

## &sect;4 BondTag Variant Distinction

<a id="DSL-166"></a>**DSL-166** `BondTag::Reporter(evidence_hash)` and `BondTag::Appellant(appeal_hash)` MUST be distinguishable via `PartialEq` and `Hash` even when their inner `Bytes32` values are bit-equal. `BondEscrow::escrowed(idx, Reporter(h))` and `escrowed(idx, Appellant(h))` MUST index separate slots. Serde preserves the variant discriminator.
> **Spec:** [`DSL-166.md`](specs/DSL-166.md)
