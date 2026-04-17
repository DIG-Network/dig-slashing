# REMARK Admission — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 16, 2.8

On-chain admission path for slashing evidence and slash appeals. Both travel as magic-prefixed JSON in CLVM REMARK conditions, bound to the spent coin's `puzzle_hash`.

---

## &sect;1 Evidence REMARK — Wire + Puzzle

<a id="DSL-102"></a>**DSL-102** `encode_slashing_evidence_remark_payload_v1(&SlashingEvidence)` MUST produce `SLASH_EVIDENCE_REMARK_MAGIC_V1 || serde_json::to_vec(evidence)`. `parse_slashing_evidence_from_conditions` MUST invert this for every well-formed REMARK.
> **Spec:** [`DSL-102.md`](specs/DSL-102.md)

<a id="DSL-103"></a>**DSL-103** `slashing_evidence_remark_puzzle_reveal_v1` MUST produce a CLVM program that, when executed via `chia_sdk_types::run_puzzle`, emits exactly one `Condition::Remark { message }` whose body parses back to the original evidence.
> **Spec:** [`DSL-103.md`](specs/DSL-103.md)

---

## &sect;2 Evidence Admission

<a id="DSL-104"></a>**DSL-104** `enforce_slashing_evidence_remark_admission` MUST return `Ok(())` when the spent coin's `puzzle_hash` equals `slashing_evidence_remark_puzzle_hash_v1(&evidence)`.
> **Spec:** [`DSL-104.md`](specs/DSL-104.md)

<a id="DSL-105"></a>**DSL-105** `enforce_slashing_evidence_remark_admission` MUST return `Err(SlashingRemarkError::AdmissionPuzzleHashMismatch)` when the spent coin's `puzzle_hash` differs from the derived REMARK puzzle-hash.
> **Spec:** [`DSL-105.md`](specs/DSL-105.md)

---

## &sect;3 Evidence Mempool Policy

<a id="DSL-106"></a>**DSL-106** `enforce_slashing_evidence_mempool_policy` MUST reject evidence with `current_epoch > SLASH_LOOKBACK_EPOCHS AND evidence.epoch < current_epoch - SLASH_LOOKBACK_EPOCHS` via `SlashingRemarkError::OutsideLookback`.
> **Spec:** [`DSL-106.md`](specs/DSL-106.md)

<a id="DSL-107"></a>**DSL-107** `enforce_slashing_evidence_mempool_policy` MUST reject duplicates (by JSON fingerprint) against both the pending set AND within the incoming batch via `SlashingRemarkError::DuplicateEvidence`.
> **Spec:** [`DSL-107.md`](specs/DSL-107.md)

<a id="DSL-108"></a>**DSL-108** `enforce_block_level_slashing_caps` MUST return `Err(BlockCapExceeded)` when `evidences.len() > MAX_SLASH_PROPOSALS_PER_BLOCK` (64).
> **Spec:** [`DSL-108.md`](specs/DSL-108.md)

<a id="DSL-109"></a>**DSL-109** Any evidence whose serialized JSON exceeds `MAX_SLASH_PROPOSAL_PAYLOAD_BYTES` (65_536) MUST be rejected with `SlashingRemarkError::PayloadTooLarge`.
> **Spec:** [`DSL-109.md`](specs/DSL-109.md)

---

## &sect;4 Appeal REMARK — Wire + Puzzle

<a id="DSL-110"></a>**DSL-110** `encode_slash_appeal_remark_payload_v1(&SlashAppeal)` MUST produce `SLASH_APPEAL_REMARK_MAGIC_V1 || serde_json::to_vec(appeal)`. `parse_slash_appeals_from_conditions` MUST invert this.
> **Spec:** [`DSL-110.md`](specs/DSL-110.md)

<a id="DSL-111"></a>**DSL-111** `slash_appeal_remark_puzzle_reveal_v1` MUST produce a CLVM program that emits exactly one parseable `Condition::Remark`.
> **Spec:** [`DSL-111.md`](specs/DSL-111.md)

---

## &sect;5 Appeal Admission

<a id="DSL-112"></a>**DSL-112** `enforce_slash_appeal_remark_admission` MUST return `Ok(())` on matching `puzzle_hash`.
> **Spec:** [`DSL-112.md`](specs/DSL-112.md)

<a id="DSL-113"></a>**DSL-113** `enforce_slash_appeal_remark_admission` MUST return `AdmissionPuzzleHashMismatch` on mismatched `puzzle_hash`.
> **Spec:** [`DSL-113.md`](specs/DSL-113.md)

---

## &sect;6 Appeal Mempool Policy

<a id="DSL-114"></a>**DSL-114** `enforce_slash_appeal_mempool_policy` MUST reject an appeal whose `evidence_hash` is not present in the pending-slash set via `AppealForUnknownSlash`.
> **Spec:** [`DSL-114.md`](specs/DSL-114.md)

<a id="DSL-115"></a>**DSL-115** `enforce_slash_appeal_mempool_policy` MUST reject an appeal filed after `submitted_at_epoch + SLASH_APPEAL_WINDOW_EPOCHS` via `AppealWindowExpired`.
> **Spec:** [`DSL-115.md`](specs/DSL-115.md)

<a id="DSL-116"></a>**DSL-116** `enforce_slash_appeal_mempool_policy` MUST reject an appeal referencing a `Finalised` or `Reverted` pending-slash via `AppealForFinalisedSlash`.
> **Spec:** [`DSL-116.md`](specs/DSL-116.md)

<a id="DSL-117"></a>**DSL-117** `enforce_slash_appeal_mempool_policy` MUST reject an appeal whose payload variant does not match the evidence payload variant via `AppealVariantMismatch`.
> **Spec:** [`DSL-117.md`](specs/DSL-117.md)

<a id="DSL-118"></a>**DSL-118** `enforce_slash_appeal_mempool_policy` MUST reject duplicate appeals (by byte-equal payload fingerprint) via `DuplicateEvidence` semantics.
> **Spec:** [`DSL-118.md`](specs/DSL-118.md)

<a id="DSL-119"></a>**DSL-119** `enforce_block_level_appeal_caps` MUST return `BlockCapExceeded` when `appeals.len() > MAX_APPEALS_PER_BLOCK` (64).
> **Spec:** [`DSL-119.md`](specs/DSL-119.md)

<a id="DSL-120"></a>**DSL-120** Any appeal whose serialized JSON exceeds `MAX_APPEAL_PAYLOAD_BYTES` (131_072) MUST be rejected via `PayloadTooLarge`.
> **Spec:** [`DSL-120.md`](specs/DSL-120.md)
