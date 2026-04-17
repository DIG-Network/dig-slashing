# Appeal System — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 3.6, 3.7, 3.8, 6

The appeal domain implements the fraud-proof challenge path that a validator may file against a `PendingSlash` during the `SLASH_APPEAL_WINDOW_EPOCHS` window. Verification is deterministic, payload-per-ground, and bonded on both sides. All cryptographic checks reuse `chia-bls`, `chia-sha2`, and `dig-block::L2BlockHeader` signing material. The domain is validator-only — no DFSP, no CID, no availability-attestation references.

---

## &sect;1 Proposer Appeal

<a id="DSL-034"></a>**DSL-034** `verify_appeal` MUST sustain a `ProposerSlashingAppeal` with ground `HeadersIdentical` when the two `SignedBlockHeader.message` byte-slices carried by the evidence are byte-equal. No other state is consulted.
> **Spec:** [`DSL-034.md`](specs/DSL-034.md)

<a id="DSL-035"></a>**DSL-035** `verify_appeal` MUST sustain a `ProposerSlashingAppeal` with ground `ProposerIndexMismatch` when `header_a.proposer_index != header_b.proposer_index` in the evidence.
> **Spec:** [`DSL-035.md`](specs/DSL-035.md)

<a id="DSL-036"></a>**DSL-036** `verify_appeal` MUST sustain a `ProposerSlashingAppeal` with ground `SignatureAInvalid` when BLS `verify(pubkey_a, block_signing_message(header_a, network_id), sig_a)` returns `false`. The pubkey is resolved via `validator_view` using `header_a.proposer_index`.
> **Spec:** [`DSL-036.md`](specs/DSL-036.md)

<a id="DSL-037"></a>**DSL-037** `verify_appeal` MUST sustain a `ProposerSlashingAppeal` with ground `SignatureBInvalid` under the same rule as DSL-036 applied to `header_b` / `sig_b`.
> **Spec:** [`DSL-037.md`](specs/DSL-037.md)

<a id="DSL-038"></a>**DSL-038** `verify_appeal` MUST sustain a `ProposerSlashingAppeal` with ground `SlotMismatch` when `header_a.slot != header_b.slot`.
> **Spec:** [`DSL-038.md`](specs/DSL-038.md)

<a id="DSL-039"></a>**DSL-039** `verify_appeal` MUST sustain a `ProposerSlashingAppeal` with ground `ValidatorNotActiveAtEpoch` when `validator_view.is_active_at_epoch(proposer_index, header.epoch)` returns `false`. The witness carries an `ActivationRange { activation_epoch, exit_epoch }` but the authoritative predicate is `validator_view`.
> **Spec:** [`DSL-039.md`](specs/DSL-039.md)

<a id="DSL-040"></a>**DSL-040** `verify_appeal` MUST reject a `ProposerSlashingAppeal` whose ground does not hold on the evidence (e.g. `HeadersIdentical` on non-identical headers, `SlotMismatch` on equal slots, `SignatureAInvalid` on a genuine signature). The verdict is `AppealVerdict::Rejected`.
> **Spec:** [`DSL-040.md`](specs/DSL-040.md)

---

## &sect;2 Attester Appeal

<a id="DSL-041"></a>**DSL-041** `verify_appeal` MUST sustain an `AttesterSlashingAppeal` with ground `AttestationsIdentical` when the canonical byte encodings of `attestation_1` and `attestation_2` in the evidence are byte-equal.
> **Spec:** [`DSL-041.md`](specs/DSL-041.md)

<a id="DSL-042"></a>**DSL-042** `verify_appeal` MUST sustain an `AttesterSlashingAppeal` with ground `NotSlashableByPredicate` when neither the double-vote predicate (`data_1.target.epoch == data_2.target.epoch && data_1 != data_2`) nor the surround-vote predicate (`src1 < src2 && tgt2 < tgt1` or mirror) holds.
> **Spec:** [`DSL-042.md`](specs/DSL-042.md)

<a id="DSL-043"></a>**DSL-043** `verify_appeal` MUST sustain an `AttesterSlashingAppeal` with ground `EmptyIntersection` when the sorted-ascending intersection of `attestation_1.attesting_indices` and `attestation_2.attesting_indices` is empty.
> **Spec:** [`DSL-043.md`](specs/DSL-043.md)

<a id="DSL-044"></a>**DSL-044** `verify_appeal` MUST sustain an `AttesterSlashingAppeal` with ground `SignatureAInvalid` when the aggregate BLS verify of `attestation_1.signature` over `attestation_1.data.signing_root(network_id)` and the committee pubkeys (resolved via `validator_view`) returns `false`.
> **Spec:** [`DSL-044.md`](specs/DSL-044.md)

<a id="DSL-045"></a>**DSL-045** `verify_appeal` MUST sustain an `AttesterSlashingAppeal` with ground `SignatureBInvalid` under the same rule as DSL-044 applied to `attestation_2`.
> **Spec:** [`DSL-045.md`](specs/DSL-045.md)

<a id="DSL-046"></a>**DSL-046** `verify_appeal` MUST sustain an `AttesterSlashingAppeal` with ground `InvalidIndexedAttestationStructure` when either `attestation_1.validate_structure()` or `attestation_2.validate_structure()` returns an error (empty indices, non-ascending, duplicates, or committee overflow).
> **Spec:** [`DSL-046.md`](specs/DSL-046.md)

<a id="DSL-047"></a>**DSL-047** `verify_appeal` MUST sustain an `AttesterSlashingAppeal` with ground `ValidatorNotInIntersection { validator_index }` when the named `validator_index` is not a member of the intersection of the two `attesting_indices` sets.
> **Spec:** [`DSL-047.md`](specs/DSL-047.md)

<a id="DSL-048"></a>**DSL-048** `verify_appeal` MUST reject an `AttesterSlashingAppeal` when the evidence is a genuine slashing (structurally valid, slashable predicate holds, intersection non-empty, both signatures valid). The verdict is `AppealVerdict::Rejected`.
> **Spec:** [`DSL-048.md`](specs/DSL-048.md)

---

## &sect;3 Invalid-Block Appeal

<a id="DSL-049"></a>**DSL-049** `verify_appeal` MUST sustain an `InvalidBlockAppeal` with ground `BlockActuallyValid` when `InvalidBlockOracle::re_execute(header, witness)` returns `ExecutionOutcome::Valid`. The oracle MUST be supplied; otherwise see DSL-053.
> **Spec:** [`DSL-049.md`](specs/DSL-049.md)

<a id="DSL-050"></a>**DSL-050** `verify_appeal` MUST sustain an `InvalidBlockAppeal` with ground `ProposerSignatureInvalid` when BLS verify of the evidence's signature over `block_signing_message(header, network_id)` returns `false`. No oracle is required.
> **Spec:** [`DSL-050.md`](specs/DSL-050.md)

<a id="DSL-051"></a>**DSL-051** `verify_appeal` MUST sustain an `InvalidBlockAppeal` with ground `FailureReasonMismatch` when `InvalidBlockOracle::re_execute(header, witness)` returns `ExecutionOutcome::Invalid(actual_reason)` and `actual_reason != evidence.failure_reason`.
> **Spec:** [`DSL-051.md`](specs/DSL-051.md)

<a id="DSL-052"></a>**DSL-052** `verify_appeal` MUST sustain an `InvalidBlockAppeal` with ground `EvidenceEpochMismatch` when `header.slot / SLOTS_PER_EPOCH != evidence.epoch`. No oracle is required.
> **Spec:** [`DSL-052.md`](specs/DSL-052.md)

<a id="DSL-053"></a>**DSL-053** `verify_appeal` MUST return `AppealError::MissingOracle("invalid_block_oracle")` when the appeal ground requires re-execution (`BlockActuallyValid` or `FailureReasonMismatch`) and no `InvalidBlockOracle` was supplied by the caller.
> **Spec:** [`DSL-053.md`](specs/DSL-053.md)

<a id="DSL-054"></a>**DSL-054** `verify_appeal` MUST reject an `InvalidBlockAppeal` when the evidence describes a genuinely invalid block (oracle confirms `Invalid(reason)` matching `evidence.failure_reason`, proposer signature is valid, and epoch field matches).
> **Spec:** [`DSL-054.md`](specs/DSL-054.md)

---

## &sect;4 Appeal Submission Preconditions

<a id="DSL-055"></a>**DSL-055** `SlashingManager::submit_appeal` MUST return `AppealError::UnknownEvidence(hex(appeal.evidence_hash))` when no `PendingSlash` with that hash exists in the `PendingSlashBook`.
> **Spec:** [`DSL-055.md`](specs/DSL-055.md)

<a id="DSL-056"></a>**DSL-056** `submit_appeal` MUST return `AppealError::WindowExpired { submitted_at, window, current }` when `appeal.filed_epoch > pending.window_expires_at_epoch`.
> **Spec:** [`DSL-056.md`](specs/DSL-056.md)

<a id="DSL-057"></a>**DSL-057** `submit_appeal` MUST return `AppealError::VariantMismatch` when `appeal.payload` variant (Proposer/Attester/InvalidBlock) does not match `pending.evidence.payload` variant.
> **Spec:** [`DSL-057.md`](specs/DSL-057.md)

<a id="DSL-058"></a>**DSL-058** `submit_appeal` MUST return `AppealError::DuplicateAppeal` when the canonical serialization of the incoming appeal is byte-equal to an existing `AppealAttempt.appeal_hash` preimage on the pending record.
> **Spec:** [`DSL-058.md`](specs/DSL-058.md)

<a id="DSL-059"></a>**DSL-059** `submit_appeal` MUST return `AppealError::TooManyAttempts { count, limit }` when `pending.appeal_history.len() >= MAX_APPEAL_ATTEMPTS_PER_SLASH` (`= 4`).
> **Spec:** [`DSL-059.md`](specs/DSL-059.md)

<a id="DSL-060"></a>**DSL-060** `submit_appeal` MUST return `AppealError::SlashAlreadyReverted` when `pending.status` is `Reverted { .. }`.
> **Spec:** [`DSL-060.md`](specs/DSL-060.md)

<a id="DSL-061"></a>**DSL-061** `submit_appeal` MUST return `AppealError::SlashAlreadyFinalised` when `pending.status` is `Finalised { .. }`.
> **Spec:** [`DSL-061.md`](specs/DSL-061.md)

<a id="DSL-062"></a>**DSL-062** `submit_appeal` MUST call `BondEscrow::lock(appellant_index, APPELLANT_BOND_MOJOS, BondTag::Appellant(appeal_hash))` **before** adjudication. A lock failure MUST be surfaced as `AppealError::AppellantBondLockFailed`.
> **Spec:** [`DSL-062.md`](specs/DSL-062.md)

<a id="DSL-063"></a>**DSL-063** `submit_appeal` MUST return `AppealError::PayloadTooLarge { actual, limit }` when the canonical serialization of `appeal.payload` exceeds `MAX_APPEAL_PAYLOAD_BYTES` (`= 131_072`).
> **Spec:** [`DSL-063.md`](specs/DSL-063.md)

---

## &sect;5 Adjudicator

<a id="DSL-064"></a>**DSL-064** On `AppealVerdict::Sustained`, `AppealAdjudicator::adjudicate` MUST call `ValidatorView::credit_stake(idx, base_slash_amount)` for every `PerValidatorSlash` in `pending.base_slash_per_validator`, reverting the original stake deduction.
> **Spec:** [`DSL-064.md`](specs/DSL-064.md)

<a id="DSL-065"></a>**DSL-065** On `AppealVerdict::Sustained`, `adjudicate` MUST call `CollateralSlasher::credit(idx, collateral_slashed)` for every `PerValidatorSlash` with non-zero collateral, when a collateral slasher is supplied.
> **Spec:** [`DSL-065.md`](specs/DSL-065.md)

<a id="DSL-066"></a>**DSL-066** On `AppealVerdict::Sustained`, `adjudicate` MUST call `ValidatorView::restore_status(idx)` for every validator listed in `pending.base_slash_per_validator`, clearing the slashed flag and exit lock.
> **Spec:** [`DSL-066.md`](specs/DSL-066.md)

<a id="DSL-067"></a>**DSL-067** On `AppealVerdict::Sustained`, `adjudicate` MUST call `RewardClawback::claw_back(reporter_ph, wb_reward)` and `RewardClawback::claw_back(proposer_ph, prop_reward)`, totalling any shortfall (amount not recovered) into `AppealAdjudicationResult.clawback_shortfall`.
> **Spec:** [`DSL-067.md`](specs/DSL-067.md)

<a id="DSL-068"></a>**DSL-068** On `AppealVerdict::Sustained`, `adjudicate` MUST call `BondEscrow::forfeit(reporter_idx, REPORTER_BOND_MOJOS, BondTag::Reporter(evidence_hash))` and split the forfeited amount: `appellant_award = forfeited * BOND_AWARD_TO_WINNER_BPS / 10_000` (50%) paid to appellant; the remainder is burned (after shortfall absorption, see DSL-073).
> **Spec:** [`DSL-068.md`](specs/DSL-068.md)

<a id="DSL-069"></a>**DSL-069** On `AppealVerdict::Sustained`, `adjudicate` MUST slash the reporter using the InvalidBlock base formula: `base = max(eff_bal * INVALID_BLOCK_BASE_BPS / 10_000, eff_bal / 32)`; then `ValidatorView::slash_absolute(reporter_idx, base, current_epoch)` and record into `slashed_in_window`.
> **Spec:** [`DSL-069.md`](specs/DSL-069.md)

<a id="DSL-070"></a>**DSL-070** On `AppealVerdict::Sustained`, `adjudicate` MUST set `pending.status = PendingSlashStatus::Reverted { winning_appeal_hash, reverted_at_epoch: current_epoch }` and append an `AppealAttempt { outcome: Won }` to `pending.appeal_history`.
> **Spec:** [`DSL-070.md`](specs/DSL-070.md)

<a id="DSL-071"></a>**DSL-071** On `AppealVerdict::Rejected`, `adjudicate` MUST call `BondEscrow::forfeit(appellant_idx, APPELLANT_BOND_MOJOS, BondTag::Appellant(appeal_hash))`; `reporter_award = forfeited * BOND_AWARD_TO_WINNER_BPS / 10_000` paid via `RewardPayout::pay(reporter_ph, reporter_award)`; burn = `forfeited - reporter_award`.
> **Spec:** [`DSL-071.md`](specs/DSL-071.md)

<a id="DSL-072"></a>**DSL-072** On `AppealVerdict::Rejected`, `adjudicate` MUST leave `pending.status = PendingSlashStatus::ChallengeOpen { first_appeal_filed_epoch: min(existing, filed), appeal_count: n + 1 }` and append an `AppealAttempt { outcome: Lost { reason_hash } }` to `pending.appeal_history`.
> **Spec:** [`DSL-072.md`](specs/DSL-072.md)

<a id="DSL-073"></a>**DSL-073** On `AppealVerdict::Sustained`, any `clawback_shortfall` (tokens that `RewardClawback` could not recover) MUST be absorbed by burning from the forfeited reporter bond BEFORE computing `appellant_award`; any residue after winner award is burned. If the shortfall exceeds the forfeited bond, the overflow is reported in telemetry but does not create protocol debt.
> **Spec:** [`DSL-073.md`](specs/DSL-073.md)

---

## &sect;6 SlashAppeal Hash + Serde

<a id="DSL-159"></a>**DSL-159** `SlashAppeal::hash()` MUST be deterministic across calls and MUST change on ANY field mutation (`evidence_hash`, `appellant_index`, `appellant_puzzle_hash`, `filed_epoch`, or any byte of `payload`). Domain-prefixed under `DOMAIN_SLASH_APPEAL` using `chia_sha2::Sha256`.
> **Spec:** [`DSL-159.md`](specs/DSL-159.md)

<a id="DSL-160"></a>**DSL-160** `SlashAppeal`, `SlashAppealPayload`, and all per-offense ground enums MUST round-trip byte-exactly via `bincode` + `serde_json`. Every ground including `AttesterAppealGround::ValidatorNotInIntersection { validator_index }` preserves its payload fields.
> **Spec:** [`DSL-160.md`](specs/DSL-160.md)

<a id="DSL-161"></a>**DSL-161** `PendingSlash`, `PendingSlashStatus` (all 4 variants), `AppealAttempt`, and `AppealOutcome` (all 3 variants) MUST round-trip byte-exactly via `bincode`.
> **Spec:** [`DSL-161.md`](specs/DSL-161.md)

<a id="DSL-164"></a>**DSL-164** `AppealAdjudicationResult` MUST round-trip byte-exactly via `bincode` + `serde_json`. Sustained (reverted_* populated) and Rejected (reporter_award > 0) cases both preserved; `AppealOutcome` variants all preserved.
> **Spec:** [`DSL-164.md`](specs/DSL-164.md)
