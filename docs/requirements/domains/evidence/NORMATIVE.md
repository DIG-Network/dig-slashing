# Evidence — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 2 (Constants), 3 (Data Model), 5 (Evidence Verification)

---

## &sect;1 Types

<a id="DSL-001"></a>**DSL-001** `OffenseType::base_penalty_bps()` MUST return `EQUIVOCATION_BASE_BPS` (500) for `ProposerEquivocation`, `INVALID_BLOCK_BASE_BPS` (300) for `InvalidBlock`, `ATTESTATION_BASE_BPS` (100) for `AttesterDoubleVote`, and `ATTESTATION_BASE_BPS` (100) for `AttesterSurroundVote`. Every returned value MUST be strictly less than `MAX_PENALTY_BPS` (1_000).
> **Spec:** [`DSL-001.md`](specs/DSL-001.md)

<a id="DSL-002"></a>**DSL-002** `SlashingEvidence::hash()` MUST be deterministic: repeated invocations on the same evidence MUST yield bit-identical `Bytes32`. Mutation of ANY field (`offense_type`, `reporter_validator_index`, `reporter_puzzle_hash`, `epoch`, or any byte of `payload`) MUST produce a different hash. The hash MUST be domain-separated under `DOMAIN_SLASHING_EVIDENCE`.
> **Spec:** [`DSL-002.md`](specs/DSL-002.md)

<a id="DSL-003"></a>**DSL-003** `Checkpoint` MUST support serde round-trip (serialize → deserialize yields a value that is `PartialEq`-equal and hashes identically). The type MUST derive `Copy`, `Eq`, `Hash`, `PartialEq`, `Serialize`, `Deserialize`.
> **Spec:** [`DSL-003.md`](specs/DSL-003.md)

<a id="DSL-004"></a>**DSL-004** `AttestationData::signing_root(&self, network_id: &Bytes32)` MUST be deterministic, MUST be prefixed with `DOMAIN_BEACON_ATTESTER`, and MUST change whenever any field (`slot`, `index`, `beacon_block_root`, `source.epoch`, `source.root`, `target.epoch`, `target.root`) or `network_id` is mutated.
> **Spec:** [`DSL-004.md`](specs/DSL-004.md)

<a id="DSL-005"></a>**DSL-005** `IndexedAttestation::validate_structure()` MUST return `Err(SlashingError::InvalidIndexedAttestation(_))` when: indices are not strictly ascending, any duplicate index exists, the list is empty, the length exceeds `MAX_VALIDATORS_PER_COMMITTEE` (2_048), or `signature.len() != BLS_SIGNATURE_SIZE` (96). Well-formed inputs MUST return `Ok(())`.
> **Spec:** [`DSL-005.md`](specs/DSL-005.md)

<a id="DSL-006"></a>**DSL-006** `IndexedAttestation::verify_signature(&self, pks: &dyn PublicKeyLookup, network_id: &Bytes32)` MUST call `chia_bls::aggregate_verify` over the committee's public keys against `signing_root(network_id)`. Valid aggregates MUST return `Ok(())`; any bit-level corruption of `signature`, any substituted public key, or any tampered message MUST return `Err(SlashingError::BlsVerifyFailed)`.
> **Spec:** [`DSL-006.md`](specs/DSL-006.md)

<a id="DSL-007"></a>**DSL-007** `AttesterSlashing::slashable_indices(&self)` MUST return the sorted (strictly ascending, no duplicates) set-intersection of `attestation_a.attesting_indices` and `attestation_b.attesting_indices`. If either operand's indices are malformed, the result is still deterministic (based on the raw stored vectors).
> **Spec:** [`DSL-007.md`](specs/DSL-007.md)

<a id="DSL-008"></a>**DSL-008** `InvalidBlockProof` and `InvalidBlockReason` MUST be constructible from all documented field combinations and MUST survive a serde round-trip byte-exactly. `InvalidBlockReason` MUST enumerate `BadStateRoot`, `BadParentRoot`, `BadTimestamp`, `BadProposerIndex`, `TransactionExecutionFailure`, `OverweightBlock`, `DuplicateTransaction`, `Other`.
> **Spec:** [`DSL-008.md`](specs/DSL-008.md)

<a id="DSL-009"></a>**DSL-009** `SignedBlockHeader { message: L2BlockHeader, signature: Vec<u8> }` MUST survive a serde round-trip byte-exactly. The deserialized value MUST be `PartialEq`-equal to the original.
> **Spec:** [`DSL-009.md`](specs/DSL-009.md)

<a id="DSL-010"></a>**DSL-010** `SlashingEvidence::slashable_validators(&self)` MUST return exactly one validator index for `Proposer` and `InvalidBlock` payloads (the `header.proposer_index`), and the full intersection cardinality (`AttesterSlashing::slashable_indices()`, which is `N >= 1` for valid attester slashings) for `Attester` payloads.
> **Spec:** [`DSL-010.md`](specs/DSL-010.md)

---

## &sect;2 Verification

<a id="DSL-011"></a>**DSL-011** `verify_evidence` MUST return `Err(SlashingError::OffenseTooOld { offense_epoch, current_epoch })` when `evidence.epoch + SLASH_LOOKBACK_EPOCHS < current_epoch`. The equality boundary (`evidence.epoch + SLASH_LOOKBACK_EPOCHS == current_epoch`) MUST be accepted.
> **Spec:** [`DSL-011.md`](specs/DSL-011.md)

<a id="DSL-012"></a>**DSL-012** `verify_evidence` MUST return `Err(SlashingError::ReporterIsAccused(reporter_index))` when `evidence.reporter_validator_index ∈ evidence.slashable_validators()`. The check MUST run after `OffenseTooOld` and reporter-registration checks.
> **Spec:** [`DSL-012.md`](specs/DSL-012.md)

<a id="DSL-013"></a>**DSL-013** `verify_proposer_slashing` MUST enforce: (a) `header_a.slot == header_b.slot`, (b) `header_a.proposer_index == header_b.proposer_index`, (c) `header_a.hash() != header_b.hash()`, (d) both signatures parse as 96-byte G2 points and verify against `block_signing_message(network_id, header.epoch, &header.hash(), header.proposer_index)`, (e) the proposer is a live validator active at `header.epoch`. Any failure MUST return `Err(SlashingError::InvalidProposerSlashing(_))` or `Err(SlashingError::BlsVerifyFailed)`.
> **Spec:** [`DSL-013.md`](specs/DSL-013.md)

<a id="DSL-014"></a>**DSL-014** `verify_attester_slashing` MUST accept a double-vote: `attestation_a.data.target.epoch == attestation_b.data.target.epoch && attestation_a.data != attestation_b.data`. When the predicate holds and all other checks pass, the verifier MUST return `Ok(VerifiedEvidence { offense_type: OffenseType::AttesterDoubleVote, .. })`.
> **Spec:** [`DSL-014.md`](specs/DSL-014.md)

<a id="DSL-015"></a>**DSL-015** `verify_attester_slashing` MUST accept a surround-vote: `a.data.source.epoch < b.data.source.epoch && a.data.target.epoch > b.data.target.epoch` (or the mirror). When the predicate holds and all other checks pass, the verifier MUST return `Ok(VerifiedEvidence { offense_type: OffenseType::AttesterSurroundVote, .. })`.
> **Spec:** [`DSL-015.md`](specs/DSL-015.md)

<a id="DSL-016"></a>**DSL-016** `verify_attester_slashing` MUST return `Err(SlashingError::EmptySlashableIntersection)` when `slashable_indices(a, b)` is empty, even if a slashable predicate holds.
> **Spec:** [`DSL-016.md`](specs/DSL-016.md)

<a id="DSL-017"></a>**DSL-017** `verify_attester_slashing` MUST return `Err(SlashingError::AttesterSlashingNotSlashable)` when neither the double-vote predicate nor the surround-vote predicate holds, regardless of other field values.
> **Spec:** [`DSL-017.md`](specs/DSL-017.md)

<a id="DSL-018"></a>**DSL-018** `verify_invalid_block` MUST verify `signed_header.signature` via `chia_bls::verify` against the message `dig_block::block_signing_message(network_id, header.epoch, &header.hash(), header.proposer_index)` and the proposer's public key. Verification failure MUST return `Err(SlashingError::BlsVerifyFailed)`.
> **Spec:** [`DSL-018.md`](specs/DSL-018.md)

<a id="DSL-019"></a>**DSL-019** `verify_invalid_block` MUST return `Err(SlashingError::InvalidSlashingEvidence(_))` when `signed_header.message.epoch != evidence.epoch`.
> **Spec:** [`DSL-019.md`](specs/DSL-019.md)

<a id="DSL-020"></a>**DSL-020** When an `InvalidBlockOracle` is supplied to `verify_invalid_block`, the verifier MUST invoke `oracle.verify_failure(header, &failure_witness, failure_reason)` and MUST return `Err(SlashingError::InvalidSlashingEvidence(_))` if the oracle returns `Err`. When no oracle is supplied (bootstrap path), the verifier MUST skip this step.
> **Spec:** [`DSL-020.md`](specs/DSL-020.md)

<a id="DSL-021"></a>**DSL-021** `verify_evidence_for_inclusion` MUST perform the exact same checks as `verify_evidence` and return the same `Result` values for the same inputs, but MUST NOT mutate any state (including the `ValidatorView` or any oracle). It is the version called by mempool and block-admission pipelines.
> **Spec:** [`DSL-021.md`](specs/DSL-021.md)

---

## &sect;3 Serialization

<a id="DSL-157"></a>**DSL-157** `SlashingEvidence` and `SlashingEvidencePayload` MUST round-trip byte-exactly via `bincode` AND `serde_json`, preserving every envelope and payload field across all three variants (`Proposer`, `Attester`, `InvalidBlock`). `serde_bytes` fields encode as raw bytes.
> **Spec:** [`DSL-157.md`](specs/DSL-157.md)

<a id="DSL-158"></a>**DSL-158** `IndexedAttestation` MUST round-trip byte-exactly via `bincode` + `serde_json`, preserving ordering of `attesting_indices`, `serde_bytes` encoding of `signature`, and nested `AttestationData` including `Checkpoint` source/target.
> **Spec:** [`DSL-158.md`](specs/DSL-158.md)
