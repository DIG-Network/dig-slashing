//! Evidence verification dispatcher.
//!
//! Traces to: [SPEC.md §5.1](../../docs/resources/SPEC.md), catalogue rows
//! [DSL-011..021](../../docs/requirements/domains/evidence/specs/).
//!
//! # Role
//!
//! `verify_evidence` is the sole entry point every `SlashingEvidence`
//! flows through on its way to:
//!
//! - `SlashingManager::submit_evidence` (DSL-022) — state-mutating.
//! - Block-admission / mempool pipelines — via
//!   `verify_evidence_for_inclusion` (DSL-021), which must be identical
//!   minus state mutation.
//!
//! The function runs per-envelope preconditions in a fixed order, then
//! dispatches per payload variant. Preconditions are split into
//! "cheap filters" (epoch lookback, reporter registration / self-accuse)
//! and "crypto-heavy" (BLS verify, oracle re-execution) — cheap first.
//!
//! # Implementation status
//!
//! This module currently implements the OffenseTooOld precondition
//! (DSL-011) and emits a placeholder success result for every other
//! path. The remaining preconditions (DSL-012 reporter self-accuse,
//! DSL-013..020 per-payload dispatch) land in subsequent commits. Each
//! DSL row adds one conditional, never mutating the structure of the
//! function.

use chia_bls::{PublicKey, Signature};
use dig_protocol::Bytes32;

use crate::constants::{
    BLS_SIGNATURE_SIZE, DOMAIN_BEACON_PROPOSER, MAX_SLASH_PROPOSAL_PAYLOAD_BYTES,
};
use crate::error::SlashingError;
use crate::evidence::attester_slashing::AttesterSlashing;
use crate::evidence::envelope::{SlashingEvidence, SlashingEvidencePayload};
use crate::evidence::invalid_block::InvalidBlockProof;
use crate::evidence::offense::OffenseType;
use crate::evidence::proposer_slashing::{ProposerSlashing, SignedBlockHeader};
use crate::traits::{InvalidBlockOracle, PublicKeyLookup, ValidatorView};

/// Successful-verification return shape.
///
/// Traces to [SPEC §3.9](../../docs/resources/SPEC.md).
///
/// # Invariants
///
/// - `offense_type == evidence.offense_type` (verifier never reclassifies).
/// - `slashable_validator_indices == evidence.slashable_validators()`
///   (same ordering + cardinality; ascending for Attester per DSL-010).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VerifiedEvidence {
    /// Classification of the confirmed offense. Drives base-penalty
    /// lookup (DSL-001) and downstream reward routing.
    pub offense_type: OffenseType,
    /// Validator indices the manager will debit. For Proposer /
    /// InvalidBlock this is a single-element vec; for Attester it is
    /// the sorted intersection (DSL-007).
    pub slashable_validator_indices: Vec<u32>,
}

/// Verify a `SlashingEvidence` envelope against the current validator
/// set + epoch context.
///
/// Implements [DSL-011](../../docs/requirements/domains/evidence/specs/DSL-011.md)
/// (OffenseTooOld precondition). Subsequent DSLs extend this function
/// rather than replace it — verifier ordering is protocol.
///
/// # Current precondition order
///
/// 1. **OffenseTooOld** (DSL-011): `evidence.epoch + SLASH_LOOKBACK_EPOCHS
///    >= current_epoch`. Addition on the LHS avoids underflow at network
///    boot (`current_epoch < SLASH_LOOKBACK_EPOCHS`).
/// 2. **ReporterIsAccused** (DSL-012):
///    `evidence.reporter_validator_index ∉ evidence.slashable_validators()`.
///    Blocks a validator from self-slashing to collect the whistleblower
///    reward.
///
/// 3. **Per-payload dispatch**:
///    - Proposer → [`verify_proposer_slashing`] (DSL-013).
///    - Attester / InvalidBlock → placeholder accept (DSL-014..020 land
///      in subsequent commits).
///
/// # Not yet enforced (placeholder accept)
///
/// - DSL-014/015: attester double-vote / surround-vote predicates.
/// - DSL-016/017: attester intersection / predicate failure.
/// - DSL-018/019/020: invalid-block signature / epoch / oracle.
///
/// Until those land, envelopes passing the lookback check return a
/// placeholder `VerifiedEvidence` — consumers MUST NOT treat this
/// function as fully soundness-complete yet. The placeholder is
/// observable only in test fixtures (DSL-011 test only exercises the
/// boundary + error path).
///
/// # Parameters
///
/// - `evidence`: the envelope to verify.
/// - `_validator_view`: validator set handle. Consumed by DSL-012+
///   (currently unused but locked into the signature per SPEC §5.1).
/// - `_network_id`: chain id for BLS signing-root derivation. Consumed
///   by DSL-013/018 (currently unused).
/// - `current_epoch`: epoch the verifier is running in. ONLY required
///   right now for the OffenseTooOld check.
pub fn verify_evidence(
    evidence: &SlashingEvidence,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
    current_epoch: u64,
) -> Result<VerifiedEvidence, SlashingError> {
    // DSL-011: OffenseTooOld. Phrased with `evidence.epoch + LOOKBACK`
    // on the LHS so `current_epoch = 0` cannot underflow the RHS.
    // `u64::saturating_add` is the defensive belt — `evidence.epoch`
    // arriving as `u64::MAX - LOOKBACK` would overflow a naïve `+`.
    let lookback_sum = evidence
        .epoch
        .saturating_add(dig_epoch::SLASH_LOOKBACK_EPOCHS);
    if lookback_sum < current_epoch {
        return Err(SlashingError::OffenseTooOld {
            offense_epoch: evidence.epoch,
            current_epoch,
        });
    }

    // DSL-012: ReporterIsAccused. Compute slashable validators once and
    // reuse for both this check and the `VerifiedEvidence` return.
    // Intentional binding: a validator cannot whistleblow on itself and
    // collect the reward — that would turn slashing into a profitable
    // self-report.
    let slashable = evidence.slashable_validators();
    if slashable.contains(&evidence.reporter_validator_index) {
        return Err(SlashingError::ReporterIsAccused(
            evidence.reporter_validator_index,
        ));
    }

    // DSL-013+: per-payload dispatch. Each variant drives a dedicated
    // verifier that enforces payload-specific preconditions + BLS math.
    // The dispatcher never reclassifies offense_type — it either
    // returns the same `VerifiedEvidence { offense_type, slashable }`
    // or a payload-specific error variant.
    let _ = slashable;
    match &evidence.payload {
        SlashingEvidencePayload::Proposer(p) => {
            verify_proposer_slashing(evidence, p, validator_view, network_id)
        }
        SlashingEvidencePayload::Attester(a) => {
            verify_attester_slashing(evidence, a, validator_view, network_id)
        }
        // DSL-018..020: invalid-block. Dispatcher passes `None` for the
        // oracle — bootstrap semantics; callers needing full re-execution
        // call `verify_invalid_block` directly with `Some(oracle)`.
        SlashingEvidencePayload::InvalidBlock(i) => {
            verify_invalid_block(evidence, i, validator_view, network_id, None)
        }
    }
}

/// Proposer-equivocation verifier.
///
/// Implements [DSL-013](../../docs/requirements/domains/evidence/specs/DSL-013.md).
/// Traces to SPEC §5.2.
///
/// # Preconditions (checked in order)
///
/// 1. `header_a.slot == header_b.slot` — equivocation requires the
///    proposer signed at the SAME slot.
/// 2. `header_a.proposer_index == header_b.proposer_index` — both
///    signatures must claim the same proposer.
/// 3. `header_a.hash() != header_b.hash()` — different content; two
///    byte-equal headers are not equivocation (DSL-034 appeal ground
///    `HeadersIdentical`).
/// 4. Both `signature.len() == BLS_SIGNATURE_SIZE` and decode as a
///    valid G2 element.
/// 5. Validator at `proposer_index` exists in the view, is not already
///    slashed (short-circuit — DSL-026 dedup will reject at manager
///    level but we reject here too to keep mempool admission honest),
///    and `is_active_at_epoch(header_a.message.epoch)`.
/// 6. Both signatures BLS-verify under the validator's pubkey against
///    [`block_signing_message`] for their respective header.
///
/// # Returns
///
/// `Ok(VerifiedEvidence)` with `slashable_validator_indices ==
/// [proposer_index]` (cardinality 1 per DSL-010).
///
/// Every precondition failure returns
/// `SlashingError::InvalidProposerSlashing(reason)` carrying a
/// human-readable diagnostic — appeals (DSL-034..040) distinguish the
/// same categories via structured variants at their own layer.
pub fn verify_proposer_slashing(
    evidence: &SlashingEvidence,
    payload: &ProposerSlashing,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
) -> Result<VerifiedEvidence, SlashingError> {
    let header_a = &payload.signed_header_a.message;
    let header_b = &payload.signed_header_b.message;

    // 1. Same slot.
    if header_a.height != header_b.height {
        return Err(SlashingError::InvalidProposerSlashing(format!(
            "slot mismatch: header_a.height={}, header_b.height={}",
            header_a.height, header_b.height,
        )));
    }

    // 2. Same proposer.
    if header_a.proposer_index != header_b.proposer_index {
        return Err(SlashingError::InvalidProposerSlashing(format!(
            "proposer mismatch: header_a.proposer_index={}, header_b.proposer_index={}",
            header_a.proposer_index, header_b.proposer_index,
        )));
    }

    // 3. Different content. Using `hash()` is cheaper than full
    // `header_a == header_b` byte compare on the multi-KB preimage
    // because `L2BlockHeader::hash` is a single SHA-256.
    let hash_a = header_a.hash();
    let hash_b = header_b.hash();
    if hash_a == hash_b {
        return Err(SlashingError::InvalidProposerSlashing(
            "headers are identical (no equivocation)".into(),
        ));
    }

    // 4. Decode both signatures. Width + parse failures collapse to
    // InvalidProposerSlashing with a reason naming which side failed.
    let sig_a = decode_sig(&payload.signed_header_a, "a")?;
    let sig_b = decode_sig(&payload.signed_header_b, "b")?;

    // 5. Validator lookup + active check. `is_active_at_epoch` is
    // activation-inclusive, exit-exclusive (DSL-134).
    let proposer_index = header_a.proposer_index;
    let entry = validator_view
        .get(proposer_index)
        .ok_or(SlashingError::ValidatorNotRegistered(proposer_index))?;
    if entry.is_slashed() {
        return Err(SlashingError::InvalidProposerSlashing(format!(
            "proposer {proposer_index} is already slashed",
        )));
    }
    if !entry.is_active_at_epoch(header_a.epoch) {
        return Err(SlashingError::InvalidProposerSlashing(format!(
            "proposer {proposer_index} not active at epoch {}",
            header_a.epoch,
        )));
    }

    // 6. BLS verify both signatures against the respective signing
    // messages. The augmented scheme (pk || msg) is applied by
    // `chia_bls::verify` internally — same convention as DSL-006.
    let pk = entry.public_key();
    let msg_a = block_signing_message(network_id, header_a.epoch, &hash_a, proposer_index);
    let msg_b = block_signing_message(network_id, header_b.epoch, &hash_b, proposer_index);
    if !chia_bls::verify(&sig_a, pk, &msg_a) {
        return Err(SlashingError::InvalidProposerSlashing(
            "signature A BLS verify failed".into(),
        ));
    }
    if !chia_bls::verify(&sig_b, pk, &msg_b) {
        return Err(SlashingError::InvalidProposerSlashing(
            "signature B BLS verify failed".into(),
        ));
    }

    Ok(VerifiedEvidence {
        offense_type: evidence.offense_type,
        slashable_validator_indices: vec![proposer_index],
    })
}

/// Attester-slashing verifier.
///
/// Implements [DSL-014](../../docs/requirements/domains/evidence/specs/DSL-014.md)
/// (double-vote predicate + acceptance path). Also enforces the sibling
/// preconditions that share the same control flow:
/// [DSL-015](../../docs/requirements/domains/evidence/specs/DSL-015.md)
/// (surround-vote), [DSL-016](../../docs/requirements/domains/evidence/specs/DSL-016.md)
/// (empty-intersection rejection), and
/// [DSL-017](../../docs/requirements/domains/evidence/specs/DSL-017.md)
/// (neither-predicate rejection).
///
/// Traces to SPEC §5.3.
///
/// # Preconditions (checked in order)
///
/// 1. `attestation_a.validate_structure()` AND
///    `attestation_b.validate_structure()` (DSL-005).
/// 2. `attestation_a != attestation_b` (byte-wise) — byte-identical
///    pairs are `InvalidAttesterSlashing("identical")`; they are NOT a
///    slashable offense and the appeal ground `AttestationsIdentical`
///    (DSL-041) mirrors this.
/// 3. Double-vote OR surround-vote predicate holds (DSL-014 /
///    DSL-015). If neither →
///    [`SlashingError::AttesterSlashingNotSlashable`] (DSL-017).
/// 4. `slashable = payload.slashable_indices()` non-empty (DSL-016).
///    If empty → [`SlashingError::EmptySlashableIntersection`].
/// 5. Both `IndexedAttestation::verify_signature` succeed (DSL-006) —
///    aggregate BLS verify against each `AttestationData::signing_root`.
///    Pubkeys are looked up through `validator_view`.
///
/// # Ordering rationale
///
/// Structure + identical + predicate + intersection are all byte
/// comparisons — cheapest first. BLS verify is last because a
/// failed aggregate pairing is the most expensive check. This
/// ordering is protocol (appeal adjudication in DSL-042..048 walks
/// the same sequence) and MUST NOT be reordered.
///
/// # Returns
///
/// `Ok(VerifiedEvidence { slashable_validator_indices: intersection })`
/// where the intersection is the sorted set `{i : i ∈ a.indices ∧ i ∈
/// b.indices}` (DSL-007).
pub fn verify_attester_slashing(
    evidence: &SlashingEvidence,
    payload: &AttesterSlashing,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
) -> Result<VerifiedEvidence, SlashingError> {
    // 1. Structure. `validate_structure` returns a reason-bearing
    // `InvalidIndexedAttestation`; bubble it up. Consumers (e.g.
    // DSL-046 appeal ground) need the sub-variant intact.
    payload.attestation_a.validate_structure()?;
    payload.attestation_b.validate_structure()?;

    // 2. Byte-identical pair → not equivocation.
    if payload.attestation_a == payload.attestation_b {
        return Err(SlashingError::InvalidAttesterSlashing(
            "attestations are byte-identical (no offense)".into(),
        ));
    }

    // 3. Predicate decision. A slashing is valid iff EITHER predicate
    // holds. DSL-014: same target epoch + different data. DSL-015:
    // one window strictly surrounds the other (checked both ways).
    let a_data = &payload.attestation_a.data;
    let b_data = &payload.attestation_b.data;
    let is_double_vote = a_data.target.epoch == b_data.target.epoch && a_data != b_data;
    let is_surround_vote = (a_data.source.epoch < b_data.source.epoch
        && a_data.target.epoch > b_data.target.epoch)
        || (b_data.source.epoch < a_data.source.epoch && b_data.target.epoch > a_data.target.epoch);
    if !(is_double_vote || is_surround_vote) {
        return Err(SlashingError::AttesterSlashingNotSlashable);
    }

    // 4. Intersection must be non-empty (DSL-016). Run BEFORE the BLS
    // verify so honest nodes don't pay pairing cost on adversarial
    // disjoint-committee evidence.
    let slashable = payload.slashable_indices();
    if slashable.is_empty() {
        return Err(SlashingError::EmptySlashableIntersection);
    }

    // 5. BLS aggregate verify on BOTH attestations (DSL-006). Pubkeys
    // come from the validator view via the `PublicKeyLookup` adapter.
    // A missing index for any committee member collapses to
    // `BlsVerifyFailed` — same coarse channel as DSL-006.
    let pks = ValidatorViewPubkeys(validator_view);
    payload.attestation_a.verify_signature(&pks, network_id)?;
    payload.attestation_b.verify_signature(&pks, network_id)?;

    // Classification: the verifier does NOT reclassify offense_type.
    // The envelope already declares AttesterDoubleVote or AttesterSurroundVote;
    // the predicate test above only confirms that at least one predicate
    // holds. An honest reporter MAY file a double-vote evidence under
    // the AttesterDoubleVote offense_type; correlation-penalty math
    // (DSL-030) treats both variants identically.
    Ok(VerifiedEvidence {
        offense_type: evidence.offense_type,
        slashable_validator_indices: slashable,
    })
}

/// Invalid-block verifier.
///
/// Implements [DSL-018](../../docs/requirements/domains/evidence/specs/DSL-018.md)
/// (BLS over `block_signing_message`). Also enforces the sibling
/// preconditions that share the same control flow:
/// [DSL-019](../../docs/requirements/domains/evidence/specs/DSL-019.md)
/// (`evidence.epoch == header.epoch`) and
/// [DSL-020](../../docs/requirements/domains/evidence/specs/DSL-020.md)
/// (optional `InvalidBlockOracle::verify_failure` call).
///
/// Traces to SPEC §5.4.
///
/// # Preconditions (checked in order)
///
/// 1. `header.epoch == evidence.epoch` (DSL-019) — cheap filter before
///    any BLS work.
/// 2. `failure_witness.len() ∈ [1, MAX_SLASH_PROPOSAL_PAYLOAD_BYTES]`
///    (SPEC §5.4 step 4).
/// 3. Signature decodes as a valid 96-byte G2 element.
/// 4. Validator exists in the view, is not already slashed, and is
///    active at `header.epoch`.
/// 5. BLS verify via `chia_bls::verify(sig, pk, block_signing_message(...))`
///    using the SAME helper as honest block production (DSL-018).
/// 6. Optional `oracle.verify_failure(header, witness, reason)` —
///    bootstrap mode (`oracle = None`) accepts; full-node mode
///    re-executes and rejects on disagreement (DSL-020).
///
/// # Ordering rationale
///
/// Cheap scalar compare → size check → sig parse → validator lookup →
/// BLS pairing → oracle re-execution. Each stage is stricty more
/// expensive than the previous; honest nodes reject adversarial
/// evidence at the earliest possible stage.
///
/// # Returns
///
/// `Ok(VerifiedEvidence)` with
/// `slashable_validator_indices = [proposer_index]` (cardinality 1
/// per DSL-010).
pub fn verify_invalid_block(
    evidence: &SlashingEvidence,
    payload: &InvalidBlockProof,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
    oracle: Option<&dyn InvalidBlockOracle>,
) -> Result<VerifiedEvidence, SlashingError> {
    let header = &payload.signed_header.message;

    // 1. Epoch match (DSL-019). Cheap + first — a mismatched envelope
    // epoch is either a reporter bug or a replay attempt.
    if header.epoch != evidence.epoch {
        return Err(SlashingError::InvalidSlashingEvidence(format!(
            "epoch mismatch: header={} envelope={}",
            header.epoch, evidence.epoch,
        )));
    }

    // 2. Witness size bound. Zero-length witnesses are trivially
    // useless (nothing to re-execute); oversized witnesses are a
    // payload-bloat attack.
    let witness_len = payload.failure_witness.len();
    if witness_len == 0 {
        return Err(SlashingError::InvalidSlashingEvidence(
            "failure_witness is empty".into(),
        ));
    }
    if witness_len > MAX_SLASH_PROPOSAL_PAYLOAD_BYTES {
        return Err(SlashingError::InvalidSlashingEvidence(format!(
            "failure_witness length {witness_len} exceeds MAX_SLASH_PROPOSAL_PAYLOAD_BYTES ({MAX_SLASH_PROPOSAL_PAYLOAD_BYTES})",
        )));
    }

    // 3. Signature decode.
    let sig_bytes: &[u8; BLS_SIGNATURE_SIZE] = payload
        .signed_header
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            SlashingError::InvalidSlashingEvidence(format!(
                "signature width {} != {BLS_SIGNATURE_SIZE}",
                payload.signed_header.signature.len(),
            ))
        })?;
    let sig = Signature::from_bytes(sig_bytes).map_err(|_| {
        SlashingError::InvalidSlashingEvidence("signature failed to decode as BLS G2".into())
    })?;

    // 4. Validator lookup + state checks.
    let proposer_index = header.proposer_index;
    let entry = validator_view
        .get(proposer_index)
        .ok_or(SlashingError::ValidatorNotRegistered(proposer_index))?;
    if entry.is_slashed() {
        return Err(SlashingError::InvalidSlashingEvidence(format!(
            "proposer {proposer_index} is already slashed",
        )));
    }
    if !entry.is_active_at_epoch(header.epoch) {
        return Err(SlashingError::InvalidSlashingEvidence(format!(
            "proposer {proposer_index} not active at epoch {}",
            header.epoch,
        )));
    }

    // 5. BLS verify over the canonical block-signing message (DSL-018).
    // SAME helper as honest block production → domain binding prevents
    // cross-network replay + cross-context (attester) replay.
    let msg = block_signing_message(network_id, header.epoch, &header.hash(), proposer_index);
    let pk = entry.public_key();
    if !chia_bls::verify(&sig, pk, &msg) {
        return Err(SlashingError::InvalidSlashingEvidence(
            "bad invalid-block signature".into(),
        ));
    }

    // 6. Optional oracle (DSL-020). `None` → bootstrap mode. Full-node
    // impls re-execute the block and validate the claimed failure
    // reason. Any oracle error propagates.
    if let Some(oracle) = oracle {
        oracle.verify_failure(header, &payload.failure_witness, payload.failure_reason)?;
    }

    Ok(VerifiedEvidence {
        offense_type: evidence.offense_type,
        slashable_validator_indices: vec![proposer_index],
    })
}

/// Zero-cost adapter that lets `verify_attester_slashing` reuse
/// `IndexedAttestation::verify_signature` (DSL-006) against a
/// `ValidatorView`.
///
/// `ValidatorView` and `PublicKeyLookup` are separate traits by design
/// (SPEC §15) — the view owns mutating state, the lookup is read-only.
/// Bridging inline here avoids forcing downstream callers to implement
/// both traits on the same struct.
struct ValidatorViewPubkeys<'a>(&'a dyn ValidatorView);

impl<'a> PublicKeyLookup for ValidatorViewPubkeys<'a> {
    fn pubkey_of(&self, index: u32) -> Option<&PublicKey> {
        self.0.get(index).map(|e| e.public_key())
    }
}

/// Parse a 96-byte BLS G2 signature from a `SignedBlockHeader`.
fn decode_sig(signed: &SignedBlockHeader, label: &str) -> Result<Signature, SlashingError> {
    let sig_bytes: &[u8; BLS_SIGNATURE_SIZE] =
        signed.signature.as_slice().try_into().map_err(|_| {
            SlashingError::InvalidProposerSlashing(format!(
                "signature {label} has width {}, expected {BLS_SIGNATURE_SIZE}",
                signed.signature.len(),
            ))
        })?;
    Signature::from_bytes(sig_bytes).map_err(|_| {
        SlashingError::InvalidProposerSlashing(format!(
            "signature {label} failed to decode as BLS G2 element",
        ))
    })
}

/// Build the canonical BLS signing message for an L2 block header.
///
/// Traces to [SPEC §5.2 step 6](../../docs/resources/SPEC.md) + §2.10.
///
/// # Wire layout
///
/// ```text
/// DOMAIN_BEACON_PROPOSER    ( 22 bytes, "DIG_BEACON_PROPOSER_V1")
/// network_id                ( 32 bytes)
/// epoch                     (  8 bytes, little-endian u64)
/// header_hash               ( 32 bytes)
/// proposer_index            (  4 bytes, little-endian u32)
/// ```
///
/// Total: 98 bytes. Output: returned as `Vec<u8>` for direct use with
/// `chia_bls::sign` / `chia_bls::verify`.
///
/// # Parity
///
/// SPEC names this function `dig_block::block_signing_message`, but
/// `dig-block = 0.1` does not yet export it — the helper lives here
/// pending upstream landing. The layout is frozen protocol; any future
/// dig-block addition MUST produce byte-identical output.
///
/// Layout mirrors [`crate::AttestationData::signing_root`] (DSL-004):
/// domain-tag || network_id || LE-encoded scalars || 32-byte hash. The
/// endianness + field-ordering choices are the same.
pub fn block_signing_message(
    network_id: &Bytes32,
    epoch: u64,
    header_hash: &Bytes32,
    proposer_index: u32,
) -> Vec<u8> {
    // Domain-tag + network + LE(epoch) + header hash + LE(proposer_idx)
    let mut out = Vec::with_capacity(DOMAIN_BEACON_PROPOSER.len() + 32 + 8 + 32 + 4);
    out.extend_from_slice(DOMAIN_BEACON_PROPOSER);
    out.extend_from_slice(network_id.as_ref());
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(header_hash.as_ref());
    out.extend_from_slice(&proposer_index.to_le_bytes());
    out
}
