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

use chia_bls::Signature;
use dig_protocol::Bytes32;

use crate::constants::{BLS_SIGNATURE_SIZE, DOMAIN_BEACON_PROPOSER};
use crate::error::SlashingError;
use crate::evidence::envelope::{SlashingEvidence, SlashingEvidencePayload};
use crate::evidence::offense::OffenseType;
use crate::evidence::proposer_slashing::{ProposerSlashing, SignedBlockHeader};
use crate::traits::ValidatorView;

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
    match &evidence.payload {
        SlashingEvidencePayload::Proposer(p) => {
            verify_proposer_slashing(evidence, p, validator_view, network_id)
        }
        // Placeholder for DSL-014..020. Not yet soundness-complete.
        SlashingEvidencePayload::Attester(_) | SlashingEvidencePayload::InvalidBlock(_) => {
            Ok(VerifiedEvidence {
                offense_type: evidence.offense_type,
                slashable_validator_indices: slashable,
            })
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
