//! Per-ground appeal verifiers.
//!
//! Traces to: [SPEC.md §6](../../../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-034..054](../../../docs/requirements/domains/appeal/specs/).
//!
//! # Role
//!
//! Each verifier inspects the evidence + (optional) appeal witness
//! and returns an [`AppealVerdict`]. Grounds that re-read existing
//! evidence state ("HeadersIdentical", "SlotMismatch") are pure
//! functions of the envelope. Grounds that require external state
//! (ValidatorNotActiveAtEpoch, BlockActuallyValid) additionally
//! consult a trait handle passed at the dispatcher layer.
//!
//! # Scope (incremental)
//!
//! First commit lands DSL-034 only. Subsequent DSLs add one verifier
//! each; the dispatcher `verify_appeal` lands once enough grounds
//! exist to exercise it.

use chia_bls::Signature;
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;

use crate::appeal::ground::ProposerAppealGround;
use crate::appeal::verdict::{AppealRejectReason, AppealSustainReason, AppealVerdict};
use crate::constants::BLS_SIGNATURE_SIZE;
use crate::evidence::attester_slashing::AttesterSlashing;
use crate::evidence::proposer_slashing::ProposerSlashing;
use crate::evidence::verify::block_signing_message;
use crate::traits::ValidatorView;

/// Verify `ProposerAppealGround::HeadersIdentical`.
///
/// Implements [DSL-034](../../../docs/requirements/domains/appeal/specs/DSL-034.md).
/// Traces to SPEC §6.2.
///
/// # Predicate
///
/// `evidence.signed_header_a.message == evidence.signed_header_b.message`
/// (byte-equal `L2BlockHeader` structs).
///
/// # Verdict
///
/// - `Sustained { HeadersIdentical }` iff headers byte-equal.
/// - `Rejected { GroundDoesNotHold }` otherwise.
///
/// # Scope
///
/// Evidence-only check — the appeal's `witness` bytes are ignored
/// (a byte-equality check over `L2BlockHeader` is self-contained).
/// Other grounds may consume witness bytes for external-state proofs;
/// this one does not.
#[must_use]
pub fn verify_proposer_appeal_headers_identical(evidence: &ProposerSlashing) -> AppealVerdict {
    if evidence.signed_header_a.message == evidence.signed_header_b.message {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::HeadersIdentical,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

/// Verify `ProposerAppealGround::ProposerIndexMismatch`.
///
/// Implements [DSL-035](../../../docs/requirements/domains/appeal/specs/DSL-035.md).
/// Traces to SPEC §6.2.
///
/// # Predicate
///
/// `evidence.signed_header_a.message.proposer_index !=
/// evidence.signed_header_b.message.proposer_index`
///
/// # Verdict
///
/// - `Sustained { ProposerIndexMismatch }` iff the indices differ.
/// - `Rejected { GroundDoesNotHold }` otherwise.
///
/// Evidence-only check; witness ignored.
#[must_use]
pub fn verify_proposer_appeal_proposer_index_mismatch(
    evidence: &ProposerSlashing,
) -> AppealVerdict {
    let a = evidence.signed_header_a.message.proposer_index;
    let b = evidence.signed_header_b.message.proposer_index;
    if a != b {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ProposerIndexMismatch,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

/// Verify `ProposerAppealGround::SignatureAInvalid`.
///
/// Implements [DSL-036](../../../docs/requirements/domains/appeal/specs/DSL-036.md).
/// Traces to SPEC §6.2.
///
/// # Predicate
///
/// Re-runs `chia_bls::verify(sig_a, proposer_pubkey,
/// block_signing_message(...))` against header A. Sustains when the
/// verify returns `false` OR the signature bytes cannot be decoded
/// OR the proposer is not registered.
///
/// # Verdict
///
/// - `Sustained { SignatureAInvalid }` iff re-check fails.
/// - `Rejected { GroundDoesNotHold }` iff signature genuinely verifies.
///
/// # Determinism
///
/// `chia_bls::verify` is deterministic; the same (sig, pk, msg)
/// triple always produces the same verdict.
#[must_use]
pub fn verify_proposer_appeal_signature_a_invalid(
    evidence: &ProposerSlashing,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
) -> AppealVerdict {
    verify_proposer_appeal_signature_side(
        &evidence.signed_header_a.message,
        &evidence.signed_header_a.signature,
        validator_view,
        network_id,
        AppealSustainReason::SignatureAInvalid,
    )
}

/// Verify `ProposerAppealGround::SlotMismatch`.
///
/// Implements [DSL-038](../../../docs/requirements/domains/appeal/specs/DSL-038.md).
/// Traces to SPEC §6.2.
///
/// # Predicate
///
/// `evidence.signed_header_a.message.height !=
/// evidence.signed_header_b.message.height` — the L2 height field
/// serves as the "slot" coordinate for proposer equivocation.
///
/// # Verdict
///
/// - `Sustained { SlotMismatch }` iff heights differ.
/// - `Rejected { GroundDoesNotHold }` otherwise.
///
/// Evidence-only check; witness ignored.
#[must_use]
pub fn verify_proposer_appeal_slot_mismatch(evidence: &ProposerSlashing) -> AppealVerdict {
    let a = evidence.signed_header_a.message.height;
    let b = evidence.signed_header_b.message.height;
    if a != b {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::SlotMismatch,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

/// Verify `ProposerAppealGround::SignatureBInvalid`.
///
/// Implements [DSL-037](../../../docs/requirements/domains/appeal/specs/DSL-037.md).
/// Mirror of DSL-036 on `signed_header_b` — same shared helper,
/// different sustain reason.
#[must_use]
pub fn verify_proposer_appeal_signature_b_invalid(
    evidence: &ProposerSlashing,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
) -> AppealVerdict {
    verify_proposer_appeal_signature_side(
        &evidence.signed_header_b.message,
        &evidence.signed_header_b.signature,
        validator_view,
        network_id,
        AppealSustainReason::SignatureBInvalid,
    )
}

/// Verify `ProposerAppealGround::ValidatorNotActiveAtEpoch`.
///
/// Implements [DSL-039](../../../docs/requirements/domains/appeal/specs/DSL-039.md).
/// Traces to SPEC §6.2 + §15.1.
///
/// # Predicate
///
/// `!validator_view.get(proposer_index)?.is_active_at_epoch(header_a.epoch)`
/// — the accused was outside their active window at the claimed
/// offense epoch, so they could not have been the proposer.
///
/// # Verdict
///
/// - `Sustained { ValidatorNotActiveAtEpoch }` iff inactive at epoch
///   OR the validator is not registered (unknown validator → cannot
///   be active, same coarse handling as DSL-036).
/// - `Rejected { GroundDoesNotHold }` iff active.
///
/// Checks only header A — if both headers share the same
/// `proposer_index` (DSL-013 precondition 2), activation status at
/// header-A's epoch is dispositive. A verifier bug admitting
/// different epochs between A and B is separately catchable under
/// DSL-035 (ProposerIndexMismatch) or DSL-019 (InvalidBlock epoch
/// mismatch).
#[must_use]
pub fn verify_proposer_appeal_validator_not_active_at_epoch(
    evidence: &ProposerSlashing,
    validator_view: &dyn ValidatorView,
) -> AppealVerdict {
    let header = &evidence.signed_header_a.message;
    let sustain = AppealVerdict::Sustained {
        reason: AppealSustainReason::ValidatorNotActiveAtEpoch,
    };
    let Some(entry) = validator_view.get(header.proposer_index) else {
        return sustain;
    };
    if entry.is_active_at_epoch(header.epoch) {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    } else {
        sustain
    }
}

/// Shared helper: re-check one header's BLS signature. Returns
/// `Sustained { sustain_reason }` on verify-failure / decode-failure
/// / missing-pubkey, `Rejected { GroundDoesNotHold }` on successful
/// verify.
///
/// Reused by DSL-037 (`SignatureBInvalid`) — same shape, different
/// side.
fn verify_proposer_appeal_signature_side(
    header: &L2BlockHeader,
    sig_bytes: &[u8],
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
    sustain_reason: AppealSustainReason,
) -> AppealVerdict {
    let sustain = AppealVerdict::Sustained {
        reason: sustain_reason,
    };

    // Decode sig bytes — wrong width or non-curve-point bytes both
    // collapse to sustain (the signature is not a valid BLS G2).
    let Ok(sig_arr) = <&[u8; BLS_SIGNATURE_SIZE]>::try_from(sig_bytes) else {
        return sustain;
    };
    let Ok(sig) = Signature::from_bytes(sig_arr) else {
        return sustain;
    };

    // Look up the proposer's pubkey. Absent validator → sustain: the
    // appeal proves the manager slashed a non-existent/unknown key.
    let Some(entry) = validator_view.get(header.proposer_index) else {
        return sustain;
    };
    let pk = entry.public_key();

    let msg = block_signing_message(
        network_id,
        header.epoch,
        &header.hash(),
        header.proposer_index,
    );
    if chia_bls::verify(&sig, pk, &msg) {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    } else {
        sustain
    }
}

/// Verify `AttesterAppealGround::NotSlashableByPredicate`.
///
/// Implements [DSL-042](../../../docs/requirements/domains/appeal/specs/DSL-042.md).
/// Traces to SPEC §6.3.
///
/// # Predicate
///
/// Mirrors DSL-017 rejection: sustains when NEITHER double-vote
/// nor surround-vote holds on the two `AttestationData`s.
///
/// ```text
/// double_vote ⟺ a.target.epoch == b.target.epoch AND a.data != b.data
/// surround_vote ⟺
///     (a.src < b.src AND a.tgt > b.tgt)
///     OR (b.src < a.src AND b.tgt > a.tgt)
/// sustain ⟺ !(double_vote || surround_vote)
/// ```
///
/// # Verdict
///
/// - `Sustained { NotSlashableByPredicate }` iff neither holds.
/// - `Rejected { GroundDoesNotHold }` otherwise.
///
/// Evidence-only; witness ignored.
#[must_use]
pub fn verify_attester_appeal_not_slashable_by_predicate(
    evidence: &AttesterSlashing,
) -> AppealVerdict {
    let a = &evidence.attestation_a.data;
    let b = &evidence.attestation_b.data;
    let double_vote = a.target.epoch == b.target.epoch && a != b;
    let surround_vote = (a.source.epoch < b.source.epoch && a.target.epoch > b.target.epoch)
        || (b.source.epoch < a.source.epoch && b.target.epoch > a.target.epoch);
    if !(double_vote || surround_vote) {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::NotSlashableByPredicate,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

/// Verify `AttesterAppealGround::AttestationsIdentical`.
///
/// Implements [DSL-041](../../../docs/requirements/domains/appeal/specs/DSL-041.md).
/// Traces to SPEC §6.3.
///
/// # Predicate
///
/// `evidence.attestation_a == evidence.attestation_b` (byte-wise
/// `IndexedAttestation` equality — includes attesting_indices, data,
/// signature).
///
/// # Verdict
///
/// - `Sustained { AttestationsIdentical }` iff byte-equal.
/// - `Rejected { GroundDoesNotHold }` otherwise.
///
/// Evidence-only; witness ignored.
#[must_use]
pub fn verify_attester_appeal_attestations_identical(evidence: &AttesterSlashing) -> AppealVerdict {
    if evidence.attestation_a == evidence.attestation_b {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::AttestationsIdentical,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

// Compile-time sanity: keep `ProposerAppealGround::HeadersIdentical`
// referenced from the verify module so the variant-to-verifier
// mapping remains visible in cross-references.
#[allow(dead_code)]
const _HEADERS_IDENTICAL_GROUND: ProposerAppealGround = ProposerAppealGround::HeadersIdentical;
#[allow(dead_code)]
const _PROPOSER_INDEX_MISMATCH_GROUND: ProposerAppealGround =
    ProposerAppealGround::ProposerIndexMismatch;
#[allow(dead_code)]
const _SIGNATURE_A_INVALID_GROUND: ProposerAppealGround = ProposerAppealGround::SignatureAInvalid;
#[allow(dead_code)]
const _SIGNATURE_B_INVALID_GROUND: ProposerAppealGround = ProposerAppealGround::SignatureBInvalid;
#[allow(dead_code)]
const _SLOT_MISMATCH_GROUND: ProposerAppealGround = ProposerAppealGround::SlotMismatch;
#[allow(dead_code)]
const _VALIDATOR_NOT_ACTIVE_GROUND: ProposerAppealGround =
    ProposerAppealGround::ValidatorNotActiveAtEpoch;
