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
use crate::evidence::indexed_attestation::IndexedAttestation;
use crate::evidence::invalid_block::InvalidBlockProof;
use crate::evidence::proposer_slashing::ProposerSlashing;
use crate::evidence::verify::block_signing_message;
use crate::traits::{ExecutionOutcome, InvalidBlockOracle, PublicKeyLookup, ValidatorView};

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

/// Verify `AttesterAppealGround::EmptyIntersection`.
///
/// Implements [DSL-043](../../../docs/requirements/domains/appeal/specs/DSL-043.md).
/// Traces to SPEC §6.3.
///
/// # Predicate
///
/// `evidence.slashable_indices().is_empty()` — delegates to DSL-007
/// two-pointer sorted intersection. Sustains when no validator
/// participated in BOTH attestations (non-actionable evidence).
///
/// # Verdict
///
/// - `Sustained { EmptyIntersection }` iff intersection empty.
/// - `Rejected { GroundDoesNotHold }` otherwise.
///
/// Evidence-only; witness ignored.
#[must_use]
pub fn verify_attester_appeal_empty_intersection(evidence: &AttesterSlashing) -> AppealVerdict {
    if evidence.slashable_indices().is_empty() {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::EmptyIntersection,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

/// Verify `AttesterAppealGround::AttesterSignatureAInvalid`.
///
/// Implements [DSL-044](../../../docs/requirements/domains/appeal/specs/DSL-044.md).
/// Traces to SPEC §6.3, §15.2.
///
/// # Predicate
///
/// Re-runs `IndexedAttestation::verify_signature` (DSL-006) over
/// `evidence.attestation_a`. Any failure leg — malformed bytes,
/// bad G2 point, unknown attester index, cryptographic reject —
/// collapses to `Sustained{ AttesterSignatureAInvalid }`. This
/// matches the coarse DSL-006 handling of `BlsVerifyFailed` (SPEC
/// §15.2 does not distinguish "unknown validator" from "bad sig").
///
/// # Verdict
///
/// - `Sustained { AttesterSignatureAInvalid }` iff re-check fails.
/// - `Rejected { GroundDoesNotHold }` iff sig genuinely verifies.
///
/// # Determinism
///
/// `chia_bls::aggregate_verify` is deterministic; the same
/// (sig, pubkey-set, msg) triple always produces the same verdict.
#[must_use]
pub fn verify_attester_appeal_signature_a_invalid(
    evidence: &AttesterSlashing,
    pks: &dyn PublicKeyLookup,
    network_id: &Bytes32,
) -> AppealVerdict {
    verify_attester_appeal_signature_side(
        &evidence.attestation_a,
        pks,
        network_id,
        AppealSustainReason::AttesterSignatureAInvalid,
    )
}

/// Verify `AttesterAppealGround::AttesterSignatureBInvalid`.
///
/// Implements [DSL-045](../../../docs/requirements/domains/appeal/specs/DSL-045.md).
/// Mirror of DSL-044 on `attestation_b` — same shared helper,
/// different sustain reason. Traces to SPEC §6.3, §15.2.
#[must_use]
pub fn verify_attester_appeal_signature_b_invalid(
    evidence: &AttesterSlashing,
    pks: &dyn PublicKeyLookup,
    network_id: &Bytes32,
) -> AppealVerdict {
    verify_attester_appeal_signature_side(
        &evidence.attestation_b,
        pks,
        network_id,
        AppealSustainReason::AttesterSignatureBInvalid,
    )
}

/// Shared helper: re-check one `IndexedAttestation`'s aggregate
/// signature. Returns `Sustained { sustain_reason }` on any
/// verify failure (DSL-006 returns a single coarse `Err`
/// variant), `Rejected { GroundDoesNotHold }` on success.
///
/// Reused by DSL-045 (`AttesterSignatureBInvalid`) — same shape,
/// different side.
fn verify_attester_appeal_signature_side(
    attestation: &IndexedAttestation,
    pks: &dyn PublicKeyLookup,
    network_id: &Bytes32,
    sustain_reason: AppealSustainReason,
) -> AppealVerdict {
    if attestation.verify_signature(pks, network_id).is_err() {
        AppealVerdict::Sustained {
            reason: sustain_reason,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

/// Verify `AttesterAppealGround::InvalidIndexedAttestationStructure`.
///
/// Implements [DSL-046](../../../docs/requirements/domains/appeal/specs/DSL-046.md).
/// Traces to SPEC §6.3.
///
/// # Predicate
///
/// Sustains when `validate_structure()` (DSL-005) fails on either
/// attestation. Covers all five DSL-005 rejection legs:
/// - empty `attesting_indices`
/// - `attesting_indices.len() > MAX_VALIDATORS_PER_COMMITTEE`
/// - `signature.len() != BLS_SIGNATURE_SIZE`
/// - non-ascending indices (`w[0] > w[1]`)
/// - duplicate indices (`w[0] == w[1]`)
///
/// # Verdict
///
/// - `Sustained { InvalidIndexedAttestationStructure }` iff either
///   side fails structural validation.
/// - `Rejected { GroundDoesNotHold }` iff both sides are well-formed.
///
/// # Short-circuit order
///
/// Checks side A first; if A fails, B is not evaluated. Either-side
/// failure is sufficient to sustain, so the short-circuit is
/// verdict-preserving — only cost order matters.
///
/// Evidence-only; witness ignored.
#[must_use]
pub fn verify_attester_appeal_invalid_indexed_attestation_structure(
    evidence: &AttesterSlashing,
) -> AppealVerdict {
    if evidence.attestation_a.validate_structure().is_err()
        || evidence.attestation_b.validate_structure().is_err()
    {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::InvalidIndexedAttestationStructure,
        }
    } else {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    }
}

/// Verify `AttesterAppealGround::ValidatorNotInIntersection { validator_index }`.
///
/// Implements [DSL-047](../../../docs/requirements/domains/appeal/specs/DSL-047.md).
/// Traces to SPEC §6.3.
///
/// # Predicate
///
/// `!evidence.slashable_indices().contains(&validator_index)` —
/// the named validator is NOT in the two-pointer sorted
/// intersection (DSL-007). Used to rescue a falsely-included
/// validator from a buggy verifier admission without touching the
/// other slashed indices.
///
/// # Verdict
///
/// - `Sustained { ValidatorNotInIntersection }` iff the named
///   index is absent from the intersection.
/// - `Rejected { GroundDoesNotHold }` iff present.
///
/// # Per-validator scope
///
/// The verdict references only the index the appellant named. Any
/// other originally-slashed index MUST be appealed independently —
/// the adjudicator (DSL-064) credits back only the named index on
/// a sustain. Callers get this for free because the function is
/// parameterised on `validator_index`, not on the evidence alone.
///
/// Evidence-derived; witness ignored (the `validator_index` comes
/// from the ground variant, not witness bytes).
#[must_use]
pub fn verify_attester_appeal_validator_not_in_intersection(
    evidence: &AttesterSlashing,
    validator_index: u32,
) -> AppealVerdict {
    if evidence.slashable_indices().contains(&validator_index) {
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        }
    } else {
        AppealVerdict::Sustained {
            reason: AppealSustainReason::ValidatorNotInIntersection,
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

/// Verify `InvalidBlockAppealGround::BlockActuallyValid`.
///
/// Implements [DSL-049](../../../docs/requirements/domains/appeal/specs/DSL-049.md).
/// Traces to SPEC §6.4, §15.3.
///
/// # Predicate
///
/// Delegates to [`InvalidBlockOracle::re_execute`] (DSL-145). The
/// oracle re-runs full block validation with the caller-supplied
/// appeal witness (trie proofs, pre-state, parent refs). If
/// re-execution succeeds the original `InvalidBlockProof` was a
/// lie — the slash MUST be reverted.
///
/// # Witness passthrough
///
/// The appeal's own `witness: &[u8]` is passed through to the
/// oracle verbatim — NOT `evidence.failure_witness`. The appellant
/// may supply different replay material than the slasher; the
/// oracle adjudicates based on what the appeal asserts.
///
/// # Verdict
///
/// - `Sustained { BlockActuallyValid }` iff oracle returns
///   `Valid`.
/// - `Rejected { GroundDoesNotHold }` iff oracle returns
///   `Invalid(_)` (oracle disagrees with the appeal's assertion).
/// - `Rejected { MalformedWitness }` iff the oracle returns `Err`
///   (witness bytes did not decode / replay aborted). The
///   appellant failed to produce usable replay material — distinct
///   from "oracle says invalid".
/// - `Rejected { MissingOracle }` iff no oracle was supplied. The
///   appeal requires external state that the slashing crate does
///   not own (SPEC §15.3 bootstrap mode).
#[must_use]
pub fn verify_invalid_block_appeal_block_actually_valid(
    evidence: &InvalidBlockProof,
    appeal_witness: &[u8],
    oracle: Option<&dyn InvalidBlockOracle>,
) -> AppealVerdict {
    let Some(oracle) = oracle else {
        return AppealVerdict::Rejected {
            reason: AppealRejectReason::MissingOracle,
        };
    };
    match oracle.re_execute(&evidence.signed_header.message, appeal_witness) {
        Ok(ExecutionOutcome::Valid) => AppealVerdict::Sustained {
            reason: AppealSustainReason::BlockActuallyValid,
        },
        Ok(ExecutionOutcome::Invalid(_)) => AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
        Err(_) => AppealVerdict::Rejected {
            reason: AppealRejectReason::MalformedWitness,
        },
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
