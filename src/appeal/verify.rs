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

use crate::appeal::ground::ProposerAppealGround;
use crate::appeal::verdict::{AppealRejectReason, AppealSustainReason, AppealVerdict};
use crate::evidence::proposer_slashing::ProposerSlashing;

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

// Compile-time sanity: keep `ProposerAppealGround::HeadersIdentical`
// referenced from the verify module so the variant-to-verifier
// mapping remains visible in cross-references.
#[allow(dead_code)]
const _HEADERS_IDENTICAL_GROUND: ProposerAppealGround = ProposerAppealGround::HeadersIdentical;
