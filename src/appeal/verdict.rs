//! Appeal verdict types.
//!
//! Traces to: [SPEC.md §3.9](../../../docs/resources/SPEC.md).
//!
//! # Role
//!
//! Every appeal verifier returns an [`AppealVerdict`]. Sustained →
//! slash reversed (DSL-064..070); Rejected → slash persists,
//! appeal_count increments (DSL-072).

use chia_sha2::Sha256;
use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::pending::AppealOutcome;

/// Reasons an appeal was sustained.
///
/// Mirrors the ground variants — each sustain reason corresponds to
/// a ground being proven true.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AppealSustainReason {
    // ── Proposer ────────────────────────────────────────────────
    /// DSL-034.
    HeadersIdentical,
    /// DSL-035.
    ProposerIndexMismatch,
    /// DSL-036.
    SignatureAInvalid,
    /// DSL-037.
    SignatureBInvalid,
    /// DSL-038.
    SlotMismatch,
    /// DSL-039.
    ValidatorNotActiveAtEpoch,
    // ── Attester ────────────────────────────────────────────────
    /// DSL-041.
    AttestationsIdentical,
    /// DSL-042.
    NotSlashableByPredicate,
    /// DSL-043.
    EmptyIntersection,
    /// DSL-044.
    AttesterSignatureAInvalid,
    /// DSL-045.
    AttesterSignatureBInvalid,
    /// DSL-046.
    InvalidIndexedAttestationStructure,
    /// DSL-047.
    ValidatorNotInIntersection,
    // ── Invalid-block ───────────────────────────────────────────
    /// DSL-049.
    BlockActuallyValid,
    /// DSL-050.
    ProposerSignatureInvalid,
    /// DSL-051.
    FailureReasonMismatch,
    /// DSL-052.
    EvidenceEpochMismatch,
}

/// Reasons an appeal was rejected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AppealRejectReason {
    /// Caller supplied a ground but the predicate does not hold —
    /// the evidence is genuine. Default rejection path for DSL-040,
    /// DSL-048, DSL-054.
    GroundDoesNotHold,
    /// Witness bytes malformed or insufficient.
    MalformedWitness,
    /// Appeal requires an oracle but none was supplied (DSL-053).
    MissingOracle,
}

/// Outcome of a single appeal adjudication.
///
/// Traces to [SPEC §3.9](../../../docs/resources/SPEC.md).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AppealVerdict {
    /// Appeal proves the slash was in error → slash MUST be reverted.
    Sustained {
        /// Categorical reason. Mirrors the appeal ground.
        reason: AppealSustainReason,
    },
    /// Appeal rejected → slash persists; appeal_count increments.
    Rejected {
        /// Categorical reason.
        reason: AppealRejectReason,
    },
}

impl AppealVerdict {
    /// Convert this producer-side verdict into the recorded-side
    /// [`AppealOutcome`] carried on `AppealAttempt` +
    /// `AppealAdjudicationResult`.
    ///
    /// Implements [DSL-171](../../../docs/requirements/domains/appeal/specs/DSL-171.md).
    /// Traces to SPEC §3.8, §6.5.
    ///
    /// # Mapping
    ///
    /// - `Sustained { .. }` → `AppealOutcome::Won`.
    /// - `Rejected { reason }` → `AppealOutcome::Lost { reason_hash }`
    ///   where `reason_hash = SHA-256(bincode::serialize(reason))`.
    ///
    /// The hash is deterministic (bincode canonical encoding + SHA-256)
    /// and domain-agnostic — the enum discriminant contributes via
    /// bincode's variant-tag bytes. Distinct `AppealRejectReason`
    /// variants therefore produce distinct `reason_hash` values,
    /// verified by DSL-171 row 4.
    ///
    /// # Never Pending
    ///
    /// `AppealOutcome::Pending` is a transient state used in
    /// `AppealAttempt::outcome` BEFORE adjudication runs. Since
    /// this conversion is only meaningful after a verdict exists,
    /// the output is always terminal.
    ///
    /// # Panics
    ///
    /// `bincode::serialize` on a closed-enum-of-unit-variants cannot
    /// fail in practice; `.expect` surfaces the invariant rather
    /// than silently coercing.
    #[must_use]
    pub fn to_appeal_outcome(&self) -> AppealOutcome {
        match self {
            AppealVerdict::Sustained { .. } => AppealOutcome::Won,
            AppealVerdict::Rejected { reason } => {
                let mut h = Sha256::new();
                let encoded =
                    bincode::serialize(reason).expect("AppealRejectReason bincode must not fail");
                h.update(&encoded);
                let out: [u8; 32] = h.finalize();
                AppealOutcome::Lost {
                    reason_hash: Bytes32::new(out),
                }
            }
        }
    }
}
