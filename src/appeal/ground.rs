//! Per-variant appeal payloads + ground enums.
//!
//! Traces to: [SPEC.md §3.6](../../../docs/resources/SPEC.md).
//!
//! # Shape
//!
//! Every appeal carries a `ground` (categorical reason the appeal is
//! being filed) and an opaque `witness` byte vec. Grounds are closed
//! enums — `serde_bytes` annotation on witness keeps CBOR/MessagePack
//! encodings compact (DSL-110).

use serde::{Deserialize, Serialize};

/// Grounds on which a `ProposerSlashing` can be appealed.
///
/// Traces to [SPEC §3.6.1](../../../docs/resources/SPEC.md). Each
/// ground mirrors a DSL-013 precondition (`verify_proposer_slashing`)
/// — when an appeal proves one of these holds, the slash must be
/// reverted because the evidence verifier would have rejected the
/// submission had it been working correctly.
///
/// # Variant index
///
/// - `HeadersIdentical` — byte-equal headers (DSL-034).
/// - `ProposerIndexMismatch` — different proposer on the two headers
///   (DSL-035).
/// - `SignatureAInvalid` — sig A fails BLS verify (DSL-036).
/// - `SignatureBInvalid` — sig B fails BLS verify (DSL-037).
/// - `SlotMismatch` — different slots (DSL-038).
/// - `ValidatorNotActiveAtEpoch` — accused inactive at the offense
///   epoch (DSL-039).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposerAppealGround {
    /// The two signed headers are byte-equal (no equivocation).
    HeadersIdentical,
    /// `signed_header_a.message.proposer_index !=
    /// signed_header_b.message.proposer_index`.
    ProposerIndexMismatch,
    /// Signature A fails BLS verify against the canonical signing
    /// message.
    SignatureAInvalid,
    /// Signature B fails BLS verify.
    SignatureBInvalid,
    /// `signed_header_a.message.height != signed_header_b.message.height`.
    SlotMismatch,
    /// Accused validator was not active at `header.epoch`.
    ValidatorNotActiveAtEpoch,
}

/// Proposer-slashing appeal payload.
///
/// Traces to [SPEC §3.6.1](../../../docs/resources/SPEC.md).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposerSlashingAppeal {
    /// Categorical ground for this appeal.
    pub ground: ProposerAppealGround,
    /// Ground-specific witness bytes. Many proposer grounds are
    /// evidence-only (re-derivable from the envelope) — witness is
    /// allowed to be empty. Grounds that require external state
    /// (`ValidatorNotActiveAtEpoch`) carry proof bytes here.
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
}

/// Grounds on which an `AttesterSlashing` can be appealed.
///
/// Traces to [SPEC §3.6.2](../../../docs/resources/SPEC.md). Mirrors
/// DSL-014..017 preconditions + DSL-005 structural check.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttesterAppealGround {
    /// Both attestations are byte-equal (DSL-041).
    AttestationsIdentical,
    /// Neither double-vote nor surround-vote holds (DSL-042).
    NotSlashableByPredicate,
    /// Intersection is empty (DSL-043).
    EmptyIntersection,
    /// Aggregate signature A invalid (DSL-044).
    SignatureAInvalid,
    /// Aggregate signature B invalid (DSL-045).
    SignatureBInvalid,
    /// Structural validation failed (non-ascending indices, cap,
    /// sig-width) — DSL-046.
    InvalidIndexedAttestationStructure,
    /// Named validator not actually in the slashable intersection
    /// (DSL-047).
    ValidatorNotInIntersection {
        /// Index of the validator the appeal argues is not slashable.
        validator_index: u32,
    },
}

/// Attester-slashing appeal payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttesterSlashingAppeal {
    /// Categorical ground for this appeal.
    pub ground: AttesterAppealGround,
    /// Optional witness bytes.
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
}

/// Grounds on which an `InvalidBlockProof` can be appealed.
///
/// Traces to [SPEC §3.6.3](../../../docs/resources/SPEC.md). Mirrors
/// DSL-018..020 preconditions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum InvalidBlockAppealGround {
    /// Block re-executes cleanly per the oracle (DSL-049).
    BlockActuallyValid,
    /// Proposer BLS signature invalid (DSL-050).
    ProposerSignatureInvalid,
    /// `failure_reason` in the evidence disagrees with the oracle's
    /// re-execution outcome (DSL-051).
    FailureReasonMismatch,
    /// `header.epoch != evidence.epoch` (DSL-052).
    EvidenceEpochMismatch,
}

/// Invalid-block appeal payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvalidBlockAppeal {
    /// Categorical ground for this appeal.
    pub ground: InvalidBlockAppealGround,
    /// Witness bytes — `BlockActuallyValid` grounds require full
    /// block body + pre-state for oracle re-execution.
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
}
