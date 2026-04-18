//! `SignedBlockHeader` + `ProposerSlashing` — proposer-side evidence types.
//!
//! Traces to: [SPEC.md §3.4](../../docs/resources/SPEC.md), catalogue rows
//! [DSL-009](../../docs/requirements/domains/evidence/specs/DSL-009.md) +
//! [DSL-013](../../docs/requirements/domains/evidence/specs/DSL-013.md).
//!
//! # Role
//!
//! Carries `dig_block::L2BlockHeader` (the canonical L2 block header) +
//! its 96-byte BLS G2 signature. Consumed by:
//!
//! - `ProposerSlashing` (DSL-013) — equivocation requires TWO `SignedBlockHeader`s
//!   at the same slot with matching proposer but different messages.
//! - `InvalidBlockProof` (DSL-018) — invalid-block evidence carries ONE.
//!
//! # Scope
//!
//! Passive wire carrier. This file is `serde` + `PartialEq` only — NO
//! cryptographic verification. Signature-width enforcement, BLS verify,
//! and message re-derivation all live DOWNSTREAM in the verifiers:
//!
//! - `verify_proposer_slashing` (DSL-013) runs `chia_bls::Signature::from_bytes`
//!   which rejects widths != `BLS_SIGNATURE_SIZE`.
//! - `verify_invalid_block` (DSL-018) runs the same check.
//!
//! Keeping the type passive lets construct/serde work uniformly across
//! valid AND structurally-malformed inputs — critical for fuzzers and
//! property-based tests (`proptest`).
//!
//! # Wire layout
//!
//! - `message`: `dig_block::L2BlockHeader` — NOT redefined here. Full
//!   type identity with `dig-block` so cross-crate consumers (validator,
//!   mempool) round-trip the same bytes.
//! - `signature`: `Vec<u8>` annotated `#[serde(with = "serde_bytes")]`.
//!   JSON emits a byte-string (not a 96-element integer array), keeping
//!   REMARK payloads (DSL-102, DSL-110) compact.

use dig_block::L2BlockHeader;
use serde::{Deserialize, Serialize};

/// Block header + BLS signature pair.
///
/// Per [SPEC §3.4](../../docs/resources/SPEC.md). Length of `signature`
/// is NOT enforced here — see module docs for the rationale + the
/// downstream enforcement points.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBlockHeader {
    /// Canonical L2 block header.
    pub message: L2BlockHeader,
    /// BLS G2 signature over `dig_block::block_signing_message(...)`.
    /// MUST be exactly `BLS_SIGNATURE_SIZE` (96) bytes when consumed by
    /// the verifiers (DSL-013, DSL-018).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Proposer-equivocation evidence: two signed headers at the same slot
/// from the same proposer with distinct content.
///
/// Per [SPEC §3.4](../../docs/resources/SPEC.md). Carried as
/// `SlashingEvidencePayload::Proposer` in the envelope (DSL-002 / DSL-010).
///
/// # Scope
///
/// Passive wire carrier. The semantic equivocation predicate —
/// `same_slot && same_proposer && signed_header_a != signed_header_b` —
/// is enforced DOWNSTREAM by `verify_proposer_slashing` (DSL-013). This
/// type will serde-roundtrip ANY pair of `SignedBlockHeader` values,
/// including identical ones, empty signatures, or mismatched proposers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposerSlashing {
    /// First signed header. By convention the one observed first in time,
    /// but the predicate is symmetric so ordering does not affect slash.
    pub signed_header_a: SignedBlockHeader,
    /// Second signed header. MUST differ from `signed_header_a` in at
    /// least one field for the slashing to be valid (DSL-013 rejects
    /// `HeadersIdentical`).
    pub signed_header_b: SignedBlockHeader,
}
