//! `SlashAppeal` envelope — wraps one of the three appeal payloads
//! plus appellant identity + timing.
//!
//! Traces to: [SPEC.md §3.7](../../../docs/resources/SPEC.md),
//! catalogue row
//! [DSL-159](../../../docs/requirements/domains/appeal/specs/DSL-159.md).
//!
//! # Role
//!
//! Appeals are content-addressed like evidence: the envelope's
//! `hash()` serves as the appeal's unique identity. DSL-159 will
//! land the hash method once adjudication needs it.

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::appeal::ground::{AttesterSlashingAppeal, InvalidBlockAppeal, ProposerSlashingAppeal};

/// Per-payload appeal body.
///
/// Traces to [SPEC §3.7](../../../docs/resources/SPEC.md). Variant
/// MUST match the evidence's payload variant — the DSL-057
/// `VariantMismatch` precondition enforces this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SlashAppealPayload {
    /// Rebuts a `ProposerSlashing` (DSL-034..040).
    Proposer(ProposerSlashingAppeal),
    /// Rebuts an `AttesterSlashing` (DSL-041..048).
    Attester(AttesterSlashingAppeal),
    /// Rebuts an `InvalidBlockProof` (DSL-049..054).
    InvalidBlock(InvalidBlockAppeal),
}

/// Slash-appeal envelope.
///
/// Traces to [SPEC §3.7](../../../docs/resources/SPEC.md). Fields:
///
///   - `evidence_hash` — binds this appeal to a specific
///     `PendingSlash` (DSL-055 UnknownEvidence check).
///   - `appellant_index` — validator index of the appellant;
///     whitehouse-bond lookup key (DSL-062).
///   - `appellant_puzzle_hash` — reward/refund payout address
///     (DSL-067).
///   - `filed_epoch` — epoch the appeal was filed; used for
///     window-expiry checks (DSL-056).
///   - `payload` — the per-ground body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashAppeal {
    /// Evidence hash the appeal targets.
    pub evidence_hash: Bytes32,
    /// Validator index of the appellant.
    pub appellant_index: u32,
    /// Puzzle hash the appellant bond / award is routed to.
    pub appellant_puzzle_hash: Bytes32,
    /// Epoch the appeal was filed.
    pub filed_epoch: u64,
    /// Per-variant body.
    pub payload: SlashAppealPayload,
}
