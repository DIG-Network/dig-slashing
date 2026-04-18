//! `InvalidBlockProof` — per-offense payload for `OffenseType::InvalidBlock`.
//!
//! Traces to: [SPEC.md §3.4](../../docs/resources/SPEC.md), catalogue row
//! [DSL-008](../../docs/requirements/domains/evidence/specs/DSL-008.md).
//!
//! # Role
//!
//! Carries everything needed to prove a proposer signed a block that
//! fails canonical validation:
//!
//! - [`SignedBlockHeader`](super::proposer_slashing::SignedBlockHeader)
//!   — the block header + BLS signature (DSL-009).
//! - `failure_witness` — caller-supplied bytes that the
//!   [`InvalidBlockOracle`](../../traits.rs) (DSL-020) replays to
//!   reproduce the validation failure. Size depends on the failure
//!   reason; `serde_bytes` keeps the binary-format encoding compact.
//! - [`InvalidBlockReason`] — categorical tag. Eight variants covering
//!   the distinct canonical-validation failure modes.
//!
//! # Downstream
//!
//! - `verify_invalid_block` (DSL-018..020) consumes all three fields.
//! - Appeal ground `InvalidBlockAppealGround::FailureReasonMismatch`
//!   (DSL-051) checks oracle-reported reason against the claimed
//!   `failure_reason`.

use serde::{Deserialize, Serialize};

use crate::evidence::proposer_slashing::SignedBlockHeader;

/// Canonical reason categories for `InvalidBlockProof::failure_reason`.
///
/// Per [SPEC §3.4](../../docs/resources/SPEC.md). Adding a new variant
/// is a protocol-version bump — downstream pattern-matches assume
/// exhaustive coverage of exactly these eight cases (see
/// `test_dsl_008_all_reasons_enumerated`).
///
/// The enum is `Copy` + `Hash` because it's a lightweight discriminant
/// that shows up in `AppealAdjudicationResult`, oracle return values,
/// and metrics labels — passing by value is cheap and avoids `.clone()`
/// noise in consumers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum InvalidBlockReason {
    /// Post-block state root doesn't match the re-executed state.
    BadStateRoot,
    /// Header's parent hash doesn't match the canonical parent.
    BadParentRoot,
    /// Timestamp outside allowed window (future or past canonical tip).
    BadTimestamp,
    /// `proposer_index` doesn't match the slot's assigned proposer.
    BadProposerIndex,
    /// One or more transactions failed during block execution.
    TransactionExecutionFailure,
    /// Block exceeds `MAX_BLOCK_COST` or analogous resource cap.
    OverweightBlock,
    /// Block contains the same spend bundle twice.
    DuplicateTransaction,
    /// Reason not otherwise categorised; witness should carry detail.
    Other,
}

/// Evidence that a proposer signed an invalid block.
///
/// Per [SPEC §3.4](../../docs/resources/SPEC.md). Passive wire carrier:
/// no validation happens at construction, only at
/// `verify_invalid_block` (DSL-018..020).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvalidBlockProof {
    /// The offending signed block header.
    pub signed_header: SignedBlockHeader,
    /// Caller-supplied replay material for the `InvalidBlockOracle`.
    /// Shape depends on `failure_reason`; the verifier is responsible
    /// for interpreting the bytes against the oracle.
    #[serde(with = "serde_bytes")]
    pub failure_witness: Vec<u8>,
    /// Categorical classification of the failure.
    pub failure_reason: InvalidBlockReason,
}
