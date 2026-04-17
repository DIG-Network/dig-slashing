//! `Checkpoint` — the FFG `(epoch, root)` vote pair.
//!
//! Traces to: [SPEC.md §3.3](../../docs/resources/SPEC.md), catalogue row
//! [DSL-003](../../docs/requirements/domains/evidence/specs/DSL-003.md).
//!
//! # Role
//!
//! A `Checkpoint` pins a vote to a specific epoch and to a specific beacon
//! block root at that epoch. Consumed by:
//!
//! - [`AttestationData::source`](super::attestation_data::AttestationData) —
//!   the justified checkpoint the attester is voting from (DSL-004).
//! - [`AttestationData::target`](super::attestation_data::AttestationData) —
//!   the checkpoint the attester is voting for (DSL-004).
//! - [`JustificationView`] trait (DSL-143) — the
//!   `current_justified_checkpoint` / `previous_justified_checkpoint` /
//!   `finalized_checkpoint` accessors.
//!
//! # Determinism + leafness
//!
//! `Checkpoint` has no nested types beyond the 32-byte root. Every derive
//! (`Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash`) is
//! defaulted. The type is `Copy` so it can be passed by value across every
//! downstream API without lifetime or borrow friction.

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

/// A `(epoch, root)` FFG vote pair.
///
/// Per [SPEC §3.3](../../docs/resources/SPEC.md), `Checkpoint` is the
/// primitive finality-gadget vote: the attester's source and target votes
/// both carry an epoch number and a beacon block root that pins the vote
/// to a specific history.
///
/// # Fields
///
/// - `epoch` — the L2 epoch number of the vote.
/// - `root` — the canonical beacon block root at the end of that epoch's
///   canonical chain (the target-root for target votes; the last-justified
///   root for source votes).
///
/// # Equality + hashing
///
/// `Checkpoint`s are `PartialEq` iff both `epoch` and `root` match; `Hash`
/// output is consistent with `Eq` per the Rust stdlib contract. This enables
/// use as a `HashMap`/`HashSet` key in consumer crates (e.g. a
/// justification-graph crate).
///
/// # Serde
///
/// Both `bincode` and `serde_json` round-trip byte-exactly; see
/// `tests/dsl_003_checkpoint_roundtrip_test.rs` for the full suite.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Checkpoint {
    /// L2 epoch number of the vote.
    pub epoch: u64,
    /// Canonical beacon block root at this checkpoint.
    pub root: Bytes32,
}
