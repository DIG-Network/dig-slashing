//! Bond-escrow surface: tag enum, error enum, and `BondEscrow` trait.
//!
//! Traces to: [SPEC.md §12.3](../docs/resources/SPEC.md), catalogue rows
//! [DSL-121..126](../docs/requirements/domains/bonds/specs/).
//!
//! # Scope
//!
//! `dig-slashing` does NOT own escrow storage. The escrowed mojos live
//! in `dig-collateral` (or a dedicated bond-escrow crate) that
//! implements [`BondEscrow`]. This module defines the narrow trait
//! surface the slashing manager + appeal adjudicator call through.
//!
//! # Symmetry
//!
//! Reporter and appellant bonds share the same trait + error surface.
//! They are distinguished by the [`BondTag`] variant, which doubles as
//! the unique escrow key — two concurrent bonds on the same principal
//! cannot collide because the envelope/appeal hash is mixed in.

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Bond categorisation + escrow key.
///
/// Traces to [SPEC §12.3](../../docs/resources/SPEC.md).
///
/// # Why the hash is part of the tag
///
/// `BondEscrow` uses the tag as a lookup key — `(principal_idx, tag)`
/// is the uniquifier. Binding the evidence hash (resp. appeal hash)
/// into the tag means the same validator can hold multiple
/// concurrent bonds across independent evidences without collision.
/// DSL-166 verifies `Reporter(h) != Appellant(h)` for any shared `h`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BondTag {
    /// Reporter bond for the referenced `SlashingEvidence::hash()`.
    /// Locked by DSL-023 in `SlashingManager::submit_evidence`.
    Reporter(Bytes32),
    /// Appellant bond for the referenced `SlashAppeal::hash()`.
    /// Locked by DSL-062 in the appeal admission path.
    Appellant(Bytes32),
}

/// Failure modes for `BondEscrow` operations.
///
/// Traces to [SPEC §17.3](../../docs/resources/SPEC.md). The variants
/// are intentionally distinct so the slashing manager can attribute
/// rejections correctly — `InsufficientBalance` → reporter lacks
/// collateral; `DoubleLock` → state machine bug; `TagNotFound` →
/// release/forfeit on an uninitialised tag.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum BondError {
    /// Principal's stake (net of outstanding slashes) is below `need`.
    /// Raised by `lock`; surfaced at DSL-028 as `BondLockFailed`.
    #[error("insufficient balance to lock bond: have {have}, need {need}")]
    InsufficientBalance {
        /// Available stake in mojos.
        have: u64,
        /// Amount requested.
        need: u64,
    },
    /// `release` / `forfeit` called for a tag that was never locked.
    #[error("bond tag {tag:?} not found")]
    TagNotFound {
        /// The offending tag.
        tag: BondTag,
    },
    /// `lock` called for a tag already held — should never happen if
    /// the manager's dedup (DSL-026) runs first.
    #[error("bond tag {tag:?} already locked")]
    DoubleLock {
        /// The already-locked tag.
        tag: BondTag,
    },
}

/// Bond-escrow storage interface consumed by the slashing manager +
/// appeal adjudicator.
///
/// Traces to [SPEC §12.3](../../docs/resources/SPEC.md). Concrete
/// impls live in `dig-collateral` (or equivalent). Every method is
/// `&mut self` except `escrowed` — mutating operations acquire
/// exclusive access to the underlying coin store.
pub trait BondEscrow {
    /// Move `amount` mojos from the principal's free stake into
    /// escrow under `tag`.
    ///
    /// - `Ok(())` on success.
    /// - `Err(BondError::InsufficientBalance { .. })` if the
    ///   principal lacks collateral.
    /// - `Err(BondError::DoubleLock { tag })` if the tag is already
    ///   locked (programmer bug — dedup should prevent this).
    fn lock(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError>;
    /// Release `amount` back to the principal's free stake. Called on
    /// finalisation (DSL-031) or appeal-rejected/sustained unwinds.
    fn release(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError>;
    /// Forfeit `amount` from the escrow. Returns the forfeited mojos
    /// so callers can route to winner-award + burn split (DSL-068,
    /// DSL-071). On a sustained appeal (DSL-068) the forfeited mojos
    /// come from the reporter; on a rejected appeal (DSL-071) they
    /// come from the appellant.
    fn forfeit(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<u64, BondError>;
    /// Currently-escrowed mojos under `(principal_idx, tag)`. `0`
    /// when the tag is not present — read-only.
    fn escrowed(&self, principal_idx: u32, tag: BondTag) -> u64;
}
