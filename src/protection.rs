//! Self-slashing protection for a single validator.
//!
//! Traces to: [SPEC §14](../docs/resources/SPEC.md), catalogue
//! rows
//! [DSL-094..101](../docs/requirements/domains/protection/specs/).
//!
//! # Role
//!
//! `SlashingProtection` is a per-validator local-state struct
//! that prevents a running validator from signing two
//! messages that would slash itself on restart / fork-choice
//! change. Lives on the validator's machine, not the chain —
//! purely advisory at the network level, but load-bearing at
//! the single-validator level.
//!
//! # Scope (incremental)
//!
//! Module grows one DSL at a time. First commit lands DSL-094
//! (proposal-slot monotonic check). Future DSLs add:
//!
//!   - DSL-095: attestation same-(src,tgt) different-hash check
//!   - DSL-096: would-surround self-check
//!   - DSL-097: `record_proposal` + `record_attestation`
//!     persistence
//!   - DSL-098: `rewind_attestation_to_epoch`
//!   - DSL-099/100/101: reorg, bootstrap, persistence details

use serde::{Deserialize, Serialize};

/// Per-validator local slashing-protection state.
///
/// Implements [DSL-094](../docs/requirements/domains/protection/specs/DSL-094.md)
/// (+ DSL-095/096/097 in later commits). Traces to SPEC §14.
///
/// # Fields
///
/// - `last_proposed_slot` — largest slot the validator has
///   proposed at. `check_proposal_slot` requires a strictly
///   greater slot before signing a new proposal.
///
/// Future DSLs add `last_source_epoch`, `last_target_epoch`,
/// `attested_hash_by_target` and similar fields as their
/// guards come online.
///
/// # Default
///
/// `Default::default()` → `last_proposed_slot = 0`. Any slot
/// `> 0` passes `check_proposal_slot` on a fresh instance.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SlashingProtection {
    last_proposed_slot: u64,
}

impl SlashingProtection {
    /// Construct with `last_proposed_slot = 0`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Last slot at which the validator proposed. Used for
    /// introspection + persistence round-trips.
    #[must_use]
    pub fn last_proposed_slot(&self) -> u64 {
        self.last_proposed_slot
    }

    /// `true` iff the caller MAY sign a new proposal at `slot`.
    ///
    /// Implements [DSL-094](../docs/requirements/domains/protection/specs/DSL-094.md).
    ///
    /// # Predicate
    ///
    /// `slot > self.last_proposed_slot` — strict greater-than
    /// so the same slot cannot be signed twice (that would be
    /// the canonical proposer-equivocation offense).
    ///
    /// Fresh validators have `last_proposed_slot = 0`, so any
    /// slot `> 0` is safe to sign.
    #[must_use]
    pub fn check_proposal_slot(&self, slot: u64) -> bool {
        slot > self.last_proposed_slot
    }

    /// Record a successful proposal at `slot`. Subsequent
    /// `check_proposal_slot(s)` calls with `s <= slot` will
    /// return `false`.
    ///
    /// Implements [DSL-094](../docs/requirements/domains/protection/specs/DSL-094.md).
    /// Persistence semantics land in DSL-097.
    pub fn record_proposal(&mut self, slot: u64) {
        self.last_proposed_slot = slot;
    }
}
