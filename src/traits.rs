//! External-state traits.
//!
//! Traces to: [SPEC.md §15.2](../docs/resources/SPEC.md), catalogue rows
//! [DSL-131..145](../docs/requirements/domains/).
//!
//! # Role
//!
//! The crate does NOT own validator state — it is consumed by external
//! runtimes (node, validator, fork-choice) that do. This module exposes
//! the narrow trait surface the crate reads through.
//!
//! Each trait is defined in the single DSL-NNN that introduces its first
//! consumer, with the blanket / concrete impl landing later under the
//! DSL-131..145 Phase 9 tasks.

use chia_bls::PublicKey;

/// Validator-index → BLS public-key lookup.
///
/// Traces to [SPEC §15.2](../../docs/resources/SPEC.md), catalogue row
/// [DSL-138](../../docs/requirements/domains/).
///
/// # Consumers
///
/// - `IndexedAttestation::verify_signature` (DSL-006) materializes the
///   pubkey set for the aggregate BLS verify by looking up every
///   `attesting_indices[i]`.
/// - `verify_proposer_slashing` / `verify_invalid_block` (DSL-013 /
///   DSL-018) fetch the single proposer pubkey per offense.
///
/// # Return semantics
///
/// `pubkey_of(idx)` returns `None` when `idx` does not correspond to a
/// registered validator — the caller is responsible for translating
/// that to a domain-appropriate error. For BLS verify, a missing
/// pubkey collapses to aggregate-verify failure (DSL-006), which
/// matches the security model: we do not want to distinguish "unknown
/// validator" from "bad signature" at this layer because both are
/// equally invalid evidence.
pub trait PublicKeyLookup {
    /// Look up the BLS G1 public key for `index`. Returns `None` if no
    /// validator is registered at that slot.
    fn pubkey_of(&self, index: u32) -> Option<&PublicKey>;
}
