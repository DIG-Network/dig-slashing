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
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;

use crate::error::SlashingError;
use crate::evidence::invalid_block::InvalidBlockReason;

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

/// Validator-set read+write surface consumed by the verifiers and
/// slashing manager.
///
/// Traces to [SPEC §15.1](../../docs/resources/SPEC.md), catalogue row
/// [DSL-136](../../docs/requirements/domains/).
///
/// # Scope
///
/// `ValidatorView` is the narrow surface `dig-slashing` needs to read
/// (and mutate, on slash/appeal) per-validator state owned by the
/// consensus layer. The full trait surface is defined here so every
/// function signature in this crate can accept `&dyn ValidatorView` /
/// `&mut dyn ValidatorView`; concrete impls land in `dig-consensus`
/// and in test fixtures.
///
/// # Consumer list
///
/// - `verify_evidence` (DSL-011..020) — read-only for precondition
///   checks (registered, active, not-already-slashed).
/// - `SlashingManager::submit_evidence` (DSL-022) — mutating for
///   per-validator debit via `ValidatorEntry::slash_absolute`.
/// - `AppealAdjudicator` (DSL-064..067) — mutating for credit /
///   restore_status on sustained appeals.
pub trait ValidatorView {
    /// Immutable lookup. `None` when `index` is not registered.
    fn get(&self, index: u32) -> Option<&dyn ValidatorEntry>;
    /// Mutable lookup (for slash / credit / restore on adjudication).
    fn get_mut(&mut self, index: u32) -> Option<&mut dyn ValidatorEntry>;
    /// Number of registered validators.
    fn len(&self) -> usize;
    /// Convenience predicate matching `Vec::is_empty` contract.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Per-validator state accessor.
///
/// Traces to [SPEC §15.1](../../docs/resources/SPEC.md), catalogue rows
/// [DSL-131..135](../../docs/requirements/domains/).
///
/// # Invariants (enforced by DSL-131..135 when those impls land)
///
/// - `slash_absolute` saturates at effective-balance floor — cannot
///   drive balance negative.
/// - `credit_stake` returns the amount actually credited after any
///   ceiling clamp.
/// - `restore_status` is idempotent — returns `true` only when status
///   actually changed.
/// - `is_active_at_epoch(epoch)` is inclusive on activation, exclusive
///   on exit (DSL-134 boundary behaviour).
pub trait ValidatorEntry {
    /// Validator's BLS G1 public key. Used by all signature verifiers.
    fn public_key(&self) -> &PublicKey;
    /// Payout puzzle hash for participation rewards / whistleblower
    /// rewards (DSL-025, DSL-141).
    fn puzzle_hash(&self) -> Bytes32;
    /// Current effective balance in mojos. Drives base-penalty math
    /// (DSL-022) and reward/penalty deltas (DSL-081..085).
    fn effective_balance(&self) -> u64;
    /// `true` if this validator has an outstanding slash (pending or
    /// finalised). Gates duplicate slashing (DSL-026).
    fn is_slashed(&self) -> bool;
    /// Epoch the validator became active.
    fn activation_epoch(&self) -> u64;
    /// Epoch the validator scheduled exit at (or u64::MAX if none).
    fn exit_epoch(&self) -> u64;
    /// Activation-inclusive, exit-exclusive membership check at `epoch`.
    fn is_active_at_epoch(&self, epoch: u64) -> bool;
    /// Debit `amount_mojos` from the effective balance (saturating).
    /// Returns the amount actually debited. DSL-131.
    fn slash_absolute(&mut self, amount_mojos: u64, epoch: u64) -> u64;
    /// Undo a prior `slash_absolute` (sustained appeal / reorg).
    /// Returns the amount actually credited. DSL-132.
    fn credit_stake(&mut self, amount_mojos: u64) -> u64;
    /// Clear `Slashed` flag; restore active state. Idempotent. DSL-133.
    /// Returns `true` iff state actually changed.
    fn restore_status(&mut self) -> bool;
    /// Schedule the post-finalisation exit lock. DSL-135.
    fn schedule_exit(&mut self, exit_lock_until_epoch: u64);
}

/// Block re-execution result used by `InvalidBlockOracle`.
///
/// Traces to [SPEC §15.3](../../docs/resources/SPEC.md), catalogue row
/// [DSL-145](../../docs/requirements/domains/).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionOutcome {
    /// Block re-executed successfully — it is NOT invalid.
    Valid,
    /// Block is invalid; variant carries the specific failure reason
    /// so the adjudicator can cross-check against
    /// `InvalidBlockProof::failure_reason` (DSL-051
    /// `FailureReasonMismatch` appeal ground).
    Invalid(InvalidBlockReason),
}

/// Full-node block re-execution hook.
///
/// Traces to [SPEC §15.3](../../docs/resources/SPEC.md), catalogue rows
/// [DSL-020](../../docs/requirements/domains/evidence/specs/DSL-020.md)
/// + [DSL-049](../../docs/requirements/domains/) + [DSL-145].
///
/// # Role
///
/// - `verify_invalid_block` (DSL-020) calls `verify_failure` when the
///   caller supplied an oracle; absence means bootstrap mode (the
///   evidence is admitted and defers to the challenge window).
/// - `InvalidBlockAppeal::BlockActuallyValid` (DSL-049) calls
///   `re_execute` to adjudicate whether the accused block really is
///   invalid.
///
/// # Default `verify_failure`
///
/// The default body is `Ok(())` — bootstrap mode where every
/// well-signed evidence envelope is admitted. Real full-node impls
/// override to re-execute the block and cross-check the claimed
/// failure reason.
///
/// # Determinism
///
/// `re_execute` MUST be deterministic — same inputs → same outcome
/// (DSL-145). Non-determinism here would let the same block flip
/// between "valid" and "invalid" across honest nodes, breaking
/// evidence consensus.
pub trait InvalidBlockOracle {
    /// Verify the caller's claim that `header` is invalid for the
    /// stated `reason`, using `witness` bytes (trie proofs, state
    /// diff, etc.).
    ///
    /// Default: accept — bootstrap path. Full nodes override.
    fn verify_failure(
        &self,
        _header: &L2BlockHeader,
        _witness: &[u8],
        _reason: InvalidBlockReason,
    ) -> Result<(), SlashingError> {
        Ok(())
    }
    /// Re-execute the block deterministically. Returns whether it is
    /// Valid or Invalid (with the specific reason when invalid).
    fn re_execute(
        &self,
        header: &L2BlockHeader,
        witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError>;
}
