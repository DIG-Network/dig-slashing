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

use dig_protocol::Bytes32;
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
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingProtection {
    /// Largest slot the validator has proposed at. Guards
    /// proposer-equivocation (DSL-094).
    last_proposed_slot: u64,
    /// `source.epoch` of the validator's last successful
    /// attestation. `0` on a fresh instance. Guards attester
    /// double-vote (DSL-095) + surround-vote (DSL-096).
    last_attested_source_epoch: u64,
    /// `target.epoch` of the validator's last successful
    /// attestation. `0` on a fresh instance.
    last_attested_target_epoch: u64,
    /// Block-root hex (`0x...` lowercase) of the validator's
    /// last successful attestation. `None` when no attestation
    /// has been recorded. Stored as a `String` so persistence
    /// (DSL-101) can round-trip via JSON without binary-blob
    /// plumbing.
    last_attested_block_hash: Option<String>,
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

    /// `source.epoch` of the last recorded attestation.
    #[must_use]
    pub fn last_attested_source_epoch(&self) -> u64 {
        self.last_attested_source_epoch
    }

    /// `target.epoch` of the last recorded attestation.
    #[must_use]
    pub fn last_attested_target_epoch(&self) -> u64 {
        self.last_attested_target_epoch
    }

    /// Lowercase `0x`-prefixed hex of the last recorded
    /// attestation's block hash. `None` when no attestation
    /// has been recorded.
    #[must_use]
    pub fn last_attested_block_hash(&self) -> Option<&str> {
        self.last_attested_block_hash.as_deref()
    }

    /// `true` iff the caller MAY sign an attestation at
    /// `(source_epoch, target_epoch, block_hash)`.
    ///
    /// Implements DSL-095 (same-(src, tgt) different-hash
    /// self-check). DSL-096 (surround-vote self-check) extends
    /// this method in a later commit.
    ///
    /// # DSL-095 rule
    ///
    /// When the candidate FFG coordinates match the stored
    /// last-attested pair EXACTLY, the attestation is allowed
    /// only if the candidate block hash matches the stored
    /// hash (case-insensitive hex compare). This is the
    /// "re-sign the same vote" carve-out — a validator
    /// restarting mid-epoch may re-emit its own attestation,
    /// but may NOT switch to a different block at the same
    /// source/target pair (that would be an
    /// `AttesterDoubleVote`, DSL-014).
    ///
    /// If no prior attestation is stored (`last_attested_*
    /// = 0, None`), the check falls through to the surround
    /// guard (DSL-096 — currently a no-op stub) and returns
    /// `true`.
    #[must_use]
    pub fn check_attestation(
        &self,
        source_epoch: u64,
        target_epoch: u64,
        block_hash: &Bytes32,
    ) -> bool {
        // DSL-096: surround-vote self-check. Runs BEFORE the
        // DSL-095 same-coord check — a surround is slashable
        // regardless of the stored hash, so we short-circuit
        // cheaply. Mirrors the DSL-015 verify-side predicate.
        if self.would_surround(source_epoch, target_epoch) {
            return false;
        }

        // DSL-095: exact (source, target) coordinate collision.
        // The stored hash must be present AND match the
        // candidate case-insensitively; anything else is a
        // potential double-vote.
        if source_epoch == self.last_attested_source_epoch
            && target_epoch == self.last_attested_target_epoch
        {
            let candidate = to_hex_lower(block_hash.as_ref());
            match self.last_attested_block_hash.as_deref() {
                Some(stored) if stored.eq_ignore_ascii_case(&candidate) => {
                    // Re-sign the SAME vote is allowed.
                }
                _ => return false,
            }
        }
        true
    }

    /// Would the candidate attestation surround the stored
    /// one?
    ///
    /// Implements [DSL-096](../docs/requirements/domains/protection/specs/DSL-096.md).
    /// Traces to SPEC §14.2.
    ///
    /// # Predicate
    ///
    /// ```text
    /// candidate_source < self.last_attested_source_epoch
    ///   AND
    /// candidate_target > self.last_attested_target_epoch
    /// ```
    ///
    /// Both strict — a candidate matching either epoch exactly
    /// is NOT a surround (it is either a same-coord case
    /// (DSL-095) or a non-surround flank).
    #[must_use]
    fn would_surround(&self, candidate_source: u64, candidate_target: u64) -> bool {
        candidate_source < self.last_attested_source_epoch
            && candidate_target > self.last_attested_target_epoch
    }

    /// Record a successful attestation. Updates
    /// `last_attested_source_epoch`, `last_attested_target_epoch`
    /// and `last_attested_block_hash`.
    ///
    /// Implements the DSL-095/096 persistence primitive. DSL-097
    /// pins the full contract (including the proposer-side
    /// `record_proposal` companion).
    pub fn record_attestation(
        &mut self,
        source_epoch: u64,
        target_epoch: u64,
        block_hash: &Bytes32,
    ) {
        self.last_attested_source_epoch = source_epoch;
        self.last_attested_target_epoch = target_epoch;
        self.last_attested_block_hash = Some(to_hex_lower(block_hash.as_ref()));
    }

    /// Rewind the proposal watermark on fork-choice reorg.
    ///
    /// Previews [DSL-156](../docs/requirements/domains/protection/specs/DSL-156.md)
    /// — DSL-099 composes this fn alongside [`rewind_attestation_to_epoch`]
    /// (DSL-098) inside [`reconcile_with_chain_tip`]. The DSL-156
    /// dedicated test file lands in Phase 10.
    ///
    /// # Semantics
    ///
    /// Caps `last_proposed_slot` at `new_tip_slot` using strict `>`
    /// so the boundary (stored == tip) is a no-op and already-lower
    /// slots remain untouched. Reconcile must never RAISE a
    /// watermark — doing so would weaken slashing protection.
    ///
    /// No hash-equivalent to clear on the proposal side: DSL-094
    /// only tracks the slot, not a block binding.
    pub fn rewind_proposal_to_slot(&mut self, new_tip_slot: u64) {
        if self.last_proposed_slot > new_tip_slot {
            self.last_proposed_slot = new_tip_slot;
        }
    }

    /// Reconcile local slashing-protection state with the canonical
    /// chain tip on validator startup or after a reorg.
    ///
    /// Implements [DSL-099](../docs/requirements/domains/protection/specs/DSL-099.md).
    /// Traces to SPEC §14.3.
    ///
    /// # Semantics
    ///
    /// Composes [`rewind_proposal_to_slot`] (DSL-156) with
    /// [`rewind_attestation_to_epoch`] (DSL-098) under a single
    /// entry point. Net effect:
    ///
    ///   - `last_proposed_slot` capped at `tip_slot` (never raised).
    ///   - `last_attested_source_epoch` / `last_attested_target_epoch`
    ///     capped at `tip_epoch` (never raised).
    ///   - `last_attested_block_hash` cleared unconditionally —
    ///     the hash binds to a specific block that the reorg
    ///     invalidates.
    ///
    /// Idempotent by construction: both legs are caps, and a second
    /// call with the same `(tip_slot, tip_epoch)` finds the state
    /// already satisfying both caps.
    ///
    /// Called by:
    ///
    ///   - validator boot sequence (rejoin canonical chain after
    ///     downtime),
    ///   - [DSL-130](../../docs/requirements/domains/orchestration/specs/DSL-130.md)
    ///     global-reorg orchestration.
    pub fn reconcile_with_chain_tip(&mut self, tip_slot: u64, tip_epoch: u64) {
        self.rewind_proposal_to_slot(tip_slot);
        self.rewind_attestation_to_epoch(tip_epoch);
    }

    /// Rewind attestation state on fork-choice reorg or chain-tip
    /// refresh.
    ///
    /// Implements [DSL-098](../docs/requirements/domains/protection/specs/DSL-098.md).
    /// Traces to SPEC §14.3.
    ///
    /// # Semantics
    ///
    /// The stored (source, target, hash) triple is the validator's
    /// local memory of "what I already signed." When a reorg drops
    /// the chain back below the attested epochs, that memory is
    /// a ghost watermark — the block the hash points to no longer
    /// exists on the canonical chain. Keeping it would block honest
    /// re-attestation through DSL-095/096.
    ///
    /// Two legs:
    ///
    ///   1. Cap `last_attested_source_epoch` and
    ///      `last_attested_target_epoch` at `new_tip_epoch`. Use
    ///      strict `>` so the boundary case (stored == tip) is a
    ///      no-op — the cap must never RAISE a watermark, only
    ///      lower it.
    ///   2. Clear `last_attested_block_hash` unconditionally. The
    ///      hash binds to a specific block; a reorg invalidates
    ///      that binding regardless of epoch ordering.
    ///
    /// After rewind, a re-attestation on the new canonical tip
    /// passes [`check_attestation`].
    ///
    /// Companion DSL-099 (`reconcile_with_chain_tip`) calls this
    /// alongside the proposal-rewind DSL-156; DSL-130 triggers the
    /// whole bundle on global reorg.
    pub fn rewind_attestation_to_epoch(&mut self, new_tip_epoch: u64) {
        if self.last_attested_source_epoch > new_tip_epoch {
            self.last_attested_source_epoch = new_tip_epoch;
        }
        if self.last_attested_target_epoch > new_tip_epoch {
            self.last_attested_target_epoch = new_tip_epoch;
        }
        self.last_attested_block_hash = None;
    }
}

/// Fixed-size lowercase hex encoder with `0x` prefix. Matches
/// Ethereum JSON convention used by validator-key management
/// tooling — keeps the on-disk format portable across clients.
fn to_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}
