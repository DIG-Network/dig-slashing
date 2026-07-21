//! `AttestationData` — the Ethereum-parity attester vote payload.
//!
//! Traces to: [SPEC.md §3.3](../../docs/resources/SPEC.md), catalogue row
//! [DSL-004](../../docs/requirements/domains/evidence/specs/DSL-004.md).
//!
//! # Role
//!
//! `AttestationData` is the signable payload every attester BLS-signs. It
//! carries:
//!
//! - `slot` + `index` — the committee coordinates.
//! - `beacon_block_root` — the head vote.
//! - `source` + `target` — the FFG vote pair ([`Checkpoint`]).
//!
//! `signing_root(&network_id)` hashes the payload under `DOMAIN_BEACON_ATTESTER`
//! with the network id mixed in; the result is the BLS signing message
//! consumed by `IndexedAttestation::verify_signature` (DSL-006) and by
//! `classify_timeliness` (DSL-075..077) participation tracking.
//!
//! # Determinism + replay resistance
//!
//! - Identical inputs always produce identical output (verified by
//!   `test_dsl_004_signing_root_deterministic`).
//! - The domain tag stops a signature produced here from verifying against
//!   a proposer signing message (which uses a different tag, DSL-050).
//! - The network_id mix stops cross-network replay (testnet → mainnet).
//! - Every field (including both `Checkpoint`s in full) participates in
//!   the hash, so mutation anywhere shifts the output.

use chia_sha2::Sha256;
use dig_peer_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::constants::DOMAIN_BEACON_ATTESTER;
use crate::evidence::checkpoint::Checkpoint;

/// Attester vote payload.
///
/// Per [SPEC §3.3](../../docs/resources/SPEC.md). Field layout is frozen
/// as wire protocol — see [`AttestationData::signing_root`] for the exact
/// byte order used by BLS signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AttestationData {
    /// L2 slot the attestation targets.
    pub slot: u64,
    /// Committee index within the slot.
    pub index: u64,
    /// Head vote: canonical beacon block root at `slot`.
    pub beacon_block_root: Bytes32,
    /// FFG source checkpoint.
    pub source: Checkpoint,
    /// FFG target checkpoint.
    pub target: Checkpoint,
}

impl AttestationData {
    /// Compute the BLS signing root for this attestation.
    ///
    /// Implements [DSL-004](../../docs/requirements/domains/evidence/specs/DSL-004.md).
    /// Traces to SPEC §3.3.
    ///
    /// # Wire layout
    ///
    /// The hasher is fed the following bytes, in order:
    ///
    /// ```text
    /// DOMAIN_BEACON_ATTESTER    (22 bytes, "DIG_BEACON_ATTESTER_V1")
    /// network_id                (32 bytes)
    /// slot                      (8 bytes, little-endian u64)
    /// index                     (8 bytes, little-endian u64)
    /// beacon_block_root         (32 bytes)
    /// source.epoch              (8 bytes, little-endian u64)
    /// source.root               (32 bytes)
    /// target.epoch              (8 bytes, little-endian u64)
    /// target.root               (32 bytes)
    /// ```
    ///
    /// Total input: 182 bytes. Output: 32-byte SHA-256 digest.
    ///
    /// # Invariants
    ///
    /// - **Deterministic:** identical `(self, network_id)` inputs always
    ///   produce bit-identical output.
    /// - **Domain-bound:** prefixed with `DOMAIN_BEACON_ATTESTER`; the tag
    ///   is NOT a separate field of the struct.
    /// - **Network-bound:** `network_id` mixed in after the tag; a
    ///   signing root produced for testnet does NOT verify under mainnet.
    /// - **Field-covering:** every field (including both `Checkpoint`
    ///   components) contributes to the digest; mutating any one shifts
    ///   the output.
    ///
    /// All four invariants are enforced by
    /// `tests/dsl_004_attestation_data_signing_root_test.rs`.
    ///
    /// # Endianness
    ///
    /// All integer fields (`slot`, `index`, `source.epoch`, `target.epoch`)
    /// use little-endian encoding via `u64::to_le_bytes`. Little-endian is
    /// the wire-level standard for DIG / Chia; the test suite guards
    /// against accidental big-endian drift.
    ///
    /// # No custom hashing
    ///
    /// Uses `chia_sha2::Sha256` directly — do NOT introduce a generic
    /// `sha2` crate dep for this codebase (SPEC §5 hard rule, dt-hard-rules
    /// Rule 4).
    pub fn signing_root(&self, network_id: &Bytes32) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(DOMAIN_BEACON_ATTESTER);
        h.update(network_id.as_ref());
        h.update(self.slot.to_le_bytes());
        h.update(self.index.to_le_bytes());
        h.update(self.beacon_block_root.as_ref());
        h.update(self.source.epoch.to_le_bytes());
        h.update(self.source.root.as_ref());
        h.update(self.target.epoch.to_le_bytes());
        h.update(self.target.root.as_ref());
        let out: [u8; 32] = h.finalize();
        Bytes32::new(out)
    }

    /// Whether this attestation forms a slashable pair with `other`.
    ///
    /// The single source of truth for the attester-slashing predicate
    /// (DSL-014 double-vote, DSL-015 surround-vote). Both the evidence
    /// verifier (`verify_attester_slashing`) and the appeal ground
    /// (`verify_attester_appeal_not_slashable_by_predicate`) decide
    /// slashability from HERE. Keeping one definition is load-bearing for
    /// soundness: the appeal is the exact logical inverse of the evidence
    /// check, so a second copy could drift into an unfair slash (evidence
    /// slashes, appeal cannot revert) or an un-slashable one.
    ///
    /// Returns `true` iff EITHER predicate holds:
    /// - **Double vote (DSL-014):** same `target.epoch`, but the two
    ///   attestations are not byte-identical.
    /// - **Surround vote (DSL-015):** one `(source.epoch, target.epoch)`
    ///   window strictly surrounds the other, checked in both directions.
    ///
    /// Symmetric in its two operands:
    /// `a.is_slashable_against(b) == b.is_slashable_against(a)`.
    #[must_use]
    pub(crate) fn is_slashable_against(&self, other: &AttestationData) -> bool {
        let double_vote = self.target.epoch == other.target.epoch && self != other;
        let surround_vote = (self.source.epoch < other.source.epoch
            && self.target.epoch > other.target.epoch)
            || (other.source.epoch < self.source.epoch && other.target.epoch > self.target.epoch);
        double_vote || surround_vote
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::checkpoint::Checkpoint;

    /// Build an `AttestationData` from `(source_epoch, target_epoch)`; the
    /// checkpoint roots vary with the epoch so distinct epochs give
    /// distinct (non-byte-identical) attestations.
    fn att(source_epoch: u64, target_epoch: u64) -> AttestationData {
        AttestationData {
            slot: target_epoch,
            index: 0,
            beacon_block_root: Bytes32::new([0u8; 32]),
            source: Checkpoint {
                epoch: source_epoch,
                root: Bytes32::new([source_epoch as u8; 32]),
            },
            target: Checkpoint {
                epoch: target_epoch,
                root: Bytes32::new([target_epoch as u8; 32]),
            },
        }
    }

    #[test]
    fn double_vote_same_target_different_data_is_slashable() {
        let a = att(1, 5);
        let mut b = att(1, 5);
        b.beacon_block_root = Bytes32::new([9u8; 32]);
        assert!(a.is_slashable_against(&b));
        assert!(b.is_slashable_against(&a));
    }

    #[test]
    fn byte_identical_attestations_are_not_slashable() {
        let a = att(1, 5);
        let b = att(1, 5);
        assert!(!a.is_slashable_against(&b));
    }

    #[test]
    fn surround_vote_is_slashable_both_directions() {
        // a = [1, 6] strictly surrounds b = [2, 5].
        let a = att(1, 6);
        let b = att(2, 5);
        assert!(a.is_slashable_against(&b));
        assert!(b.is_slashable_against(&a));
    }

    #[test]
    fn distinct_non_surrounding_non_double_vote_is_not_slashable() {
        // Disjoint windows, different target epochs, neither surrounds.
        let a = att(1, 2);
        let b = att(3, 4);
        assert!(!a.is_slashable_against(&b));
        assert!(!b.is_slashable_against(&a));
    }

    #[test]
    fn predicate_is_symmetric_across_a_matrix() {
        for sa in 0..4u64 {
            for ta in sa..sa + 4 {
                for sb in 0..4u64 {
                    for tb in sb..sb + 4 {
                        let a = att(sa, ta);
                        let b = att(sb, tb);
                        assert_eq!(
                            a.is_slashable_against(&b),
                            b.is_slashable_against(&a),
                            "asymmetry at a=({sa},{ta}) b=({sb},{tb})"
                        );
                    }
                }
            }
        }
    }
}
