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
use dig_protocol::Bytes32;
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
}
