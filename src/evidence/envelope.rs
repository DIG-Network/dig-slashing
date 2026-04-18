//! `SlashingEvidence` — outer wrapper that carries offense classification,
//! reporter identity, epoch, and the per-offense payload.
//!
//! Traces to: [SPEC.md §3.5](../../docs/resources/SPEC.md), catalogue rows
//! [DSL-002](../../docs/requirements/domains/evidence/specs/DSL-002.md) +
//! [DSL-010](../../docs/requirements/domains/evidence/specs/DSL-010.md) +
//! [DSL-157](../../docs/requirements/domains/evidence/specs/DSL-157.md).
//!
//! # Role
//!
//! Everything the lifecycle needs to ingest an offense report flows
//! through this envelope:
//!
//!   - `offense_type` — tags the slash for base-penalty lookup
//!     (DSL-001) and REMARK magic dispatch (DSL-102).
//!   - `reporter_validator_index` + `reporter_puzzle_hash` — reward
//!     routing (DSL-025) and self-accuse short-circuit (DSL-012).
//!   - `epoch` — drives `OffenseTooOld` check (DSL-011) and bond-escrow
//!     lifetime.
//!   - `payload` — the variant-specific fraud proof bytes that verifiers
//!     re-execute (DSL-013 / DSL-014..017 / DSL-018..020).
//!
//! # Content-addressed identity
//!
//! [`SlashingEvidence::hash`] (DSL-002) is the primary key for two
//! runtime structures:
//!
//!   - `SlashingManager::processed` — dedup map keyed by envelope hash
//!     (DSL-026 AlreadySlashed short-circuit).
//!   - `BondEscrow::Reporter(hash)` — bond tag binding the reporter's
//!     escrowed bond to the exact envelope they submitted (DSL-023).
//!
//! Both structures require bit-exact determinism AND total field coverage:
//! mutating any byte of the envelope MUST shift the hash, else a reporter
//! could submit a mutated envelope under a colliding key and double-spend
//! either the dedup slot or the bond.
//!
//! The digest is `SHA-256(DOMAIN_SLASHING_EVIDENCE || bincode(self))`
//! using `chia_sha2::Sha256` (same hasher as attester signing roots, so
//! one crypto stack for the whole crate).
//!
//! # Per-validator fan-out
//!
//! [`SlashingEvidence::slashable_validators`] (DSL-010) returns the list
//! of validator indices the evidence accuses. Proposer / InvalidBlock
//! always return `[proposer_index]` (cardinality 1); Attester returns
//! the sorted `slashable_indices()` intersection (cardinality 0..=N,
//! DSL-007).

use chia_sha2::Sha256;
use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::constants::DOMAIN_SLASHING_EVIDENCE;
use crate::evidence::attester_slashing::AttesterSlashing;
use crate::evidence::invalid_block::InvalidBlockProof;
use crate::evidence::offense::OffenseType;
use crate::evidence::proposer_slashing::ProposerSlashing;

/// Per-offense fraud-proof payload.
///
/// One variant per `OffenseType`, but note that `AttesterDoubleVote` and
/// `AttesterSurroundVote` share the `Attester` variant: the two predicates
/// are distinguished by `verify_attester_slashing` (DSL-014 / DSL-015),
/// not by a payload tag.
///
/// Per [SPEC §3.5](../../docs/resources/SPEC.md).
///
/// # Enum size
///
/// The variants are deliberately asymmetric — `ProposerSlashing` carries
/// two full `L2BlockHeader`s (~1.5 KB), `Attester` carries two indexed
/// attestation index-lists (up to 2_048 × 4 bytes each), `InvalidBlock`
/// carries one header plus witness bytes. We accept the variance because
/// this enum is itself heap-resident inside `SlashingEvidence` and is
/// never used in tight loops — boxing would just add indirection to every
/// `hash()`/`bincode` path without changing the on-wire bytes or the
/// size of the enclosing `SlashingEvidence`. The wire format is what
/// matters, not the in-memory layout of a type that only ever lives one
/// per reporter-submission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum SlashingEvidencePayload {
    /// Equivocation: two distinct signed headers at the same slot from
    /// the same proposer (DSL-013).
    Proposer(ProposerSlashing),
    /// Double-vote or surround-vote: two IndexedAttestations whose
    /// slashable-indices intersection is non-empty and whose
    /// `AttestationData` pair satisfies either predicate
    /// (DSL-014 / DSL-015).
    Attester(AttesterSlashing),
    /// Canonical-validation failure: proposer signed a block that fails
    /// re-execution (DSL-018 / DSL-019 / DSL-020).
    InvalidBlock(InvalidBlockProof),
}

/// Slashing-evidence envelope.
///
/// Per [SPEC §3.5](../../docs/resources/SPEC.md). Fields are frozen wire
/// protocol; their order matters for the deterministic bincode serialization
/// consumed by [`SlashingEvidence::hash`] — do NOT reorder without bumping
/// the protocol version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    /// Classification of the offense. Drives base-penalty lookup
    /// (DSL-001) and REMARK dispatch (DSL-102).
    pub offense_type: OffenseType,
    /// Validator index of the reporter. Receives the whistleblower
    /// reward (DSL-025). MUST NOT appear in `slashable_validators`
    /// (DSL-012 self-accuse check).
    pub reporter_validator_index: u32,
    /// Puzzle hash the whistleblower reward is paid to (DSL-025).
    /// Bound into the hash so a malicious reporter cannot swap payout
    /// addresses after the evidence is admitted.
    pub reporter_puzzle_hash: Bytes32,
    /// Epoch at which the offense occurred. Used by DSL-011
    /// (`OffenseTooOld` lookback check).
    pub epoch: u64,
    /// The per-offense payload carrying the fraud-proof bytes.
    pub payload: SlashingEvidencePayload,
}

impl SlashingEvidence {
    /// Content-addressed identity of the envelope.
    ///
    /// Implements [DSL-002](../../docs/requirements/domains/evidence/specs/DSL-002.md).
    /// Traces to SPEC §3.5.
    ///
    /// # Construction
    ///
    /// ```text
    /// hash = SHA-256(
    ///   DOMAIN_SLASHING_EVIDENCE          (24 bytes, "DIG_SLASHING_EVIDENCE_V1")
    ///   || bincode::serialize(self)       (variable, full envelope encoding)
    /// )
    /// ```
    ///
    /// Hasher: `chia_sha2::Sha256` (matches attester signing root, DSL-004).
    ///
    /// # Invariants (all enforced by the DSL-002 test suite)
    ///
    /// - **Deterministic:** identical envelopes always produce identical
    ///   digests, across runs and processes.
    /// - **Domain-bound:** `DOMAIN_SLASHING_EVIDENCE` is mixed in as the
    ///   first input, so the digest cannot collide with any other
    ///   protocol hash.
    /// - **Field-covering:** every byte of every field (including the
    ///   payload enum discriminant + inner variant bytes) participates;
    ///   mutating any one shifts the digest.
    ///
    /// # Why bincode
    ///
    /// bincode produces a compact, deterministic encoding with explicit
    /// length prefixes on variable-length fields. `serde_json` would be
    /// non-canonical (field-order flexibility, whitespace). Serialization
    /// failure is treated as unreachable — `SlashingEvidence` contains no
    /// types bincode cannot encode, so `.expect` is the honest signal on
    /// a programmer bug rather than a runtime `Result` every caller must
    /// thread.
    pub fn hash(&self) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(DOMAIN_SLASHING_EVIDENCE);
        let encoded = bincode::serialize(self).expect("SlashingEvidence bincode must not fail");
        h.update(&encoded);
        let out: [u8; 32] = h.finalize();
        Bytes32::new(out)
    }

    /// List of validator indices this envelope accuses.
    ///
    /// Implements [DSL-010](../../docs/requirements/domains/evidence/specs/DSL-010.md).
    /// Traces to SPEC §3.5.
    ///
    /// # Returns
    ///
    /// - `Proposer` / `InvalidBlock` → exactly one index (the
    ///   `proposer_index` from the signed header).
    /// - `Attester` → sorted, deduplicated intersection of the two
    ///   indexed-attestation index lists (DSL-007). Cardinality 0..=N.
    ///
    /// Consumed by `verify_evidence` (DSL-012 reporter-self-accuse) and
    /// `SlashingManager::submit_evidence` per-validator loop (DSL-022).
    pub fn slashable_validators(&self) -> Vec<u32> {
        match &self.payload {
            SlashingEvidencePayload::Proposer(p) => {
                vec![p.signed_header_a.message.proposer_index]
            }
            SlashingEvidencePayload::Attester(a) => a.slashable_indices(),
            SlashingEvidencePayload::InvalidBlock(i) => {
                vec![i.signed_header.message.proposer_index]
            }
        }
    }
}
