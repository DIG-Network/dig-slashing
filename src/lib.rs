//! # dig-slashing
//!
//! Validator slashing, attestation participation accounting, inactivity
//! accounting, and fraud-proof appeal system for the DIG Network L2 blockchain.
//!
//! Traces to: [SPEC.md](../docs/resources/SPEC.md) v0.4+.
//!
//! # Scope
//!
//! Validator slashing only. Four discrete offenses (`ProposerEquivocation`,
//! `InvalidBlock`, `AttesterDoubleVote`, `AttesterSurroundVote`). Continuous
//! inactivity accounting (Ethereum Bellatrix parity). Optimistic slashing
//! lifecycle with 8-epoch fraud-proof appeal window.
//!
//! DFSP / storage-provider slashing is **out of scope** — different
//! subsystem, different future crate.
//!
//! # Re-exports
//!
//! The crate root re-exports every public type and constant named in any
//! `DSL-NNN` requirement. Downstream consumers should import from here,
//! not from individual modules, to keep dependency edges clean.
//!
//! # Module layout
//!
//! - [`constants`] — protocol constants (BPS, quotients, domain tags)
//! - [`evidence`] — offense types, evidence envelopes, verifiers
//!
//! (Further modules land as their DSL-NNN requirements are implemented.)

pub mod constants;
pub mod error;
pub mod evidence;
pub mod traits;

// ── Public re-exports (alphabetical within category) ────────────────────────

pub use constants::{
    ATTESTATION_BASE_BPS, BLS_PUBLIC_KEY_SIZE, BLS_SIGNATURE_SIZE, DOMAIN_BEACON_ATTESTER,
    DOMAIN_SLASHING_EVIDENCE, EQUIVOCATION_BASE_BPS, INVALID_BLOCK_BASE_BPS, MAX_PENALTY_BPS,
    MAX_VALIDATORS_PER_COMMITTEE,
};
pub use error::SlashingError;
pub use evidence::{
    AttestationData, AttesterSlashing, Checkpoint, IndexedAttestation, InvalidBlockProof,
    InvalidBlockReason, OffenseType, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload,
};
pub use traits::PublicKeyLookup;
