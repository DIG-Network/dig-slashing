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
pub mod manager;
pub mod traits;

// ── Public re-exports (alphabetical within category) ────────────────────────

pub use constants::{
    ATTESTATION_BASE_BPS, BLS_PUBLIC_KEY_SIZE, BLS_SIGNATURE_SIZE, BPS_DENOMINATOR,
    DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_SLASHING_EVIDENCE,
    EQUIVOCATION_BASE_BPS, INVALID_BLOCK_BASE_BPS, MAX_PENALTY_BPS,
    MAX_SLASH_PROPOSAL_PAYLOAD_BYTES, MAX_VALIDATORS_PER_COMMITTEE, MIN_SLASHING_PENALTY_QUOTIENT,
};
pub use error::SlashingError;
pub use evidence::{
    AttestationData, AttesterSlashing, Checkpoint, IndexedAttestation, InvalidBlockProof,
    InvalidBlockReason, OffenseType, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, VerifiedEvidence, block_signing_message, verify_attester_slashing,
    verify_evidence, verify_evidence_for_inclusion, verify_invalid_block, verify_proposer_slashing,
};
pub use manager::{PerValidatorSlash, SlashingManager, SlashingResult};
pub use traits::{
    EffectiveBalanceView, ExecutionOutcome, InvalidBlockOracle, PublicKeyLookup, ValidatorEntry,
    ValidatorView,
};

// Re-export the slash-lookback window from `dig-epoch` so downstream
// consumers do not need to pull the dep transitively to compute
// `OffenseTooOld` boundaries for tests or REMARK-admission policy.
// Per SPEC §2.7.
pub use dig_epoch::SLASH_LOOKBACK_EPOCHS;
