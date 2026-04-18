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

pub mod appeal;
pub mod bonds;
pub mod constants;
pub mod error;
pub mod evidence;
pub mod manager;
pub mod pending;
pub mod traits;

// ── Public re-exports (alphabetical within category) ────────────────────────

pub use appeal::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttesterAppealGround,
    AttesterSlashingAppeal, BondSplitResult, ClawbackResult, InvalidBlockAppeal,
    InvalidBlockAppealGround, ProposerAppealGround, ProposerSlashingAppeal, ReporterPenalty,
    SlashAppeal, SlashAppealPayload, adjudicate_sustained_clawback_rewards,
    adjudicate_sustained_forfeit_reporter_bond, adjudicate_sustained_reporter_penalty,
    adjudicate_sustained_restore_status, adjudicate_sustained_revert_base_slash,
    adjudicate_sustained_revert_collateral, verify_attester_appeal_attestations_identical,
    verify_attester_appeal_empty_intersection,
    verify_attester_appeal_invalid_indexed_attestation_structure,
    verify_attester_appeal_not_slashable_by_predicate, verify_attester_appeal_signature_a_invalid,
    verify_attester_appeal_signature_b_invalid,
    verify_attester_appeal_validator_not_in_intersection,
    verify_invalid_block_appeal_block_actually_valid,
    verify_invalid_block_appeal_evidence_epoch_mismatch,
    verify_invalid_block_appeal_failure_reason_mismatch,
    verify_invalid_block_appeal_proposer_signature_invalid,
    verify_proposer_appeal_headers_identical, verify_proposer_appeal_proposer_index_mismatch,
    verify_proposer_appeal_signature_a_invalid, verify_proposer_appeal_signature_b_invalid,
    verify_proposer_appeal_slot_mismatch, verify_proposer_appeal_validator_not_active_at_epoch,
};
pub use bonds::{BondError, BondEscrow, BondTag};
pub use constants::{
    APPELLANT_BOND_MOJOS, ATTESTATION_BASE_BPS, BLS_PUBLIC_KEY_SIZE, BLS_SIGNATURE_SIZE,
    BOND_AWARD_TO_WINNER_BPS, BPS_DENOMINATOR, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_SLASH_APPEAL, DOMAIN_SLASHING_EVIDENCE, EQUIVOCATION_BASE_BPS, INVALID_BLOCK_BASE_BPS,
    MAX_APPEAL_ATTEMPTS_PER_SLASH, MAX_APPEAL_PAYLOAD_BYTES, MAX_PENALTY_BPS, MAX_PENDING_SLASHES,
    MAX_SLASH_PROPOSAL_PAYLOAD_BYTES, MAX_VALIDATORS_PER_COMMITTEE, MIN_EFFECTIVE_BALANCE,
    MIN_SLASHING_PENALTY_QUOTIENT, PROPORTIONAL_SLASHING_MULTIPLIER, PROPOSER_REWARD_QUOTIENT,
    REPORTER_BOND_MOJOS, SLASH_APPEAL_WINDOW_EPOCHS, SLASH_LOCK_EPOCHS,
    WHISTLEBLOWER_REWARD_QUOTIENT,
};
pub use error::SlashingError;
pub use evidence::{
    AttestationData, AttesterSlashing, Checkpoint, IndexedAttestation, InvalidBlockProof,
    InvalidBlockReason, OffenseType, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, VerifiedEvidence, block_signing_message, verify_attester_slashing,
    verify_evidence, verify_evidence_for_inclusion, verify_invalid_block, verify_proposer_slashing,
};
pub use manager::{FinalisationResult, PerValidatorSlash, SlashingManager, SlashingResult};
pub use pending::{
    AppealAttempt, AppealOutcome, PendingSlash, PendingSlashBook, PendingSlashStatus,
};
pub use traits::{
    CollateralSlasher, EffectiveBalanceView, ExecutionOutcome, InvalidBlockOracle, ProposerView,
    PublicKeyLookup, RewardClawback, RewardPayout, ValidatorEntry, ValidatorView,
};

// Re-export the slash-lookback window from `dig-epoch` so downstream
// consumers do not need to pull the dep transitively to compute
// `OffenseTooOld` boundaries for tests or REMARK-admission policy.
// Per SPEC §2.7.
pub use dig_epoch::SLASH_LOOKBACK_EPOCHS;
