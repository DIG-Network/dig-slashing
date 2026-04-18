//! Appeal-domain types + verifiers.
//!
//! Traces to: [SPEC.md §3.6 + §6](../../docs/resources/SPEC.md),
//! catalogue rows [DSL-034..073 + DSL-159..164](../../docs/requirements/domains/appeal/specs/).
//!
//! # Role
//!
//! Optimistic slashing is reversible during the 8-epoch appeal window.
//! This module owns the three appeal payload shapes
//! ([`ProposerSlashingAppeal`], [`AttesterSlashingAppeal`],
//! [`InvalidBlockAppeal`]), the [`SlashAppeal`] envelope, and the
//! per-ground verifiers that produce an [`AppealVerdict`].
//!
//! # Scope (incremental)
//!
//! Module grows one DSL at a time. First commit lands DSL-034
//! (ProposerAppeal HeadersIdentical). Sibling grounds + the
//! dispatcher + adjudicator come in subsequent commits.

pub mod envelope;
pub mod ground;
pub mod verdict;
pub mod verify;

pub use envelope::{SlashAppeal, SlashAppealPayload};
pub use ground::{
    AttesterAppealGround, AttesterSlashingAppeal, InvalidBlockAppeal, InvalidBlockAppealGround,
    ProposerAppealGround, ProposerSlashingAppeal,
};
pub use verdict::{AppealRejectReason, AppealSustainReason, AppealVerdict};
pub use verify::{
    verify_attester_appeal_attestations_identical, verify_attester_appeal_empty_intersection,
    verify_attester_appeal_invalid_indexed_attestation_structure,
    verify_attester_appeal_not_slashable_by_predicate, verify_attester_appeal_signature_a_invalid,
    verify_attester_appeal_signature_b_invalid,
    verify_attester_appeal_validator_not_in_intersection,
    verify_invalid_block_appeal_block_actually_valid, verify_proposer_appeal_headers_identical,
    verify_proposer_appeal_proposer_index_mismatch, verify_proposer_appeal_signature_a_invalid,
    verify_proposer_appeal_signature_b_invalid, verify_proposer_appeal_slot_mismatch,
    verify_proposer_appeal_validator_not_active_at_epoch,
};
