//! Evidence-domain types + verification.
//!
//! Traces to: [SPEC.md §3, §5](../../docs/resources/SPEC.md), catalogue rows
//! DSL-001..DSL-021 + DSL-157..DSL-158.
//!
//! This module owns the offense catalogue, evidence envelopes, attestation
//! data model, and per-offense deterministic verifiers. Every public type
//! here is consumed by the lifecycle, appeal, and REMARK modules but does
//! NOT depend on them (one-way edge).

pub mod attestation_data;
pub mod attester_slashing;
pub mod checkpoint;
pub mod indexed_attestation;
pub mod invalid_block;
pub mod offense;
pub mod proposer_slashing;

pub use attestation_data::AttestationData;
pub use attester_slashing::AttesterSlashing;
pub use checkpoint::Checkpoint;
pub use indexed_attestation::IndexedAttestation;
pub use invalid_block::{InvalidBlockProof, InvalidBlockReason};
pub use offense::OffenseType;
pub use proposer_slashing::SignedBlockHeader;
