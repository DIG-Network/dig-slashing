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
pub mod offense;

pub use attestation_data::AttestationData;
pub use attester_slashing::AttesterSlashing;
pub use checkpoint::Checkpoint;
pub use indexed_attestation::IndexedAttestation;
pub use offense::OffenseType;
