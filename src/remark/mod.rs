//! REMARK wire encoding + on-chain admission helpers.
//!
//! Traces to: [SPEC §16](../docs/resources/SPEC.md).
//!
//! # Role
//!
//! Evidence and appeal payloads travel on-chain inside CLVM
//! `REMARK` conditions. This module owns the serialisation format,
//! the magic prefixes that namespace DIG slashing payloads
//! against foreign REMARK apps sharing the same on-chain
//! namespace, and the parser that the consensus / mempool layer
//! invokes on every block.
//!
//! # Surface
//!
//! Phase 6 REMARK Admission is implemented end to end:
//!
//!   - DSL-102/103: evidence-side wire encoder + parser + puzzle
//!   - DSL-104/105: admission preconditions (coin match / mismatch)
//!   - DSL-106..109: mempool policy (expiry, dupe, caps, payload cap)
//!   - DSL-110..120: appeal-side parity
//!
//! # Submodules
//!
//! - [`evidence_wire`] — evidence encoder + parser + puzzle
//! - [`appeal_wire`] — appeal encoder + parser + puzzle
//! - [`admissions`] — block-level admission processing
//! - [`policy`] — mempool + block-cap admission policy

pub mod admissions;
pub mod appeal_wire;
pub mod evidence_wire;
pub mod policy;

pub use admissions::{BlockAdmissionReport, process_block_admissions};
pub use appeal_wire::{
    encode_slash_appeal_remark_payload_v1, parse_slash_appeals_from_conditions,
    slash_appeal_remark_puzzle_hash_v1, slash_appeal_remark_puzzle_reveal_v1,
};
pub use evidence_wire::{
    encode_slashing_evidence_remark_payload_v1, parse_slashing_evidence_from_conditions,
    slashing_evidence_remark_puzzle_hash_v1, slashing_evidence_remark_puzzle_reveal_v1,
};
pub use policy::{
    enforce_block_level_appeal_caps, enforce_block_level_slashing_caps,
    enforce_slash_appeal_mempool_dedup_policy, enforce_slash_appeal_mempool_policy,
    enforce_slash_appeal_payload_cap, enforce_slash_appeal_remark_admission,
    enforce_slash_appeal_terminal_status_policy, enforce_slash_appeal_variant_policy,
    enforce_slash_appeal_window_policy, enforce_slashing_evidence_mempool_dedup_policy,
    enforce_slashing_evidence_mempool_policy, enforce_slashing_evidence_payload_cap,
    enforce_slashing_evidence_remark_admission,
};
