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
//! # Scope (incremental)
//!
//! Opens Phase 6 REMARK Admission. Module grows one DSL at a
//! time. First commit lands DSL-102 — the evidence-side wire
//! encoder + parser. Future DSLs extend this surface:
//!
//!   - DSL-103: `slashing_evidence_remark_puzzle_reveal_v1`
//!   - DSL-104/105: admission preconditions (coin match / mismatch)
//!   - DSL-106..108: mempool policy (expiry, dupe, caps)
//!   - DSL-109: payload cap
//!   - DSL-110..120: full appeal-side parity
//!
//! # Submodules
//!
//! - [`evidence_wire`] — DSL-102 evidence encoder + parser
//!
//! Further submodules (`evidence_puzzle`, `appeal_wire`,
//! `appeal_puzzle`, `admission`, `policy`) land with their
//! DSL-NNN requirements.

pub mod evidence_wire;
pub mod policy;

pub use evidence_wire::{
    encode_slashing_evidence_remark_payload_v1, parse_slashing_evidence_from_conditions,
    slashing_evidence_remark_puzzle_hash_v1, slashing_evidence_remark_puzzle_reveal_v1,
};
pub use policy::{
    enforce_slashing_evidence_mempool_policy, enforce_slashing_evidence_remark_admission,
};
