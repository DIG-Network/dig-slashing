//! Requirement DSL-118: mempool-level dedup across
//! `pending_appeals` and `incoming_appeals`. Byte-identical JSON
//! fingerprint in either direction → `SlashingError::DuplicateAppeal`.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Appeal-side analogue of DSL-107. Upstream of DSL-058 manager
//! dedup (which operates on bincode appeal hash inside
//! `PendingSlash::appeal_history`). Prevents appellant spam at the
//! mempool boundary before any bond-lock / BLS work.
//!
//! # Test matrix (maps to DSL-118 Test Plan + acceptance)
//!
//!   1. `test_dsl_118_pending_duplicate_rejected` — same appeal
//!      in pending + incoming
//!   2. `test_dsl_118_incoming_duplicate_rejected` — same appeal
//!      twice in incoming
//!   3. `test_dsl_118_distinct_ok` — all distinct admits
//!   4. `test_dsl_118_empty_inputs_ok` — vacuous

use dig_protocol::Bytes32;
use dig_slashing::{
    ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal, SlashAppealPayload, SlashingError,
    enforce_slash_appeal_mempool_dedup_policy,
};

fn appeal(appellant_idx: u32, evidence_hash_byte: u8) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: Bytes32::new([evidence_hash_byte; 32]),
        appellant_index: appellant_idx,
        appellant_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

#[test]
fn test_dsl_118_pending_duplicate_rejected() {
    let ap = appeal(11, 0x11);
    let pending = vec![ap.clone()];
    let incoming = vec![ap];
    let err = enforce_slash_appeal_mempool_dedup_policy(&pending, &incoming)
        .expect_err("pending-incoming collision rejects");
    assert!(matches!(err, SlashingError::DuplicateAppeal));
}

#[test]
fn test_dsl_118_incoming_duplicate_rejected() {
    let ap = appeal(11, 0x11);
    let pending: Vec<SlashAppeal> = Vec::new();
    let incoming = vec![ap.clone(), ap];
    let err = enforce_slash_appeal_mempool_dedup_policy(&pending, &incoming)
        .expect_err("in-batch collision rejects");
    assert!(matches!(err, SlashingError::DuplicateAppeal));
}

#[test]
fn test_dsl_118_distinct_ok() {
    // Varying both appellant_index AND evidence_hash — fingerprints
    // differ in multiple fields, so no false-positives on partial
    // overlap.
    let pending = vec![appeal(11, 0x11), appeal(12, 0x22)];
    let incoming = vec![appeal(13, 0x33), appeal(14, 0x44)];
    enforce_slash_appeal_mempool_dedup_policy(&pending, &incoming).expect("fully distinct admits");

    // In-incoming distinct.
    let pending: Vec<SlashAppeal> = Vec::new();
    let incoming = vec![appeal(11, 0x11), appeal(11, 0x22)];
    enforce_slash_appeal_mempool_dedup_policy(&pending, &incoming)
        .expect("same appellant different evidence_hash admits");
}

#[test]
fn test_dsl_118_empty_inputs_ok() {
    let pending: Vec<SlashAppeal> = Vec::new();
    let incoming: Vec<SlashAppeal> = Vec::new();
    enforce_slash_appeal_mempool_dedup_policy(&pending, &incoming).expect("empty admits");
}
