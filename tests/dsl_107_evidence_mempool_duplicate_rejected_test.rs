//! Requirement DSL-107: mempool-level dedup across `pending_evidence`
//! (already accepted into the mempool on a prior pass) and
//! `incoming_evidence` (new REMARKs in the block being admitted).
//!
//! Fingerprint = `serde_json::to_vec(&ev)` bytes. Any match
//! between pending/incoming or within the incoming set itself
//! → `SlashingError::DuplicateEvidence`.
//!
//! Traces to: docs/resources/SPEC.md §16.3, §22.12.
//!
//! # Role
//!
//! Separate from DSL-026 manager-level dedup (`AlreadySlashed` on
//! evidence-hash collision): mempool policy runs upstream, before
//! the manager even sees the payload. Prevents a reporter from
//! spamming identical evidence into a single block or across
//! adjacent blocks while their original submission is still
//! pending.
//!
//! # Why JSON bytes as the fingerprint
//!
//! DSL-106/107 operate on raw REMARK payloads — the wire format
//! is JSON (DSL-102). Using the same bytes that rode on the wire
//! as the fingerprint means byte-identical payloads collide
//! without re-deriving any hash. Content-identical but JSON-
//! formatted-differently payloads are treated as distinct; that
//! is intentional because admission compares puzzle hashes
//! (DSL-104), and different JSON → different coin commitment →
//! different coin, which is a separate bundle anyway.
//!
//! # Test matrix (maps to DSL-107 Test Plan + acceptance)
//!
//!   1. `test_dsl_107_pending_duplicate_rejected` — ev in
//!      pending + same ev in incoming → DuplicateEvidence
//!   2. `test_dsl_107_incoming_duplicate_rejected` — same ev
//!      appears twice in incoming → DuplicateEvidence
//!   3. `test_dsl_107_distinct_ok` — pending & incoming all
//!      distinct → Ok
//!   4. `test_dsl_107_empty_inputs_ok` — edge: empty pending
//!      + empty incoming admits trivially

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, OffenseType, ProposerSlashing, SignedBlockHeader, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, enforce_slashing_evidence_mempool_dedup_policy,
};

fn sample_header(state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_byte; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        9,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn evidence(reporter_idx: u32, state_byte: u8) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        epoch: 12,
        reporter_validator_index: reporter_idx,
        reporter_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: SignedBlockHeader {
                message: sample_header(state_byte),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            signed_header_b: SignedBlockHeader {
                message: sample_header(state_byte ^ 0xFF),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
        }),
    }
}

/// DSL-107 row 1: incoming evidence that is byte-identical to an
/// entry already in `pending_evidence` must reject.
#[test]
fn test_dsl_107_pending_duplicate_rejected() {
    let ev = evidence(11, 0x02);
    let pending = vec![ev.clone()];
    let incoming = vec![ev];

    let err = enforce_slashing_evidence_mempool_dedup_policy(&pending, &incoming)
        .expect_err("pending/incoming collision must reject");
    assert!(
        matches!(err, SlashingError::DuplicateEvidence),
        "wrong variant: {err:?}",
    );
}

/// DSL-107 row 2: the same evidence appearing twice in the
/// incoming batch must reject — a reporter cannot submit a REMARK
/// twice in the same block to game policy ordering.
#[test]
fn test_dsl_107_incoming_duplicate_rejected() {
    let ev = evidence(11, 0x02);
    let pending: Vec<SlashingEvidence> = Vec::new();
    let incoming = vec![ev.clone(), ev];

    let err = enforce_slashing_evidence_mempool_dedup_policy(&pending, &incoming)
        .expect_err("in-batch duplicate must reject");
    assert!(matches!(err, SlashingError::DuplicateEvidence));
}

/// DSL-107 row 3: distinct payloads across pending + incoming
/// admit. We vary BOTH `reporter_validator_index` AND
/// `state_byte` so the fingerprints differ in multiple fields —
/// proves the dedup does not false-positive on partial-overlap.
#[test]
fn test_dsl_107_distinct_ok() {
    let pending = vec![evidence(11, 0x02), evidence(12, 0x33)];
    let incoming = vec![evidence(13, 0x44), evidence(14, 0x55)];

    enforce_slashing_evidence_mempool_dedup_policy(&pending, &incoming)
        .expect("distinct payloads must admit");

    // Within-incoming distinct is also fine.
    let pending: Vec<SlashingEvidence> = Vec::new();
    let incoming = vec![evidence(11, 0x02), evidence(12, 0x03)];
    enforce_slashing_evidence_mempool_dedup_policy(&pending, &incoming)
        .expect("distinct incoming-only batch must admit");
}

/// Edge: empty pending + empty incoming is the trivial case —
/// vacuously Ok. Dedup never triggers when there is nothing to
/// dedup.
#[test]
fn test_dsl_107_empty_inputs_ok() {
    let pending: Vec<SlashingEvidence> = Vec::new();
    let incoming: Vec<SlashingEvidence> = Vec::new();
    enforce_slashing_evidence_mempool_dedup_policy(&pending, &incoming)
        .expect("empty inputs admit vacuously");
}
