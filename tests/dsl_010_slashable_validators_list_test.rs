//! Requirement DSL-010: `SlashingEvidence::slashable_validators()` returns
//! the list of validator indices this envelope accuses.
//!
//! Traces to: docs/resources/SPEC.md §3.5, §22.1.
//!
//! # Role
//!
//! Two downstream consumers depend on this method:
//!
//!   - `verify_evidence` (DSL-012) runs `ReporterIsAccused` check by
//!     testing `reporter_validator_index ∈ slashable_validators()`.
//!   - `SlashingManager::submit_evidence` (DSL-022) iterates this list
//!     for the per-validator slash loop (one debit per accused index).
//!
//! Cardinality MUST match SPEC §3.5:
//!
//!   - `Proposer` → exactly 1 (the `proposer_index` from header A).
//!   - `InvalidBlock` → exactly 1 (the `proposer_index` from the single
//!     signed header).
//!   - `Attester` → 0..=N, the sorted intersection of the two
//!     `IndexedAttestation` index lists (delegates to
//!     `AttesterSlashing::slashable_indices`, DSL-007).
//!
//! # Test matrix (maps to DSL-010 Test Plan)
//!
//!   1. `test_dsl_010_proposer_single_index` — Proposer → [proposer_index]
//!   2. `test_dsl_010_invalid_block_single_index` — InvalidBlock → [proposer_index]
//!   3. `test_dsl_010_attester_intersection` — matches DSL-007 output
//!   4. `test_dsl_010_attester_empty_intersection` — disjoint → []
//!   5. `test_dsl_010_deterministic` — two calls byte-equal
//!   6. `test_dsl_010_attester_sorted_ascending` — intersection output sorted

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    InvalidBlockProof, InvalidBlockReason, OffenseType, ProposerSlashing, SignedBlockHeader,
    SlashingEvidence, SlashingEvidencePayload,
};

fn sample_header(proposer_index: u32) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        proposer_index,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn sample_signed_header(proposer_index: u32) -> SignedBlockHeader {
    SignedBlockHeader {
        message: sample_header(proposer_index),
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    }
}

fn sample_attestation_data(target_epoch: u64) -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x11u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: target_epoch,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}

fn sample_envelope(payload: SlashingEvidencePayload) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 42,
        payload,
    }
}

/// DSL-010 row 1: Proposer payload → single-element vec containing
/// `signed_header_a.message.proposer_index`.
///
/// The envelope cites ONE proposer (the equivocator). `signed_header_b`
/// MUST share the same proposer under the DSL-013 verifier, so reading
/// from header A is canonical — picking B or intersecting would be
/// redundant.
#[test]
fn test_dsl_010_proposer_single_index() {
    let payload = SlashingEvidencePayload::Proposer(ProposerSlashing {
        signed_header_a: sample_signed_header(7),
        signed_header_b: sample_signed_header(7),
    });
    let ev = sample_envelope(payload);

    let list = ev.slashable_validators();
    assert_eq!(list, vec![7u32], "Proposer must return [proposer_index]");
    assert_eq!(list.len(), 1, "Proposer cardinality MUST be 1");
}

/// DSL-010 row 2: InvalidBlock payload → single-element vec containing
/// the proposer_index of the offending signed block header.
#[test]
fn test_dsl_010_invalid_block_single_index() {
    let payload = SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
        signed_header: sample_signed_header(13),
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    });
    let ev = sample_envelope(payload);

    let list = ev.slashable_validators();
    assert_eq!(
        list,
        vec![13u32],
        "InvalidBlock must return [proposer_index]"
    );
    assert_eq!(list.len(), 1, "InvalidBlock cardinality MUST be 1");
}

/// DSL-010 row 3: Attester payload → matches `AttesterSlashing::slashable_indices()`
/// bit-for-bit.
///
/// Double-vote scenario: two IndexedAttestations on the same target epoch
/// with different target roots would be the DSL-014 predicate; here we
/// only check the method's list-extraction. Overlap `{3, 5}` between
/// `[1, 3, 5, 7]` and `[2, 3, 5, 8]`.
#[test]
fn test_dsl_010_attester_intersection() {
    let a = IndexedAttestation {
        attesting_indices: vec![1, 3, 5, 7],
        data: sample_attestation_data(3),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    let b = IndexedAttestation {
        attesting_indices: vec![2, 3, 5, 8],
        // Different target root would violate double-vote predicate, but
        // predicate is out of scope for DSL-010; this test only exercises
        // list extraction.
        data: sample_attestation_data(3),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    let payload = SlashingEvidencePayload::Attester(AttesterSlashing {
        attestation_a: a.clone(),
        attestation_b: b.clone(),
    });
    let ev = sample_envelope(payload);

    let list = ev.slashable_validators();
    assert_eq!(list, vec![3u32, 5u32], "intersection must be {{3, 5}}");

    // Explicit parity with the underlying helper — any divergence would
    // mean `slashable_validators` drifted away from DSL-007.
    let direct = AttesterSlashing {
        attestation_a: a,
        attestation_b: b,
    }
    .slashable_indices();
    assert_eq!(
        list, direct,
        "must delegate to AttesterSlashing::slashable_indices"
    );
}

/// DSL-010 row 4: disjoint Attester → empty vec. `verify_attester_slashing`
/// (DSL-016) will later reject this envelope with
/// `EmptySlashableIntersection`, but `slashable_validators` is type-level
/// and MUST be able to report zero — otherwise the verifier can't detect
/// the condition cleanly.
#[test]
fn test_dsl_010_attester_empty_intersection() {
    let a = IndexedAttestation {
        attesting_indices: vec![1, 3, 5],
        data: sample_attestation_data(3),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    let b = IndexedAttestation {
        attesting_indices: vec![2, 4, 6],
        data: sample_attestation_data(3),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    let payload = SlashingEvidencePayload::Attester(AttesterSlashing {
        attestation_a: a,
        attestation_b: b,
    });
    let ev = sample_envelope(payload);

    let list = ev.slashable_validators();
    assert!(list.is_empty(), "disjoint Attester must yield empty vec");
}

/// DSL-010 row 5: two calls on the same envelope return byte-equal vecs.
///
/// Covers all three variants. Any non-determinism (HashSet iteration,
/// allocator-order leak) would make `SlashingManager::submit_evidence`
/// iterate validator indices in different orders across replays, which
/// the correlation penalty (DSL-030) is not designed to tolerate.
#[test]
fn test_dsl_010_deterministic() {
    let cases = [
        SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: sample_signed_header(7),
            signed_header_b: sample_signed_header(7),
        }),
        SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: IndexedAttestation {
                attesting_indices: vec![1, 3, 5, 7],
                data: sample_attestation_data(3),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            attestation_b: IndexedAttestation {
                attesting_indices: vec![2, 3, 5, 8],
                data: sample_attestation_data(3),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
        }),
        SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: sample_signed_header(13),
            failure_witness: vec![],
            failure_reason: InvalidBlockReason::Other,
        }),
    ];
    for payload in cases {
        let ev = sample_envelope(payload);
        let first = ev.slashable_validators();
        let second = ev.slashable_validators();
        assert_eq!(first, second, "consecutive calls must return equal vecs");
    }
}

/// DSL-010 row 6: Attester intersection is strictly ascending.
///
/// Guards against a regression where `slashable_validators` starts
/// returning e.g. `HashSet`-iterated output (which would be arbitrary
/// order on Rust's SipHash). The correlation penalty (DSL-030) and
/// per-validator fan-out loop (DSL-022) both assume sorted input.
#[test]
fn test_dsl_010_attester_sorted_ascending() {
    // Construct index lists where a naive implementation that concatenated
    // + dedup'd might emit [7, 5, 3, 1] (reverse) or [5, 3, 1, 7]
    // (insertion order). Correct output is strictly ascending: [1, 3, 5, 7].
    let a = IndexedAttestation {
        attesting_indices: vec![1, 3, 5, 7],
        data: sample_attestation_data(3),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    let b = IndexedAttestation {
        attesting_indices: vec![1, 3, 5, 7],
        data: sample_attestation_data(3),
        signature: vec![0u8; BLS_SIGNATURE_SIZE],
    };
    let payload = SlashingEvidencePayload::Attester(AttesterSlashing {
        attestation_a: a,
        attestation_b: b,
    });
    let ev = sample_envelope(payload);

    let list = ev.slashable_validators();
    assert_eq!(list, vec![1, 3, 5, 7]);
    for pair in list.windows(2) {
        assert!(
            pair[0] < pair[1],
            "list MUST be strictly ascending: {list:?}"
        );
    }
}
