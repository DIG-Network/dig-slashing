//! Requirement DSL-103: evidence REMARK puzzle reveal emits
//! exactly ONE `Condition::Remark { message }` carrying the
//! DSL-102 encoded payload. Puzzle hash via
//! `clvm_utils::tree_hash`.
//!
//! Traces to: docs/resources/SPEC.md §16.1, §22.12.
//!
//! # Role
//!
//! DSL-102 pins the WIRE FORMAT of evidence on-chain. DSL-103
//! pins the PUZZLE that a reporter spends to put that wire
//! payload into a block's condition list. A minimal "return
//! one REMARK" CLVM puzzle is enough: the reporter signs a
//! coin whose `puzzle_hash` is the tree-hash of this reveal,
//! and consensus verifies the admission via DSL-104/105.
//!
//! # Test matrix (maps to DSL-103 Test Plan + acceptance)
//!
//!   1. `test_dsl_103_run_puzzle_one_remark` — run_puzzle on
//!      the reveal + empty solution produces a condition list
//!      containing exactly one Remark
//!   2. `test_dsl_103_remark_parses_back` — the REMARK message
//!      decodes through DSL-102 `parse_slashing_evidence_from_conditions`
//!      to the original evidence
//!   3. `test_dsl_103_puzzle_hash_stable` — two calls to
//!      `slashing_evidence_remark_puzzle_hash_v1` on the same
//!      evidence return the same `Bytes32`
//!   4. `test_dsl_103_puzzle_hash_matches_tree_hash` — the
//!      returned puzzle hash equals `clvm_utils::tree_hash_from_bytes`
//!      on the reveal bytes (acceptance bullet 4)

use chia_sdk_types::{Condition, run_puzzle};
use clvm_traits::FromClvm;
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, SExp};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, OffenseType, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, parse_slashing_evidence_from_conditions,
    slashing_evidence_remark_puzzle_hash_v1, slashing_evidence_remark_puzzle_reveal_v1,
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

fn fixture_evidence() -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        epoch: 12,
        reporter_validator_index: 11,
        reporter_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: SignedBlockHeader {
                message: sample_header(0x02),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            signed_header_b: SignedBlockHeader {
                message: sample_header(0x99),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
        }),
    }
}

/// DSL-103 row 1: run the puzzle reveal with an empty solution.
/// CLVM execution must yield a proper list of conditions
/// containing EXACTLY one entry, and that entry must be a Remark.
///
/// A "proper list" means: (cond . (cond . (...) . nil)). We parse
/// the output via `Vec<Condition<NodePtr>>::from_clvm` — that impl
/// enforces properness and will fail to decode on any malformed
/// tail.
#[test]
fn test_dsl_103_run_puzzle_one_remark() {
    let ev = fixture_evidence();
    let reveal = slashing_evidence_remark_puzzle_reveal_v1(&ev).expect("reveal");

    let mut allocator = Allocator::new();
    let puzzle = node_from_bytes(&mut allocator, &reveal).expect("reveal must be valid CLVM");
    let solution = allocator.nil();
    let output = run_puzzle(&mut allocator, puzzle, solution).expect("puzzle must run cleanly");

    let conditions = Vec::<Condition<clvmr::NodePtr>>::from_clvm(&allocator, output)
        .expect("output must decode as a condition list");
    assert_eq!(
        conditions.len(),
        1,
        "puzzle must emit exactly one condition",
    );
    assert!(
        matches!(conditions[0], Condition::Remark(_)),
        "sole condition must be a Remark variant",
    );
}

/// DSL-103 row 2: the REMARK's message bytes pass cleanly
/// through DSL-102's parser back to the original evidence.
///
/// This is the full end-to-end: build evidence → encode via
/// DSL-102 → wrap in DSL-103 puzzle → run puzzle → extract
/// REMARK message → run DSL-102 parser → compare PartialEq.
#[test]
fn test_dsl_103_remark_parses_back() {
    let ev = fixture_evidence();
    let reveal = slashing_evidence_remark_puzzle_reveal_v1(&ev).unwrap();

    let mut allocator = Allocator::new();
    let puzzle = node_from_bytes(&mut allocator, &reveal).unwrap();
    let solution = allocator.nil();
    let output = run_puzzle(&mut allocator, puzzle, solution).unwrap();

    let conditions = Vec::<Condition<clvmr::NodePtr>>::from_clvm(&allocator, output).unwrap();

    // Extract the REMARK payload atom. `Remark<T> { rest: T }` is
    // the cdr of the condition pair. For our canonical `(1 payload)`
    // proper-list form, rest = `(payload . nil)`. Walk the pair to
    // get the payload atom, then read its raw bytes directly from
    // the allocator — Vec<u8>::from_clvm would try to decode as a
    // list of u8 atoms, which is NOT what we stored.
    let message_bytes: Vec<u8> = match &conditions[0] {
        Condition::Remark(remark) => match allocator.sexp(remark.rest) {
            SExp::Pair(payload_atom, _nil) => allocator.atom(payload_atom).as_ref().to_vec(),
            SExp::Atom => allocator.atom(remark.rest).as_ref().to_vec(),
        },
        _ => panic!("expected Remark"),
    };

    let parsed = parse_slashing_evidence_from_conditions(&[message_bytes]);
    assert_eq!(parsed.len(), 1, "DSL-102 parser must accept the message");
    assert_eq!(
        parsed[0], ev,
        "full roundtrip: ev → reveal → REMARK → parse → ev"
    );
}

/// DSL-103 row 3: the puzzle hash is deterministic. Computing it
/// twice on the same evidence must produce the same Bytes32. This
/// is the coin-commitment invariant — a reporter builds the coin
/// once, the consensus layer recomputes on admission, and they
/// must agree to the byte.
#[test]
fn test_dsl_103_puzzle_hash_stable() {
    let ev = fixture_evidence();
    let h1 = slashing_evidence_remark_puzzle_hash_v1(&ev).unwrap();
    let h2 = slashing_evidence_remark_puzzle_hash_v1(&ev).unwrap();
    assert_eq!(h1, h2, "puzzle hash must be deterministic across calls");

    // Different evidence → different hash. The payload is bound
    // into the puzzle bytes, so any field change must propagate to
    // the hash — otherwise the reporter could swap payloads after
    // admission.
    let mut ev2 = fixture_evidence();
    ev2.reporter_validator_index = 22;
    let h3 = slashing_evidence_remark_puzzle_hash_v1(&ev2).unwrap();
    assert_ne!(
        h1, h3,
        "reporter_index change must propagate to puzzle hash",
    );
}

/// DSL-103 row 4 (acceptance bullet 4): the puzzle hash is derived
/// via `clvm_utils::tree_hash_from_bytes`, not a custom SHA scheme.
/// Pinning this equality means downstream consensus (dig-block's
/// `verify_coin_spend_puzzle_hash`) will accept the coin without
/// special-casing.
#[test]
fn test_dsl_103_puzzle_hash_matches_tree_hash() {
    let ev = fixture_evidence();
    let reveal = slashing_evidence_remark_puzzle_reveal_v1(&ev).unwrap();
    let computed = slashing_evidence_remark_puzzle_hash_v1(&ev).unwrap();

    let expected: Bytes32 = clvm_utils::tree_hash_from_bytes(&reveal)
        .expect("reveal bytes must parse for tree_hash")
        .into();
    assert_eq!(
        computed, expected,
        "puzzle hash must equal tree_hash_from_bytes(reveal)",
    );
}
