//! Requirement DSL-111: appeal REMARK puzzle reveal emits
//! exactly ONE `Condition::Remark { message }` whose payload
//! parses back to the original `SlashAppeal` via DSL-110, and
//! whose tree hash is deterministic.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Appeal-side analogue of DSL-103. DSL-110 pins the wire; this
//! DSL pins the CLVM puzzle that carries the wire on-chain. A
//! constant-returning quoted puzzle `(q . ((1 payload)))` commits
//! the appellant to the exact appeal bytes at coin-creation time
//! via the puzzle-hash derived from the reveal. DSL-112/113 then
//! admits/rejects based on coin-puzzle-hash equality.
//!
//! # Test matrix (maps to DSL-111 Test Plan + acceptance)
//!
//!   1. `test_dsl_111_run_puzzle_one_remark` — run_puzzle yields
//!      exactly one Condition::Remark
//!   2. `test_dsl_111_parses_back` — REMARK message round-trips
//!      through DSL-110's parser back to the original appeal
//!   3. `test_dsl_111_hash_stable` — puzzle hash deterministic
//!      across calls AND binds appellant_index mutations
//!   4. `test_dsl_111_hash_matches_tree_hash` — returned hash
//!      equals `clvm_utils::tree_hash_from_bytes(reveal)`

use chia_sdk_types::{Condition, run_puzzle};
use clvm_traits::FromClvm;
use clvmr::serde::node_from_bytes;
use clvmr::{Allocator, SExp};
use dig_protocol::Bytes32;
use dig_slashing::{
    ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal, SlashAppealPayload,
    parse_slash_appeals_from_conditions, slash_appeal_remark_puzzle_hash_v1,
    slash_appeal_remark_puzzle_reveal_v1,
};

fn fixture_appeal(appellant_idx: u32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: Bytes32::new([0x77u8; 32]),
        appellant_index: appellant_idx,
        appellant_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-111 row 1: exactly one REMARK.
#[test]
fn test_dsl_111_run_puzzle_one_remark() {
    let ap = fixture_appeal(11);
    let reveal = slash_appeal_remark_puzzle_reveal_v1(&ap).expect("reveal");

    let mut allocator = Allocator::new();
    let puzzle = node_from_bytes(&mut allocator, &reveal).expect("valid CLVM");
    let solution = allocator.nil();
    let output = run_puzzle(&mut allocator, puzzle, solution).expect("run");

    let conditions = Vec::<Condition<clvmr::NodePtr>>::from_clvm(&allocator, output)
        .expect("output decodes as condition list");
    assert_eq!(conditions.len(), 1, "exactly one condition");
    assert!(
        matches!(conditions[0], Condition::Remark(_)),
        "sole condition is Remark",
    );
}

/// DSL-111 row 2: REMARK payload round-trips through DSL-110
/// parser back to the original appeal.
#[test]
fn test_dsl_111_parses_back() {
    let ap = fixture_appeal(11);
    let reveal = slash_appeal_remark_puzzle_reveal_v1(&ap).unwrap();

    let mut allocator = Allocator::new();
    let puzzle = node_from_bytes(&mut allocator, &reveal).unwrap();
    let solution = allocator.nil();
    let output = run_puzzle(&mut allocator, puzzle, solution).unwrap();
    let conditions = Vec::<Condition<clvmr::NodePtr>>::from_clvm(&allocator, output).unwrap();

    // Extract the payload atom from the `(1 payload)` condition
    // tail. Proper-list form: rest = (payload . nil).
    let message_bytes: Vec<u8> = match &conditions[0] {
        Condition::Remark(remark) => match allocator.sexp(remark.rest) {
            SExp::Pair(payload_atom, _nil) => allocator.atom(payload_atom).as_ref().to_vec(),
            SExp::Atom => allocator.atom(remark.rest).as_ref().to_vec(),
        },
        _ => panic!("expected Remark"),
    };

    let parsed = parse_slash_appeals_from_conditions(&[message_bytes]);
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed[0], ap,
        "full roundtrip: ap → reveal → REMARK → parse → ap",
    );
}

/// DSL-111 row 3: puzzle hash deterministic AND binds payload
/// mutations. An appellant cannot swap `appellant_index` after
/// creation without producing a different puzzle_hash (and thus
/// a different coin).
#[test]
fn test_dsl_111_hash_stable() {
    let ap = fixture_appeal(11);
    let h1 = slash_appeal_remark_puzzle_hash_v1(&ap).unwrap();
    let h2 = slash_appeal_remark_puzzle_hash_v1(&ap).unwrap();
    assert_eq!(h1, h2, "deterministic");

    let ap2 = fixture_appeal(22);
    let h3 = slash_appeal_remark_puzzle_hash_v1(&ap2).unwrap();
    assert_ne!(h1, h3, "appellant_index change must propagate to hash");
}

/// DSL-111 row 4: puzzle hash derived via
/// `clvm_utils::tree_hash_from_bytes`, matching DSL-103's
/// approach so downstream consensus validates both sides with
/// the same primitive.
#[test]
fn test_dsl_111_hash_matches_tree_hash() {
    let ap = fixture_appeal(11);
    let reveal = slash_appeal_remark_puzzle_reveal_v1(&ap).unwrap();
    let computed = slash_appeal_remark_puzzle_hash_v1(&ap).unwrap();

    let expected: Bytes32 = clvm_utils::tree_hash_from_bytes(&reveal)
        .expect("reveal parses for tree_hash")
        .into();
    assert_eq!(computed, expected);
}
