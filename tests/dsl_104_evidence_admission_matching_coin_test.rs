//! Requirement DSL-104: `enforce_slashing_evidence_remark_admission`
//! MUST return `Ok(())` when each parsed evidence's derived puzzle
//! hash equals the spent coin's `puzzle_hash`.
//!
//! Traces to: docs/resources/SPEC.md §16.1, §22.12.
//!
//! # Role
//!
//! DSL-102 ships the wire encoder. DSL-103 ships the puzzle
//! reveal + puzzle hash. DSL-104 wires them together for on-chain
//! admission: a `SpendBundle` + its per-coin REMARK-conditions
//! map goes in, an `Ok(())` comes out iff every evidence's
//! puzzle-hash commitment holds. DSL-105 covers mismatch.
//!
//! # Test matrix (maps to DSL-104 Test Plan)
//!
//!   1. `test_dsl_104_matching_admits` — single coin, single
//!      evidence, matching puzzle hash → Ok
//!   2. `test_dsl_104_multi_spend_all_match` — two coins, each
//!      with its own matching evidence → Ok
//!   3. `test_dsl_104_empty_bundle_vacuous_ok` — bundle with no
//!      REMARK payloads admits trivially (admission policy is
//!      per-evidence, not per-spend)
//!   4. `test_dsl_104_spend_without_remarks_ignored` — a spend
//!      whose coin is not in the conditions map simply has no
//!      evidences to enforce (exercises the `unwrap_or_default`
//!      fallback in the spec pseudocode)

use std::collections::HashMap;

use chia_bls::Signature;
use chia_protocol::{Bytes, Coin, CoinSpend, Program, SpendBundle};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, OffenseType, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, encode_slashing_evidence_remark_payload_v1,
    enforce_slashing_evidence_remark_admission, slashing_evidence_remark_puzzle_hash_v1,
    slashing_evidence_remark_puzzle_reveal_v1,
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

fn fixture_evidence(state_byte: u8, reporter_idx: u32) -> SlashingEvidence {
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

/// Build a CoinSpend whose coin's `puzzle_hash` matches the
/// DSL-103-derived hash for the given evidence. The solution
/// is empty nil (the DSL-103 puzzle has no solution inputs).
/// Signature + parent_coin_info are opaque padding — admission
/// only consults the puzzle-hash equality.
fn matching_coin_spend(ev: &SlashingEvidence) -> CoinSpend {
    let reveal = slashing_evidence_remark_puzzle_reveal_v1(ev).unwrap();
    let puzzle_hash = slashing_evidence_remark_puzzle_hash_v1(ev).unwrap();
    let coin = Coin::new(Bytes32::new([0u8; 32]), puzzle_hash, 1);
    CoinSpend::new(
        coin,
        Program::from(Bytes::new(reveal)),
        Program::from(Bytes::new(vec![0x80])),
    )
}

fn empty_bundle() -> SpendBundle {
    SpendBundle::new(Vec::new(), Signature::default())
}

/// DSL-104 row 1: single matching coin admits.
#[test]
fn test_dsl_104_matching_admits() {
    let ev = fixture_evidence(0x02, 11);
    let spend = matching_coin_spend(&ev);

    let wire = encode_slashing_evidence_remark_payload_v1(&ev).unwrap();
    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(spend.coin.coin_id(), vec![wire]);

    let bundle = SpendBundle::new(vec![spend], Signature::default());
    enforce_slashing_evidence_remark_admission(&bundle, &conditions)
        .expect("matching puzzle_hash must admit");
}

/// DSL-104 row 2: two spends each carrying its own matching
/// evidence. Admission MUST walk every spend and every payload.
#[test]
fn test_dsl_104_multi_spend_all_match() {
    let ev_a = fixture_evidence(0x02, 11);
    let ev_b = fixture_evidence(0x77, 22);
    let spend_a = matching_coin_spend(&ev_a);
    let spend_b = matching_coin_spend(&ev_b);

    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(
        spend_a.coin.coin_id(),
        vec![encode_slashing_evidence_remark_payload_v1(&ev_a).unwrap()],
    );
    conditions.insert(
        spend_b.coin.coin_id(),
        vec![encode_slashing_evidence_remark_payload_v1(&ev_b).unwrap()],
    );

    let bundle = SpendBundle::new(vec![spend_a, spend_b], Signature::default());
    enforce_slashing_evidence_remark_admission(&bundle, &conditions)
        .expect("both matching spends must admit");
}

/// DSL-104 row 3 (acceptance bullet 3): a bundle with no REMARK
/// payloads is vacuously Ok — the admission check is per-evidence.
#[test]
fn test_dsl_104_empty_bundle_vacuous_ok() {
    let conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    enforce_slashing_evidence_remark_admission(&empty_bundle(), &conditions)
        .expect("empty bundle admits trivially");
}

/// DSL-104 row 4: a spend whose coin_id is absent from the
/// conditions map is treated as "no REMARKs for this spend" via
/// the `unwrap_or_default` path in the spec pseudocode. Admission
/// must not spuriously reject on this shape — the consensus layer
/// provides conditions only for spends that actually emitted any,
/// and slashing admission has no opinion on non-REMARK spends.
#[test]
fn test_dsl_104_spend_without_remarks_ignored() {
    let ev = fixture_evidence(0x02, 11);
    let spend = matching_coin_spend(&ev);

    // Map is empty — spend.coin_id has no entry.
    let conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();

    let bundle = SpendBundle::new(vec![spend], Signature::default());
    enforce_slashing_evidence_remark_admission(&bundle, &conditions)
        .expect("spend with no REMARK entry in conditions map must admit");
}
