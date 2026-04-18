//! Requirement DSL-112: `enforce_slash_appeal_remark_admission`
//! returns `Ok(())` when each parsed appeal's DSL-111 puzzle
//! hash equals the spent coin's `puzzle_hash`.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Appeal-side analogue of DSL-104. DSL-110 ships the wire,
//! DSL-111 ships the puzzle + hash, DSL-112 wires them for
//! admission. DSL-113 covers the mismatch fail-path.
//!
//! # Test matrix (maps to DSL-112 Test Plan + acceptance)
//!
//!   1. `test_dsl_112_matching_admits` — single coin + single
//!      matching appeal → Ok
//!   2. `test_dsl_112_multi_spend_all_match` — two coins, each
//!      with own matching appeal → Ok
//!   3. `test_dsl_112_empty_bundle_vacuous_ok` — bundle with no
//!      REMARK payloads admits trivially
//!   4. `test_dsl_112_spend_without_remarks_ignored` — spend
//!      absent from conditions map contributes zero appeals

use std::collections::HashMap;

use chia_bls::Signature;
use chia_protocol::{Bytes, Coin, CoinSpend, Program, SpendBundle};
use dig_protocol::Bytes32;
use dig_slashing::{
    ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal, SlashAppealPayload,
    encode_slash_appeal_remark_payload_v1, enforce_slash_appeal_remark_admission,
    slash_appeal_remark_puzzle_hash_v1, slash_appeal_remark_puzzle_reveal_v1,
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

fn matching_coin_spend(ap: &SlashAppeal) -> CoinSpend {
    let reveal = slash_appeal_remark_puzzle_reveal_v1(ap).unwrap();
    let ph = slash_appeal_remark_puzzle_hash_v1(ap).unwrap();
    let coin = Coin::new(Bytes32::new([0u8; 32]), ph, 1);
    CoinSpend::new(
        coin,
        Program::from(Bytes::new(reveal)),
        Program::from(Bytes::new(vec![0x80])),
    )
}

fn empty_bundle() -> SpendBundle {
    SpendBundle::new(Vec::new(), Signature::default())
}

/// DSL-112 row 1: single matching coin admits.
#[test]
fn test_dsl_112_matching_admits() {
    let ap = fixture_appeal(11);
    let spend = matching_coin_spend(&ap);

    let wire = encode_slash_appeal_remark_payload_v1(&ap).unwrap();
    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(spend.coin.coin_id(), vec![wire]);

    let bundle = SpendBundle::new(vec![spend], Signature::default());
    enforce_slash_appeal_remark_admission(&bundle, &conditions)
        .expect("matching puzzle_hash must admit");
}

/// DSL-112 row 2: multi-spend bundle with both matching → Ok.
#[test]
fn test_dsl_112_multi_spend_all_match() {
    let ap_a = fixture_appeal(11);
    let ap_b = fixture_appeal(22);
    let spend_a = matching_coin_spend(&ap_a);
    let spend_b = matching_coin_spend(&ap_b);

    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(
        spend_a.coin.coin_id(),
        vec![encode_slash_appeal_remark_payload_v1(&ap_a).unwrap()],
    );
    conditions.insert(
        spend_b.coin.coin_id(),
        vec![encode_slash_appeal_remark_payload_v1(&ap_b).unwrap()],
    );

    let bundle = SpendBundle::new(vec![spend_a, spend_b], Signature::default());
    enforce_slash_appeal_remark_admission(&bundle, &conditions)
        .expect("both matching spends must admit");
}

/// Empty bundle → vacuously Ok.
#[test]
fn test_dsl_112_empty_bundle_vacuous_ok() {
    let conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    enforce_slash_appeal_remark_admission(&empty_bundle(), &conditions)
        .expect("empty bundle admits trivially");
}

/// Spend absent from conditions map → no appeals to enforce.
#[test]
fn test_dsl_112_spend_without_remarks_ignored() {
    let ap = fixture_appeal(11);
    let spend = matching_coin_spend(&ap);
    let conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    let bundle = SpendBundle::new(vec![spend], Signature::default());
    enforce_slash_appeal_remark_admission(&bundle, &conditions)
        .expect("spend with no REMARK entry must admit");
}
