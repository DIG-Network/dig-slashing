//! Requirement DSL-113: when an appeal REMARK-carrying spend's
//! coin `puzzle_hash` does NOT equal
//! `slash_appeal_remark_puzzle_hash_v1(&ap)`, admission MUST
//! reject with `SlashingError::AdmissionPuzzleHashMismatch`
//! carrying both hashes.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Appeal-side analogue of DSL-105. Exercises the DSL-112 fail
//! path. No new production code — the `AdmissionPuzzleHashMismatch`
//! variant and short-circuit iteration were landed in DSL-104,
//! and DSL-112 already invokes the same error return when the
//! coin commitment breaks.
//!
//! # Test matrix (maps to DSL-113 Test Plan + acceptance)
//!
//!   1. `test_dsl_113_mismatch_rejected` — wrong puzzle_hash →
//!      AdmissionPuzzleHashMismatch
//!   2. `test_dsl_113_error_carries_hashes` — `expected` + `got`
//!      fields correctly populated
//!   3. `test_dsl_113_first_mismatch_short_circuits` — iteration
//!      halts at first failure in a multi-spend bundle

use std::collections::HashMap;

use chia_bls::Signature;
use chia_protocol::{Bytes, Coin, CoinSpend, Program, SpendBundle};
use dig_protocol::Bytes32;
use dig_slashing::{
    ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal, SlashAppealPayload, SlashingError,
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

fn mismatching_coin_spend(ap: &SlashAppeal, wrong_ph: Bytes32) -> CoinSpend {
    let reveal = slash_appeal_remark_puzzle_reveal_v1(ap).unwrap();
    let coin = Coin::new(Bytes32::new([0u8; 32]), wrong_ph, 1);
    CoinSpend::new(
        coin,
        Program::from(Bytes::new(reveal)),
        Program::from(Bytes::new(vec![0x80])),
    )
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

/// DSL-113 row 1: mismatch rejects with correct variant.
#[test]
fn test_dsl_113_mismatch_rejected() {
    let ap = fixture_appeal(11);
    let wrong = Bytes32::new([0xA1u8; 32]);
    let spend = mismatching_coin_spend(&ap, wrong);

    let wire = encode_slash_appeal_remark_payload_v1(&ap).unwrap();
    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(spend.coin.coin_id(), vec![wire]);

    let bundle = SpendBundle::new(vec![spend], Signature::default());
    let err = enforce_slash_appeal_remark_admission(&bundle, &conditions)
        .expect_err("mismatched puzzle_hash must reject");

    assert!(
        matches!(err, SlashingError::AdmissionPuzzleHashMismatch { .. }),
        "variant: {err:?}",
    );
}

/// DSL-113 row 2: error fields carry the derived vs coin ph.
#[test]
fn test_dsl_113_error_carries_hashes() {
    let ap = fixture_appeal(11);
    let wrong = Bytes32::new([0xB2u8; 32]);
    let spend = mismatching_coin_spend(&ap, wrong);

    let wire = encode_slash_appeal_remark_payload_v1(&ap).unwrap();
    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(spend.coin.coin_id(), vec![wire]);

    let bundle = SpendBundle::new(vec![spend], Signature::default());
    let err = enforce_slash_appeal_remark_admission(&bundle, &conditions).unwrap_err();

    let SlashingError::AdmissionPuzzleHashMismatch { expected, got } = err else {
        panic!("wrong variant: {err:?}");
    };

    let derived = slash_appeal_remark_puzzle_hash_v1(&ap).unwrap();
    assert_eq!(expected, derived, "expected field = DSL-111-derived hash");
    assert_eq!(got, wrong, "got field = coin's puzzle_hash");
}

/// DSL-113 row 3: first mismatch short-circuits. 3-spend bundle
/// (match, mismatch_b, mismatch_c): iteration must halt on
/// spend[1], never examining spend[2].
#[test]
fn test_dsl_113_first_mismatch_short_circuits() {
    let ap_a = fixture_appeal(11);
    let ap_b = fixture_appeal(22);
    let ap_c = fixture_appeal(33);

    let spend_a = matching_coin_spend(&ap_a);
    let wrong_b = Bytes32::new([0xB1u8; 32]);
    let spend_b = mismatching_coin_spend(&ap_b, wrong_b);
    let wrong_c = Bytes32::new([0xC2u8; 32]);
    let spend_c = mismatching_coin_spend(&ap_c, wrong_c);

    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(
        spend_a.coin.coin_id(),
        vec![encode_slash_appeal_remark_payload_v1(&ap_a).unwrap()],
    );
    conditions.insert(
        spend_b.coin.coin_id(),
        vec![encode_slash_appeal_remark_payload_v1(&ap_b).unwrap()],
    );
    conditions.insert(
        spend_c.coin.coin_id(),
        vec![encode_slash_appeal_remark_payload_v1(&ap_c).unwrap()],
    );

    let bundle = SpendBundle::new(vec![spend_a, spend_b, spend_c], Signature::default());
    let err = enforce_slash_appeal_remark_admission(&bundle, &conditions).unwrap_err();

    let SlashingError::AdmissionPuzzleHashMismatch { got, .. } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(got, wrong_b, "halts on spend[1]");
    assert_ne!(got, wrong_c, "spend[2] never examined");
}
