//! Requirement DSL-105: when a REMARK-carrying spend's coin
//! `puzzle_hash` does NOT equal
//! `slashing_evidence_remark_puzzle_hash_v1(&ev)`, admission MUST
//! reject with `SlashingError::AdmissionPuzzleHashMismatch`
//! carrying both the `expected` and `got` hashes.
//!
//! Traces to: docs/resources/SPEC.md §16.1, §22.12.
//!
//! # Role
//!
//! The fail-path companion of DSL-104. An attacker who obtains
//! a valid JSON payload could try to embed it as a REMARK in a
//! spend whose coin never committed to that payload — the coin's
//! `puzzle_hash` would then be something else entirely. DSL-105
//! forces the equality: if the coin does not cryptographically
//! commit to this exact evidence at creation, admission fails
//! before any state mutation.
//!
//! # Test matrix (maps to DSL-105 Test Plan + acceptance)
//!
//!   1. `test_dsl_105_mismatch_rejected` — coin puzzle_hash set
//!      to a wrong value → AdmissionPuzzleHashMismatch
//!   2. `test_dsl_105_error_carries_hashes` — the error variant
//!      exposes both `expected` and `got` as populated `Bytes32`
//!      fields (spec acceptance: hex-encodable for logging)
//!   3. `test_dsl_105_first_mismatch_short_circuits` — iteration
//!      halts at the first mismatch: a second, even more broken
//!      spend in the same bundle never runs

use std::collections::HashMap;

use chia_bls::Signature;
use chia_protocol::{Bytes, Coin, CoinSpend, Program, SpendBundle};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, OffenseType, ProposerSlashing, SignedBlockHeader, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, encode_slashing_evidence_remark_payload_v1,
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

/// Build a CoinSpend with a DELIBERATELY WRONG puzzle_hash on the
/// coin. Reveal + solution mirror the real DSL-103 shape but the
/// coin commitment is forged.
fn mismatching_coin_spend(ev: &SlashingEvidence, wrong_ph: Bytes32) -> CoinSpend {
    let reveal = slashing_evidence_remark_puzzle_reveal_v1(ev).unwrap();
    let coin = Coin::new(Bytes32::new([0u8; 32]), wrong_ph, 1);
    CoinSpend::new(
        coin,
        Program::from(Bytes::new(reveal)),
        Program::from(Bytes::new(vec![0x80])),
    )
}

fn matching_coin_spend(ev: &SlashingEvidence) -> CoinSpend {
    let reveal = slashing_evidence_remark_puzzle_reveal_v1(ev).unwrap();
    let ph = slashing_evidence_remark_puzzle_hash_v1(ev).unwrap();
    let coin = Coin::new(Bytes32::new([0u8; 32]), ph, 1);
    CoinSpend::new(
        coin,
        Program::from(Bytes::new(reveal)),
        Program::from(Bytes::new(vec![0x80])),
    )
}

/// DSL-105 row 1: a wrong-puzzle-hash coin forces admission to
/// reject with AdmissionPuzzleHashMismatch. The parsed evidence
/// itself is valid — the rejection is solely on the coin
/// commitment.
#[test]
fn test_dsl_105_mismatch_rejected() {
    let ev = fixture_evidence(0x02, 11);
    let wrong_ph = Bytes32::new([0xAAu8; 32]);
    let spend = mismatching_coin_spend(&ev, wrong_ph);

    let wire = encode_slashing_evidence_remark_payload_v1(&ev).unwrap();
    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(spend.coin.coin_id(), vec![wire]);

    let bundle = SpendBundle::new(vec![spend], Signature::default());
    let err = enforce_slashing_evidence_remark_admission(&bundle, &conditions)
        .expect_err("mismatched puzzle_hash must reject");

    assert!(
        matches!(err, SlashingError::AdmissionPuzzleHashMismatch { .. }),
        "error variant must be AdmissionPuzzleHashMismatch; got {err:?}",
    );
}

/// DSL-105 row 2 (acceptance bullet 2): both hash fields
/// populated + recoverable for downstream logging.
///
/// Spec pseudocode uses `hex::encode` at the error site; our
/// impl stores raw `Bytes32` and relies on `BytesImpl<N>`'s
/// `Display` impl to produce lowercase hex via `hex::encode`.
/// This test verifies both fields have the correct values
/// (`expected` = DSL-103-derived hash; `got` = coin's `puzzle_hash`)
/// and that their `Display` representations are valid 64-char
/// lowercase hex strings.
#[test]
fn test_dsl_105_error_carries_hashes() {
    let ev = fixture_evidence(0x02, 11);
    let wrong_ph = Bytes32::new([0xBBu8; 32]);
    let spend = mismatching_coin_spend(&ev, wrong_ph);

    let wire = encode_slashing_evidence_remark_payload_v1(&ev).unwrap();
    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(spend.coin.coin_id(), vec![wire]);

    let bundle = SpendBundle::new(vec![spend], Signature::default());
    let err = enforce_slashing_evidence_remark_admission(&bundle, &conditions).unwrap_err();

    let SlashingError::AdmissionPuzzleHashMismatch { expected, got } = err else {
        panic!("wrong variant: {err:?}");
    };

    let derived = slashing_evidence_remark_puzzle_hash_v1(&ev).unwrap();
    assert_eq!(
        expected, derived,
        "expected field must carry DSL-103-derived puzzle_hash",
    );
    assert_eq!(got, wrong_ph, "got field must carry the coin's puzzle_hash");

    // Display renders as 64 lowercase hex chars (no prefix) per
    // chia-protocol Bytes32 impl. The spec pseudocode's
    // `hex::encode(...)` uses the same encoding, so Display in the
    // error message Just Works for operator logging.
    let expected_hex = format!("{expected}");
    let got_hex = format!("{got}");
    assert_eq!(expected_hex.len(), 64, "Bytes32 Display is 64-char hex");
    assert_eq!(got_hex.len(), 64, "Bytes32 Display is 64-char hex");
    assert!(
        expected_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "Bytes32 Display must be lowercase hex digits only",
    );
    assert!(
        got_hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "Bytes32 Display must be lowercase hex digits only",
    );

    // Sanity: the Display rendering of the whole error carries
    // both hashes so operators see them in logs.
    let rendered = format!("{err}");
    assert!(rendered.contains(&expected_hex));
    assert!(rendered.contains(&got_hex));
}

/// DSL-105 row 3 (acceptance bullet 3): iteration short-circuits
/// at the first mismatch. Construct a bundle where:
///
///   - spend[0] MATCHES (should admit in isolation),
///   - spend[1] MISMATCHES,
///   - spend[2] would also mismatch (but even more blatantly,
///     with a completely nonsense coin puzzle_hash).
///
/// Admission must fail on spend[1] and never examine spend[2].
/// We prove the short-circuit by inspecting the error's `got`
/// field and confirming it equals spend[1]'s coin ph, NOT
/// spend[2]'s.
#[test]
fn test_dsl_105_first_mismatch_short_circuits() {
    let ev_a = fixture_evidence(0x02, 11);
    let ev_b = fixture_evidence(0x33, 22);
    let ev_c = fixture_evidence(0x55, 33);

    let spend_a = matching_coin_spend(&ev_a);
    let wrong_b = Bytes32::new([0xB1u8; 32]);
    let spend_b = mismatching_coin_spend(&ev_b, wrong_b);
    let wrong_c = Bytes32::new([0xC2u8; 32]);
    let spend_c = mismatching_coin_spend(&ev_c, wrong_c);

    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(
        spend_a.coin.coin_id(),
        vec![encode_slashing_evidence_remark_payload_v1(&ev_a).unwrap()],
    );
    conditions.insert(
        spend_b.coin.coin_id(),
        vec![encode_slashing_evidence_remark_payload_v1(&ev_b).unwrap()],
    );
    conditions.insert(
        spend_c.coin.coin_id(),
        vec![encode_slashing_evidence_remark_payload_v1(&ev_c).unwrap()],
    );

    let bundle = SpendBundle::new(vec![spend_a, spend_b, spend_c], Signature::default());
    let err = enforce_slashing_evidence_remark_admission(&bundle, &conditions).unwrap_err();

    let SlashingError::AdmissionPuzzleHashMismatch { got, .. } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(
        got, wrong_b,
        "short-circuit must halt on spend[1]; `got` must be spend[1]'s ph, not spend[2]'s",
    );
    assert_ne!(got, wrong_c, "spend[2] must not have been examined");
}
