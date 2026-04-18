//! Requirement DSL-120: appeal whose `serde_json::to_vec(ap)`
//! length exceeds `MAX_APPEAL_PAYLOAD_BYTES` (131_072) MUST
//! reject with `SlashingError::AppealPayloadTooLarge { actual,
//! limit }`.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §2.6, §22.13.
//!
//! # Role
//!
//! Appeal-side analogue of DSL-109. Reuses existing
//! `SlashingError::AppealPayloadTooLarge` variant (DSL-063).
//! Cap is 2x the evidence cap because appeals can carry full
//! block bodies for invalid-block oracle re-execution.
//!
//! # Fixture strategy
//!
//! Variable-size lever is `InvalidBlockAppeal::witness`. Binary-
//! search witness_len to land JSON at-limit boundary.
//!
//! # Test matrix (maps to DSL-120 Test Plan)
//!
//!   1. `test_dsl_120_over_rejected` — JSON > cap →
//!      AppealPayloadTooLarge
//!   2. `test_dsl_120_at_limit_ok` — at-limit admits via
//!      binary-search tuner
//!   3. `test_dsl_120_small_ok` — 1 KiB admits

use dig_protocol::Bytes32;
use dig_slashing::{
    InvalidBlockAppeal, InvalidBlockAppealGround, MAX_APPEAL_PAYLOAD_BYTES, SlashAppeal,
    SlashAppealPayload, SlashingError, enforce_slash_appeal_payload_cap,
};

fn appeal_with_witness(witness_len: usize) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: Bytes32::new([0x11u8; 32]),
        appellant_index: 11,
        appellant_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::InvalidBlock(InvalidBlockAppeal {
            ground: InvalidBlockAppealGround::BlockActuallyValid,
            witness: vec![0xABu8; witness_len],
        }),
    }
}

fn json_len(ap: &SlashAppeal) -> usize {
    serde_json::to_vec(ap).unwrap().len()
}

/// Binary-search witness_len landing JSON ≤ target_len. Returns
/// (witness_len, actual_json_len).
fn tune_witness_len(target_len: usize) -> (usize, usize) {
    let mut lo = 0usize;
    let mut hi = target_len;
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        let len = json_len(&appeal_with_witness(mid));
        if len <= target_len {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    (lo, json_len(&appeal_with_witness(lo)))
}

/// DSL-120 row 1: oversize rejects with both fields populated.
#[test]
fn test_dsl_120_over_rejected() {
    let ap = appeal_with_witness(MAX_APPEAL_PAYLOAD_BYTES + 1);
    let len = json_len(&ap);
    assert!(
        len > MAX_APPEAL_PAYLOAD_BYTES,
        "fixture must exceed cap; got {len}",
    );

    let err = enforce_slash_appeal_payload_cap(&[ap]).expect_err("oversize rejects");
    let SlashingError::AppealPayloadTooLarge { actual, limit } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(actual, len);
    assert_eq!(limit, MAX_APPEAL_PAYLOAD_BYTES);
}

/// DSL-120 row 2: at-limit admits (strict `>` excludes equality).
#[test]
fn test_dsl_120_at_limit_ok() {
    let (witness, actual) = tune_witness_len(MAX_APPEAL_PAYLOAD_BYTES);
    assert!(
        actual <= MAX_APPEAL_PAYLOAD_BYTES,
        "tuner must land at or below cap; got {actual} witness_len={witness}",
    );
    enforce_slash_appeal_payload_cap(&[appeal_with_witness(witness)])
        .expect("at-or-below-limit admits");
}

/// DSL-120 row 3: small payload well inside the envelope admits.
#[test]
fn test_dsl_120_small_ok() {
    let ap = appeal_with_witness(1024);
    let len = json_len(&ap);
    assert!(
        len < MAX_APPEAL_PAYLOAD_BYTES / 4,
        "small fixture must be well inside cap; got {len}",
    );
    enforce_slash_appeal_payload_cap(&[ap]).expect("small payload admits");

    // Empty list admits vacuously.
    let empty: Vec<SlashAppeal> = Vec::new();
    enforce_slash_appeal_payload_cap(&empty).expect("empty admits");
}
