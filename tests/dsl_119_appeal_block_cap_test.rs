//! Requirement DSL-119: `enforce_block_level_appeal_caps` MUST
//! reject when `appeals.len() > MAX_APPEALS_PER_BLOCK` (64) with
//! `SlashingError::BlockCapExceeded { actual, limit }`.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §2.8, §22.13.
//!
//! # Role
//!
//! Appeal-side analogue of DSL-108. Same shared variant; the
//! `limit` field carries `MAX_APPEALS_PER_BLOCK` here so callers
//! can tell which cap fired.
//!
//! # Test matrix (maps to DSL-119 Test Plan + acceptance)
//!
//!   1. `test_dsl_119_over_cap_rejected` — 65 rejects with
//!      fields populated + `limit == MAX_APPEALS_PER_BLOCK`
//!   2. `test_dsl_119_at_cap_ok` — exactly 64 admits (strict
//!      `>`)
//!   3. `test_dsl_119_empty_ok` — 0 admits vacuously

use dig_protocol::Bytes32;
use dig_slashing::{
    MAX_APPEALS_PER_BLOCK, ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal,
    SlashAppealPayload, SlashingError, enforce_block_level_appeal_caps,
};

fn n_appeals(n: usize) -> Vec<SlashAppeal> {
    (0..n)
        .map(|i| SlashAppeal {
            evidence_hash: Bytes32::new([(i & 0xFF) as u8; 32]),
            appellant_index: i as u32,
            appellant_puzzle_hash: Bytes32::new([0xEEu8; 32]),
            filed_epoch: 42,
            payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
                ground: ProposerAppealGround::HeadersIdentical,
                witness: vec![],
            }),
        })
        .collect()
}

#[test]
fn test_dsl_119_over_cap_rejected() {
    let over = n_appeals(MAX_APPEALS_PER_BLOCK + 1);
    let err = enforce_block_level_appeal_caps(&over).expect_err("over-cap rejects");
    let SlashingError::BlockCapExceeded { actual, limit } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(actual, MAX_APPEALS_PER_BLOCK + 1);
    assert_eq!(
        limit, MAX_APPEALS_PER_BLOCK,
        "must carry MAX_APPEALS_PER_BLOCK so callers can distinguish from DSL-108 slashing cap",
    );
}

#[test]
fn test_dsl_119_at_cap_ok() {
    let at = n_appeals(MAX_APPEALS_PER_BLOCK);
    enforce_block_level_appeal_caps(&at).expect("exactly MAX admits");

    // Regression guard one below the cap.
    let below = n_appeals(MAX_APPEALS_PER_BLOCK - 1);
    enforce_block_level_appeal_caps(&below).expect("MAX - 1 admits");
}

#[test]
fn test_dsl_119_empty_ok() {
    let empty: Vec<SlashAppeal> = Vec::new();
    enforce_block_level_appeal_caps(&empty).expect("empty admits vacuously");
}
