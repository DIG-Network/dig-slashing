//! Requirement DSL-108: `enforce_block_level_slashing_caps` MUST
//! reject when the admitted evidence count exceeds
//! `MAX_SLASH_PROPOSALS_PER_BLOCK` (64) with
//! `SlashingError::BlockCapExceeded { actual, limit }`.
//!
//! Traces to: docs/resources/SPEC.md §16.3, §2.8, §22.12.
//!
//! # Role
//!
//! Hard per-block cap on admission volume. Each evidence
//! triggers DSL-103 puzzle-hash derivation plus admission and
//! verifier work. Unbounded REMARK lists would let one block
//! blow up validation time. SPEC §2.8 fixes cap at 64.
//!
//! DSL-119 mirrors this for appeals with `MAX_APPEALS_PER_BLOCK`
//! but shares the same `BlockCapExceeded` variant — the
//! distinction is available at the call site via the `limit`
//! field (64 for slashing vs 64 for appeals happens to coincide,
//! but the caps are independent constants and could diverge).
//!
//! # Test matrix (maps to DSL-108 Test Plan + acceptance)
//!
//!   1. `test_dsl_108_over_cap_rejected` — 65 evidences →
//!      BlockCapExceeded { actual: 65, limit: 64 }
//!   2. `test_dsl_108_at_cap_ok` — exactly 64 admits (the cap
//!      is inclusive of exactly-at-limit blocks)
//!   3. `test_dsl_108_empty_ok` — 0 evidences admits vacuously

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, MAX_SLASH_PROPOSALS_PER_BLOCK, OffenseType, ProposerSlashing,
    SignedBlockHeader, SlashingError, SlashingEvidence, SlashingEvidencePayload,
    enforce_block_level_slashing_caps,
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

/// Build `n` distinct evidences. We vary `reporter_validator_index`
/// per entry so each fingerprint is unique (matters only for tests
/// that compose with DSL-107 dedup; DSL-108 itself cares only
/// about the length).
fn n_evidences(n: usize) -> Vec<SlashingEvidence> {
    (0..n)
        .map(|i| SlashingEvidence {
            offense_type: OffenseType::ProposerEquivocation,
            epoch: 12,
            reporter_validator_index: i as u32,
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
        })
        .collect()
}

/// DSL-108 row 1: `MAX + 1` = 65 evidences rejects with the
/// error variant carrying both the actual count and the cap.
#[test]
fn test_dsl_108_over_cap_rejected() {
    let over = n_evidences(MAX_SLASH_PROPOSALS_PER_BLOCK + 1);
    let err =
        enforce_block_level_slashing_caps(&over).expect_err("over-cap evidence list must reject");

    let SlashingError::BlockCapExceeded { actual, limit } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(
        actual,
        MAX_SLASH_PROPOSALS_PER_BLOCK + 1,
        "actual must carry the observed count",
    );
    assert_eq!(
        limit, MAX_SLASH_PROPOSALS_PER_BLOCK,
        "limit must carry MAX_SLASH_PROPOSALS_PER_BLOCK",
    );
}

/// DSL-108 row 2 (acceptance bullet 2): a list of EXACTLY
/// `MAX_SLASH_PROPOSALS_PER_BLOCK` items admits. The cap is
/// strict `>` so the boundary is inclusive.
#[test]
fn test_dsl_108_at_cap_ok() {
    let at_cap = n_evidences(MAX_SLASH_PROPOSALS_PER_BLOCK);
    enforce_block_level_slashing_caps(&at_cap)
        .expect("list of exactly the cap must admit (strict `>` excludes equality)");

    // Also spot-check one BELOW the cap to catch any off-by-one
    // regressions that would reject N-1.
    let below = n_evidences(MAX_SLASH_PROPOSALS_PER_BLOCK - 1);
    enforce_block_level_slashing_caps(&below).expect("cap - 1 must admit");
}

/// DSL-108 row 3 (acceptance bullet 3): empty list admits
/// vacuously. The cap applies to overfull blocks; a block with
/// zero slashing REMARKs is a valid state.
#[test]
fn test_dsl_108_empty_ok() {
    let empty: Vec<SlashingEvidence> = Vec::new();
    enforce_block_level_slashing_caps(&empty).expect("empty list admits vacuously");
}
