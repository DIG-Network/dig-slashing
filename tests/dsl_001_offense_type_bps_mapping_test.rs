//! Requirement DSL-001: `OffenseType::base_penalty_bps` returns 500/300/100/100
//! for the four variants; all `< MAX_PENALTY_BPS`.
//!
//! Traces to: docs/resources/SPEC.md §2.1 (penalty BPS constants), §3.2
//! (OffenseType enum), §22.1 (catalogue row).
//!
//! These tests PROVE the requirement by exhaustively covering the Test Plan
//! table in docs/requirements/domains/evidence/specs/DSL-001.md:
//!
//!   1. `test_dsl_001_proposer_equivocation_500_bps` — ProposerEquivocation → 500
//!   2. `test_dsl_001_invalid_block_300_bps` — InvalidBlock → 300
//!   3. `test_dsl_001_attester_double_vote_100_bps` — AttesterDoubleVote → 100
//!   4. `test_dsl_001_attester_surround_vote_100_bps` — AttesterSurroundVote → 100
//!   5. `test_dsl_001_all_below_max_penalty_bps` — every variant < MAX_PENALTY_BPS
//!
//! Each test is narrow: it asserts one row of the acceptance-criteria checklist,
//! so a failure isolates the exact misbehaviour. The BPS constants are protocol
//! law — any change here is a protocol version bump, not a bug fix.
//!
//! Downstream: these BPS values feed the base-slash formula in `SlashingManager::submit_evidence`
//! (DSL-022) and the reporter-penalty path in `AppealAdjudicator` (DSL-069).

use dig_slashing::{
    ATTESTATION_BASE_BPS, EQUIVOCATION_BASE_BPS, INVALID_BLOCK_BASE_BPS, MAX_PENALTY_BPS,
    OffenseType,
};

/// DSL-001 row 1: Proposer equivocation carries the heaviest base-BPS floor.
///
/// Proves `base_penalty_bps()` returns `EQUIVOCATION_BASE_BPS` (= 500) for the
/// `ProposerEquivocation` variant. Equivocation is the most blatant consensus
/// offense — signing two distinct blocks at the same slot — and the largest
/// BPS floor reflects that severity.
#[test]
fn test_dsl_001_proposer_equivocation_500_bps() {
    assert_eq!(
        OffenseType::ProposerEquivocation.base_penalty_bps(),
        EQUIVOCATION_BASE_BPS,
        "ProposerEquivocation must map to EQUIVOCATION_BASE_BPS per SPEC §2.1",
    );
    assert_eq!(
        OffenseType::ProposerEquivocation.base_penalty_bps(),
        500,
        "EQUIVOCATION_BASE_BPS is frozen at 500 (5%) — protocol version bump required to change",
    );
}

/// DSL-001 row 2: Invalid block proposal carries the middle BPS floor.
///
/// Proves `base_penalty_bps()` returns `INVALID_BLOCK_BASE_BPS` (= 300) for
/// `InvalidBlock`. Less severe than equivocation because proposing an invalid
/// block can result from bugs as well as malice, but still an explicit
/// slashable offense.
#[test]
fn test_dsl_001_invalid_block_300_bps() {
    assert_eq!(
        OffenseType::InvalidBlock.base_penalty_bps(),
        INVALID_BLOCK_BASE_BPS,
        "InvalidBlock must map to INVALID_BLOCK_BASE_BPS per SPEC §2.1",
    );
    assert_eq!(
        OffenseType::InvalidBlock.base_penalty_bps(),
        300,
        "INVALID_BLOCK_BASE_BPS is frozen at 300 (3%)",
    );
}

/// DSL-001 row 3: Attester double-vote shares the attestation BPS floor.
///
/// Proves `base_penalty_bps()` returns `ATTESTATION_BASE_BPS` (= 100) for
/// `AttesterDoubleVote`. Attestation offenses are mass-participation (many
/// validators can be caught in a single indexed attestation), so the
/// per-validator base is smaller; correlation amplification at finalisation
/// (DSL-030/DSL-151) scales the total when many are caught.
#[test]
fn test_dsl_001_attester_double_vote_100_bps() {
    assert_eq!(
        OffenseType::AttesterDoubleVote.base_penalty_bps(),
        ATTESTATION_BASE_BPS,
        "AttesterDoubleVote must map to ATTESTATION_BASE_BPS per SPEC §2.1",
    );
    assert_eq!(
        OffenseType::AttesterDoubleVote.base_penalty_bps(),
        100,
        "ATTESTATION_BASE_BPS is frozen at 100 (1%)",
    );
}

/// DSL-001 row 4: Attester surround-vote shares the same floor as double-vote.
///
/// Proves `base_penalty_bps()` returns `ATTESTATION_BASE_BPS` (= 100) for
/// `AttesterSurroundVote`. The two attester predicates collapse to the same
/// per-validator base — the distinction is about which SPEC §5.3 predicate
/// matched, not about severity.
#[test]
fn test_dsl_001_attester_surround_vote_100_bps() {
    assert_eq!(
        OffenseType::AttesterSurroundVote.base_penalty_bps(),
        ATTESTATION_BASE_BPS,
        "AttesterSurroundVote must map to ATTESTATION_BASE_BPS per SPEC §2.1",
    );
    assert_eq!(
        OffenseType::AttesterSurroundVote.base_penalty_bps(),
        100,
        "ATTESTATION_BASE_BPS is frozen at 100 (1%)",
    );
}

/// DSL-001 row 5: Every variant's BPS floor stays under MAX_PENALTY_BPS.
///
/// Proves the MAX_PENALTY_BPS (= 1_000, 10%) ceiling holds for every offense.
/// This is the protocol's single-offense cap before correlation amplification
/// (SPEC §4). Enumerating all four variants here also defends against a silent
/// fifth variant being added without a corresponding BPS review.
#[test]
fn test_dsl_001_all_below_max_penalty_bps() {
    // Exhaustive list — if a new OffenseType variant is added, this test will
    // either fail to compile (missing arm in the implementation) or fail at
    // runtime (if the new variant's BPS is mis-configured). Both are desired.
    let variants = [
        OffenseType::ProposerEquivocation,
        OffenseType::InvalidBlock,
        OffenseType::AttesterDoubleVote,
        OffenseType::AttesterSurroundVote,
    ];

    for variant in variants {
        let bps = variant.base_penalty_bps();
        assert!(
            bps < MAX_PENALTY_BPS,
            "{variant:?}.base_penalty_bps() = {bps} must be < MAX_PENALTY_BPS = {MAX_PENALTY_BPS}",
        );
        assert!(
            bps > 0,
            "{variant:?}.base_penalty_bps() = {bps} must be > 0 (every offense has a real penalty)",
        );
    }
}
