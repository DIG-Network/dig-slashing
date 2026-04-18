//! Requirement DSL-164: `AppealAdjudicationResult` round-trips byte-exactly via bincode + serde_json.
//!
//! Traces to: docs/resources/SPEC.md §3.9, §18.
//!
//! # Role
//!
//! `AppealAdjudicationResult` is the aggregate output of the appeal-adjudication pass — summarises the economic effect (reverted stake/collateral vecs, bond forfeitures, awards, reporter penalty, burn residue) per appeal. Consumed by:
//!
//!   - Audit logs — full reproduction of what happened on a sustained / rejected appeal.
//!   - RPC responses — telemetry consumers query via serde_json.
//!   - Test fixtures — construction without running the full pipeline.
//!
//! Two "shapes" the struct typically takes:
//!
//!   - Sustained (Won) — `reverted_stake_mojos` + `reverted_collateral_mojos` populated; `appellant_award_mojos` non-zero; `clawback_shortfall` possibly non-zero; rejected-only fields zero.
//!   - Rejected (Lost { reason_hash }) — `reporter_award_mojos` + `appellant_bond_forfeited` non-zero; sustained-only fields empty/zero.
//!
//! # Test matrix (maps to DSL-164 Test Plan)
//!
//!   1. `test_dsl_164_sustained_bincode` — sustained result with populated reverted vecs + awards + non-zero clawback_shortfall.
//!   2. `test_dsl_164_rejected_bincode` — rejected result with reporter_award + appellant_bond_forfeited non-zero; reverted vecs empty.
//!   3. `test_dsl_164_json_roundtrip` — both outcomes under serde_json.
//!   4. `test_dsl_164_outcome_variants` — Won, Lost { reason_hash }, Pending all roundtrip (covers AppealOutcome enum surface inside AppealAdjudicationResult).
//!   5. `test_dsl_164_vec_ordering` — multi-validator reverted_stake_mojos + reverted_collateral_mojos preserve index-ordering under both codecs (guards against BTreeMap-style reordering drift).

use dig_protocol::Bytes32;
use dig_slashing::{AppealAdjudicationResult, AppealOutcome};

// ── fixtures ───────────────────────────────────────────────────

fn sustained_result() -> AppealAdjudicationResult {
    AppealAdjudicationResult {
        appeal_hash: Bytes32::new([0xAAu8; 32]),
        evidence_hash: Bytes32::new([0xBBu8; 32]),
        outcome: AppealOutcome::Won,
        reverted_stake_mojos: vec![(3, 1_000_000), (7, 2_000_000)],
        reverted_collateral_mojos: vec![(3, 500_000), (7, 750_000)],
        clawback_shortfall: 100_000,
        reporter_bond_forfeited: 500_000_000,
        appellant_award_mojos: 250_000_000,
        reporter_penalty_mojos: 50_000_000,
        // Rejected-branch fields zero on sustained path.
        appellant_bond_forfeited: 0,
        reporter_award_mojos: 0,
        burn_amount: 150_000_000,
    }
}

fn rejected_result() -> AppealAdjudicationResult {
    AppealAdjudicationResult {
        appeal_hash: Bytes32::new([0xCCu8; 32]),
        evidence_hash: Bytes32::new([0xDDu8; 32]),
        outcome: AppealOutcome::Lost {
            reason_hash: Bytes32::new([0xEEu8; 32]),
        },
        // Sustained-branch fields empty/zero on rejected path.
        reverted_stake_mojos: vec![],
        reverted_collateral_mojos: vec![],
        clawback_shortfall: 0,
        reporter_bond_forfeited: 0,
        appellant_award_mojos: 0,
        reporter_penalty_mojos: 0,
        // Rejected-branch fields populated.
        appellant_bond_forfeited: 500_000_000,
        reporter_award_mojos: 250_000_000,
        burn_amount: 250_000_000,
    }
}

// ── helpers ───────────────────────────────────────────────────

fn roundtrip_bincode(v: &AppealAdjudicationResult) {
    let bytes = bincode::serialize(v).expect("bincode ser");
    let decoded: AppealAdjudicationResult = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(*v, decoded, "bincode preserves every field");
}

fn roundtrip_json(v: &AppealAdjudicationResult) {
    let bytes = serde_json::to_vec(v).expect("json ser");
    let decoded: AppealAdjudicationResult = serde_json::from_slice(&bytes).expect("json deser");
    assert_eq!(*v, decoded, "serde_json preserves every field");
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-164 row 1: sustained result roundtrips under bincode.
///
/// Populated reverted_stake + reverted_collateral vecs, non-zero
/// awards, non-zero clawback_shortfall. Spot-check AppealOutcome::Won
/// is preserved in isolation so the enum tag doesn't silently drift.
#[test]
fn test_dsl_164_sustained_bincode() {
    let sustained = sustained_result();
    roundtrip_bincode(&sustained);

    let bytes = bincode::serialize(&sustained).expect("bincode ser");
    let decoded: AppealAdjudicationResult = bincode::deserialize(&bytes).expect("bincode deser");
    assert!(matches!(decoded.outcome, AppealOutcome::Won));
    assert_eq!(decoded.reverted_stake_mojos.len(), 2);
    assert_eq!(decoded.clawback_shortfall, 100_000);
    // Rejected-branch fields still zero post-roundtrip.
    assert_eq!(decoded.appellant_bond_forfeited, 0);
    assert_eq!(decoded.reporter_award_mojos, 0);
}

/// DSL-164 row 2: rejected result roundtrips under bincode.
///
/// Sustained-branch fields empty/zero; rejected-branch populated.
/// Pins `AppealOutcome::Lost { reason_hash }` struct variant
/// survives including its payload Bytes32.
#[test]
fn test_dsl_164_rejected_bincode() {
    let rejected = rejected_result();
    roundtrip_bincode(&rejected);

    let bytes = bincode::serialize(&rejected).expect("bincode ser");
    let decoded: AppealAdjudicationResult = bincode::deserialize(&bytes).expect("bincode deser");
    match decoded.outcome {
        AppealOutcome::Lost { reason_hash } => {
            assert_eq!(reason_hash, Bytes32::new([0xEEu8; 32]));
        }
        other => panic!("expected Lost, got {other:?}"),
    }
    assert!(decoded.reverted_stake_mojos.is_empty());
    assert!(decoded.reverted_collateral_mojos.is_empty());
    assert_eq!(decoded.appellant_bond_forfeited, 500_000_000);
    assert_eq!(decoded.reporter_award_mojos, 250_000_000);
}

/// DSL-164 row 3: both result shapes roundtrip under serde_json.
///
/// RPC wire path — telemetry consumers decode over HTTP. The JSON
/// encoding must preserve both sustained-only and rejected-only
/// fields alongside zero-valued counterparts so dashboards see
/// consistent structure regardless of outcome.
#[test]
fn test_dsl_164_json_roundtrip() {
    roundtrip_json(&sustained_result());
    roundtrip_json(&rejected_result());
}

/// DSL-164 row 4: all three AppealOutcome variants roundtrip nested
/// in AppealAdjudicationResult.
///
/// Pending is the transient in-flight outcome — used in AppealAttempt
/// records mid-adjudication (before the verdict is resolved) and in
/// test fixtures. Must roundtrip even though it's not a terminal
/// state.
#[test]
fn test_dsl_164_outcome_variants() {
    let reason = Bytes32::new([0xF0u8; 32]);

    for outcome in [
        AppealOutcome::Won,
        AppealOutcome::Lost {
            reason_hash: reason,
        },
        AppealOutcome::Pending,
    ] {
        let result = AppealAdjudicationResult {
            appeal_hash: Bytes32::new([0x01u8; 32]),
            evidence_hash: Bytes32::new([0x02u8; 32]),
            outcome,
            reverted_stake_mojos: vec![],
            reverted_collateral_mojos: vec![],
            clawback_shortfall: 0,
            reporter_bond_forfeited: 0,
            appellant_award_mojos: 0,
            reporter_penalty_mojos: 0,
            appellant_bond_forfeited: 0,
            reporter_award_mojos: 0,
            burn_amount: 0,
        };
        roundtrip_bincode(&result);
        roundtrip_json(&result);
    }
}

/// DSL-164 row 5: multi-validator reverted_stake_mojos +
/// reverted_collateral_mojos preserve insertion ORDER under both
/// codecs.
///
/// Pins the Vec shape (not a BTreeMap or HashMap) against a future
/// refactor that might swap the container type for dedup semantics.
/// Insertion order is load-bearing because DSL-064 credits validator
/// indices in `base_slash_per_validator` order — audit logs rely on
/// consistent pairing between the result vec and the source vec.
#[test]
fn test_dsl_164_vec_ordering() {
    let stake_pairs = vec![
        (u32::MAX, 1_000),
        (0, 2_000),
        (42, 3_000),
        (7, 4_000),
        (1_000_000, 5_000),
    ];
    let collateral_pairs = vec![(3, 100), (5, 200), (1, 300), (u32::MAX - 1, 400)];

    let result = AppealAdjudicationResult {
        appeal_hash: Bytes32::new([0x11u8; 32]),
        evidence_hash: Bytes32::new([0x22u8; 32]),
        outcome: AppealOutcome::Won,
        reverted_stake_mojos: stake_pairs.clone(),
        reverted_collateral_mojos: collateral_pairs.clone(),
        clawback_shortfall: 0,
        reporter_bond_forfeited: 1,
        appellant_award_mojos: 1,
        reporter_penalty_mojos: 0,
        appellant_bond_forfeited: 0,
        reporter_award_mojos: 0,
        burn_amount: 0,
    };

    // bincode.
    let bytes = bincode::serialize(&result).expect("bincode ser");
    let decoded: AppealAdjudicationResult = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(
        decoded.reverted_stake_mojos, stake_pairs,
        "bincode preserves reverted_stake_mojos insertion order (NOT sorted)",
    );
    assert_eq!(
        decoded.reverted_collateral_mojos, collateral_pairs,
        "bincode preserves reverted_collateral_mojos insertion order",
    );

    // serde_json.
    let json = serde_json::to_string(&result).expect("json ser");
    let json_decoded: AppealAdjudicationResult = serde_json::from_str(&json).expect("json deser");
    assert_eq!(json_decoded.reverted_stake_mojos, stake_pairs);
    assert_eq!(json_decoded.reverted_collateral_mojos, collateral_pairs);
}
