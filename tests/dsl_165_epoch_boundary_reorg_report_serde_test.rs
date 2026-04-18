//! Requirement DSL-165: `EpochBoundaryReport`, `ReorgReport`, `FlagDelta` round-trip byte-exactly via bincode + serde_json.
//!
//! Traces to: docs/resources/SPEC.md §10, §13, §18.
//!
//! # Role
//!
//! Three orchestration result types cross the wire for telemetry + snapshot/restore + RPC responses:
//!
//!   - `EpochBoundaryReport` — aggregate output of DSL-127 run_epoch_boundary. Carries flag_deltas vec + inactivity_penalties vec + finalisations vec + in_finality_stall + pruned_entries count.
//!   - `ReorgReport` — aggregate output of DSL-130 rewind_all_on_reorg. Carries rewound_pending_slashes vec (evidence hashes) + participation_epochs_dropped + inactivity_epochs_dropped + protection_rewound flag.
//!   - `FlagDelta` — per-validator reward/penalty row nested inside EpochBoundaryReport.flag_deltas.
//!
//! Adds `Serialize, Deserialize` derives to the two report structs (FlagDelta already had them). No other src/ changes.
//!
//! # Test matrix (maps to DSL-165 Test Plan)
//!
//!   1. `test_dsl_165_epoch_boundary_report_bincode` — populated EpochBoundaryReport under bincode.
//!   2. `test_dsl_165_reorg_report_bincode` — populated ReorgReport under bincode.
//!   3. `test_dsl_165_flag_delta_bincode` — standalone FlagDelta under bincode.
//!   4. `test_dsl_165_json_roundtrip_all` — all three under serde_json.
//!   5. `test_dsl_165_empty_vecs_preserved` — empty-vec cases for both reports roundtrip verbatim.
//!   6. `test_dsl_165_stall_flag_both` — in_finality_stall true + false both preserved.

use dig_protocol::Bytes32;
use dig_slashing::{
    EpochBoundaryReport, FinalisationResult, FlagDelta, PerValidatorSlash, ReorgReport,
    SlashingResult,
};

// ── fixtures ───────────────────────────────────────────────────

fn populated_flag_delta(idx: u32) -> FlagDelta {
    FlagDelta {
        validator_index: idx,
        reward: 1_000 + u64::from(idx),
        penalty: 500 + u64::from(idx),
    }
}

fn populated_finalisation(byte: u8) -> FinalisationResult {
    FinalisationResult {
        evidence_hash: Bytes32::new([byte; 32]),
        per_validator_correlation_penalty: vec![(3, 100_000), (5, 200_000)],
        reporter_bond_returned: 500_000_000,
        exit_lock_until_epoch: 1_000,
    }
}

fn populated_epoch_report() -> EpochBoundaryReport {
    EpochBoundaryReport {
        flag_deltas: vec![
            populated_flag_delta(3),
            populated_flag_delta(7),
            populated_flag_delta(11),
        ],
        inactivity_penalties: vec![(3, 50_000), (7, 75_000)],
        finalisations: vec![populated_finalisation(0xAA), populated_finalisation(0xBB)],
        in_finality_stall: true,
        pruned_entries: 42,
    }
}

fn populated_reorg_report() -> ReorgReport {
    ReorgReport {
        rewound_pending_slashes: vec![
            Bytes32::new([0x11u8; 32]),
            Bytes32::new([0x22u8; 32]),
            Bytes32::new([0x33u8; 32]),
        ],
        participation_epochs_dropped: 5,
        inactivity_epochs_dropped: 5,
        protection_rewound: true,
    }
}

fn empty_epoch_report() -> EpochBoundaryReport {
    EpochBoundaryReport {
        flag_deltas: vec![],
        inactivity_penalties: vec![],
        finalisations: vec![],
        in_finality_stall: false,
        pruned_entries: 0,
    }
}

fn empty_reorg_report() -> ReorgReport {
    ReorgReport {
        rewound_pending_slashes: vec![],
        participation_epochs_dropped: 0,
        inactivity_epochs_dropped: 0,
        protection_rewound: false,
    }
}

// ── helpers ───────────────────────────────────────────────────

fn roundtrip_bincode<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let bytes = bincode::serialize(value).expect("bincode ser");
    let decoded: T = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(*value, decoded, "bincode preserves every field");
}

fn roundtrip_json<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let bytes = serde_json::to_vec(value).expect("json ser");
    let decoded: T = serde_json::from_slice(&bytes).expect("json deser");
    assert_eq!(*value, decoded, "serde_json preserves every field");
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-165 row 1: populated EpochBoundaryReport roundtrips under bincode.
///
/// Exercises: non-empty flag_deltas (3 entries), non-empty
/// inactivity_penalties (2 entries), non-empty finalisations (2
/// entries — each with 2 correlation penalty pairs), in_finality_stall
/// = true, pruned_entries non-zero.
///
/// Spot-checks nested FinalisationResult decode (including its own
/// correlation_penalty Vec<(u32,u64)>) to guard against silent
/// truncation at any nesting level.
#[test]
fn test_dsl_165_epoch_boundary_report_bincode() {
    let report = populated_epoch_report();
    roundtrip_bincode(&report);

    let bytes = bincode::serialize(&report).expect("bincode ser");
    let decoded: EpochBoundaryReport = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(decoded.flag_deltas.len(), 3);
    assert_eq!(decoded.inactivity_penalties.len(), 2);
    assert_eq!(decoded.finalisations.len(), 2);
    assert!(decoded.in_finality_stall);
    assert_eq!(decoded.pruned_entries, 42);

    // Nested FinalisationResult decode — correlation_penalty vec
    // preserved byte-exact.
    assert_eq!(
        decoded.finalisations[0].per_validator_correlation_penalty,
        vec![(3, 100_000), (5, 200_000)],
    );
    assert_eq!(
        decoded.finalisations[0].evidence_hash,
        Bytes32::new([0xAAu8; 32])
    );
}

/// DSL-165 row 2: populated ReorgReport roundtrips under bincode.
///
/// Exercises: 3-entry rewound_pending_slashes vec of distinct
/// Bytes32 hashes, non-zero participation_epochs_dropped +
/// inactivity_epochs_dropped (same value — they mirror depth),
/// protection_rewound = true.
///
/// Post-roundtrip assert the hash vec order is preserved — reorg
/// telemetry depends on stable ordering to correlate with
/// admission-side audit logs.
#[test]
fn test_dsl_165_reorg_report_bincode() {
    let report = populated_reorg_report();
    roundtrip_bincode(&report);

    let bytes = bincode::serialize(&report).expect("bincode ser");
    let decoded: ReorgReport = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(decoded.rewound_pending_slashes.len(), 3);
    assert_eq!(
        decoded.rewound_pending_slashes[0],
        Bytes32::new([0x11u8; 32])
    );
    assert_eq!(
        decoded.rewound_pending_slashes[2],
        Bytes32::new([0x33u8; 32])
    );
    assert_eq!(decoded.participation_epochs_dropped, 5);
    assert_eq!(decoded.inactivity_epochs_dropped, 5);
    assert!(decoded.protection_rewound);
}

/// DSL-165 row 3: standalone FlagDelta roundtrips under bincode.
///
/// FlagDelta is nested inside EpochBoundaryReport but also appears
/// in isolation in test fixtures + metrics pipelines. Probe
/// extreme values (u32::MAX, u64::MAX) to catch length-prefix
/// drift on the reward/penalty u64s.
#[test]
fn test_dsl_165_flag_delta_bincode() {
    let fd = populated_flag_delta(42);
    roundtrip_bincode(&fd);

    let max = FlagDelta {
        validator_index: u32::MAX,
        reward: u64::MAX,
        penalty: u64::MAX,
    };
    roundtrip_bincode(&max);

    let zero = FlagDelta {
        validator_index: 0,
        reward: 0,
        penalty: 0,
    };
    roundtrip_bincode(&zero);
}

/// DSL-165 row 4: all three types under serde_json.
///
/// RPC wire path — telemetry + observability dashboards decode
/// these. Drift in the JSON shape of any nested field would
/// invalidate dashboard consumers.
///
/// Also probes PerValidatorSlash + SlashingResult nested
/// composition (populate a SlashingResult's per_validator with
/// one entry then feed to the roundtrip helper) so the bigger
/// picture is exercised, not just the orchestration result types
/// in isolation.
#[test]
fn test_dsl_165_json_roundtrip_all() {
    roundtrip_json(&populated_flag_delta(42));
    roundtrip_json(&populated_epoch_report());
    roundtrip_json(&populated_reorg_report());

    // Extra: prove SlashingResult (DSL-163 cousin) roundtrips via
    // serde_json alongside EpochBoundaryReport. Downstream RPC
    // endpoints often batch both.
    let sr = SlashingResult {
        per_validator: vec![PerValidatorSlash {
            validator_index: 3,
            base_slash_amount: 1_000_000,
            effective_balance_at_slash: 32_000_000_000,
            collateral_slashed: 0,
        }],
        whistleblower_reward: 1_000,
        proposer_reward: 125,
        burn_amount: 500,
        reporter_bond_escrowed: 500_000_000,
        pending_slash_hash: Bytes32::new([0xFFu8; 32]),
    };
    roundtrip_json(&sr);
}

/// DSL-165 row 5: empty-vec cases survive both codecs.
///
/// Early-epoch EpochBoundaryReports (no deltas yet) + no-reorg
/// ReorgReports surface these shapes — serde MUST preserve empty
/// vecs rather than dropping the fields or substituting defaults.
/// Dashboards rely on the struct shape being identical regardless
/// of activity.
#[test]
fn test_dsl_165_empty_vecs_preserved() {
    let empty_epoch = empty_epoch_report();
    roundtrip_bincode(&empty_epoch);
    roundtrip_json(&empty_epoch);

    let empty_reorg = empty_reorg_report();
    roundtrip_bincode(&empty_reorg);
    roundtrip_json(&empty_reorg);

    // Post-roundtrip spot-checks on both codecs.
    let bytes = bincode::serialize(&empty_epoch).expect("bincode ser");
    let decoded: EpochBoundaryReport = bincode::deserialize(&bytes).expect("bincode deser");
    assert!(decoded.flag_deltas.is_empty());
    assert!(decoded.inactivity_penalties.is_empty());
    assert!(decoded.finalisations.is_empty());
    assert!(!decoded.in_finality_stall);
    assert_eq!(decoded.pruned_entries, 0);
}

/// DSL-165 row 6: `in_finality_stall` true + false both preserved.
///
/// This bool gates the DSL-091 vs DSL-092 inactivity-leak branch
/// in downstream consumers; an accidentally-flipped roundtrip
/// would misattribute penalties across stall + non-stall epochs.
#[test]
fn test_dsl_165_stall_flag_both() {
    for stall in [true, false] {
        let report = EpochBoundaryReport {
            flag_deltas: vec![],
            inactivity_penalties: vec![],
            finalisations: vec![],
            in_finality_stall: stall,
            pruned_entries: 0,
        };

        let bytes = bincode::serialize(&report).expect("bincode ser");
        let decoded: EpochBoundaryReport = bincode::deserialize(&bytes).expect("bincode deser");
        assert_eq!(
            decoded.in_finality_stall, stall,
            "bincode must preserve in_finality_stall == {stall}",
        );

        let json = serde_json::to_string(&report).expect("json ser");
        let json_decoded: EpochBoundaryReport = serde_json::from_str(&json).expect("json deser");
        assert_eq!(
            json_decoded.in_finality_stall, stall,
            "serde_json must preserve in_finality_stall == {stall}",
        );
    }

    // Same for protection_rewound on ReorgReport.
    for flag in [true, false] {
        let report = ReorgReport {
            rewound_pending_slashes: vec![],
            participation_epochs_dropped: 0,
            inactivity_epochs_dropped: 0,
            protection_rewound: flag,
        };
        let bytes = bincode::serialize(&report).expect("bincode ser");
        let decoded: ReorgReport = bincode::deserialize(&bytes).expect("bincode deser");
        assert_eq!(decoded.protection_rewound, flag);
    }
}
