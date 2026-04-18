//! Requirement DSL-161: `PendingSlash`, `PendingSlashStatus` (all 4 variants), `AppealAttempt` (all 3 outcome variants) round-trip byte-exactly via bincode.
//!
//! Traces to: docs/resources/SPEC.md §3.8, §18.
//!
//! # Role
//!
//! `PendingSlash` is the lifecycle record held in `PendingSlashBook` between admission and finalisation/revert. Its serde contract is the persistence layer: snapshot-restore after node restart, replay of pending state across deployments, and test fixtures that inject mid-cycle state without driving the full submit→appeal→finalise pipeline.
//!
//! Three nested types must all survive bincode:
//!
//!   - `PendingSlashStatus` — 4 variants. Accepted (unit), ChallengeOpen (struct with `first_appeal_filed_epoch` + `appeal_count`), Reverted (struct with `winning_appeal_hash` + `reverted_at_epoch`), Finalised (struct with `finalised_at_epoch`).
//!   - `AppealAttempt` — struct carrying hash, appellant, epoch, outcome, bond. The inner `AppealOutcome` enum has 3 variants: Won (unit), Lost (struct with reason_hash), Pending (unit).
//!   - `PendingSlash` — top-level struct with evidence, verified evidence, status, base_slash_per_validator vec, reporter bond, AND an appeal_history vec (variable-length).
//!
//! # Test matrix (maps to DSL-161 Test Plan)
//!
//!   1. `test_dsl_161_status_accepted_roundtrip` — unit variant.
//!   2. `test_dsl_161_status_challenge_open_roundtrip` — struct variant fields preserved.
//!   3. `test_dsl_161_status_reverted_roundtrip` — Bytes32 + u64 fields preserved.
//!   4. `test_dsl_161_status_finalised_roundtrip` — u64 field preserved.
//!   5. `test_dsl_161_appeal_attempt_won_lost_pending` — all 3 AppealOutcome variants roundtrip.
//!   6. `test_dsl_161_pending_slash_full_tree` — full PendingSlash with populated appeal_history; 2 appeals at different epochs + distinct outcomes, both recovered post-roundtrip.

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealAttempt, AppealOutcome, BLS_SIGNATURE_SIZE, OffenseType, PendingSlash,
    PendingSlashStatus, PerValidatorSlash, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, VerifiedEvidence,
};

// ── fixtures ───────────────────────────────────────────────────

fn sample_header() -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
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

fn sample_pending(status: PendingSlashStatus, history: Vec<AppealAttempt>) -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([0xEFu8; 32]),
        evidence: SlashingEvidence {
            offense_type: OffenseType::ProposerEquivocation,
            epoch: 12,
            reporter_validator_index: 11,
            reporter_puzzle_hash: Bytes32::new([0xAAu8; 32]),
            payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
                signed_header_a: SignedBlockHeader {
                    message: sample_header(),
                    signature: vec![0u8; BLS_SIGNATURE_SIZE],
                },
                signed_header_b: SignedBlockHeader {
                    message: sample_header(),
                    signature: vec![0u8; BLS_SIGNATURE_SIZE],
                },
            }),
        },
        verified: VerifiedEvidence {
            offense_type: OffenseType::ProposerEquivocation,
            slashable_validator_indices: vec![7],
        },
        status,
        submitted_at_epoch: 15,
        window_expires_at_epoch: 23,
        base_slash_per_validator: vec![PerValidatorSlash {
            validator_index: 7,
            base_slash_amount: 1_000_000,
            effective_balance_at_slash: 32_000_000_000,
            collateral_slashed: 0,
        }],
        reporter_bond_mojos: 500_000_000,
        appeal_history: history,
    }
}

fn assert_bincode_roundtrip_status(status: PendingSlashStatus) {
    let bytes = bincode::serialize(&status).expect("bincode ser");
    let decoded: PendingSlashStatus = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(status, decoded, "status variant roundtrips verbatim");
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-161 row 1: `Accepted` unit variant roundtrips.
///
/// Wrapped inside a PendingSlash envelope as well so the nested-
/// enum case (status inside struct inside vec) is exercised, not
/// just the raw enum.
#[test]
fn test_dsl_161_status_accepted_roundtrip() {
    assert_bincode_roundtrip_status(PendingSlashStatus::Accepted);

    let original = sample_pending(PendingSlashStatus::Accepted, vec![]);
    let bytes = bincode::serialize(&original).expect("bincode ser");
    let decoded: PendingSlash = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(original, decoded);
    assert!(matches!(decoded.status, PendingSlashStatus::Accepted));
}

/// DSL-161 row 2: `ChallengeOpen { first_appeal_filed_epoch, appeal_count }` struct variant preserves both fields verbatim.
///
/// Critical: these two fields drive DSL-056 (window-check) +
/// DSL-059 (MAX_APPEAL_ATTEMPTS limit); drift here would corrupt
/// appeal acceptance on snapshot restore.
#[test]
fn test_dsl_161_status_challenge_open_roundtrip() {
    let status = PendingSlashStatus::ChallengeOpen {
        first_appeal_filed_epoch: 17,
        appeal_count: 3,
    };
    assert_bincode_roundtrip_status(status);

    // Extract-and-verify through full PendingSlash envelope.
    let ps = sample_pending(status, vec![]);
    let bytes = bincode::serialize(&ps).expect("bincode ser");
    let decoded: PendingSlash = bincode::deserialize(&bytes).expect("bincode deser");
    match decoded.status {
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch,
            appeal_count,
        } => {
            assert_eq!(first_appeal_filed_epoch, 17);
            assert_eq!(appeal_count, 3);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

/// DSL-161 row 3: `Reverted { winning_appeal_hash, reverted_at_epoch }` preserves the Bytes32 hash AND epoch.
///
/// winning_appeal_hash is used by downstream analytics to correlate reverts to specific appeal attempts — byte-exact preservation is non-negotiable.
#[test]
fn test_dsl_161_status_reverted_roundtrip() {
    let winning = Bytes32::new([0xDEu8; 32]);
    let status = PendingSlashStatus::Reverted {
        winning_appeal_hash: winning,
        reverted_at_epoch: 28,
    };
    assert_bincode_roundtrip_status(status);

    let ps = sample_pending(status, vec![]);
    let bytes = bincode::serialize(&ps).expect("bincode ser");
    let decoded: PendingSlash = bincode::deserialize(&bytes).expect("bincode deser");
    match decoded.status {
        PendingSlashStatus::Reverted {
            winning_appeal_hash,
            reverted_at_epoch,
        } => {
            assert_eq!(winning_appeal_hash, winning);
            assert_eq!(reverted_at_epoch, 28);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

/// DSL-161 row 4: `Finalised { finalised_at_epoch }` preserves the
/// single u64 field.
#[test]
fn test_dsl_161_status_finalised_roundtrip() {
    let status = PendingSlashStatus::Finalised {
        finalised_at_epoch: 33,
    };
    assert_bincode_roundtrip_status(status);

    let ps = sample_pending(status, vec![]);
    let bytes = bincode::serialize(&ps).expect("bincode ser");
    let decoded: PendingSlash = bincode::deserialize(&bytes).expect("bincode deser");
    match decoded.status {
        PendingSlashStatus::Finalised { finalised_at_epoch } => {
            assert_eq!(finalised_at_epoch, 33);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

/// DSL-161 row 5: `AppealAttempt` with each `AppealOutcome` variant
/// roundtrips. Covers Won (unit), Lost (struct with reason_hash),
/// Pending (unit).
///
/// Exercised both standalone AND nested inside the
/// PendingSlash.appeal_history vec — proves the Vec<AppealAttempt>
/// serde shape is stable across multiple outcome variants in the
/// same vec (no ordering drift, no variant-discriminant coupling).
#[test]
fn test_dsl_161_appeal_attempt_won_lost_pending() {
    let reason = Bytes32::new([0xCCu8; 32]);

    let attempts = vec![
        AppealAttempt {
            appeal_hash: Bytes32::new([0x11u8; 32]),
            appellant_index: 42,
            filed_epoch: 17,
            outcome: AppealOutcome::Won,
            bond_mojos: 500_000_000,
        },
        AppealAttempt {
            appeal_hash: Bytes32::new([0x22u8; 32]),
            appellant_index: 43,
            filed_epoch: 18,
            outcome: AppealOutcome::Lost {
                reason_hash: reason,
            },
            bond_mojos: 500_000_001,
        },
        AppealAttempt {
            appeal_hash: Bytes32::new([0x33u8; 32]),
            appellant_index: 44,
            filed_epoch: 19,
            outcome: AppealOutcome::Pending,
            bond_mojos: 500_000_002,
        },
    ];

    // Standalone: each attempt roundtrips byte-exact.
    for a in &attempts {
        let bytes = bincode::serialize(a).expect("bincode ser");
        let decoded: AppealAttempt = bincode::deserialize(&bytes).expect("bincode deser");
        assert_eq!(*a, decoded);
    }

    // Nested in PendingSlash.appeal_history — mixed-variant vec.
    let ps = sample_pending(PendingSlashStatus::Accepted, attempts.clone());
    let bytes = bincode::serialize(&ps).expect("bincode ser");
    let decoded: PendingSlash = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(
        decoded.appeal_history, attempts,
        "mixed-outcome appeal_history vec survives bincode verbatim",
    );

    // Spot-check Lost reason_hash survived — guards against struct-
    // variant payload drop.
    match decoded.appeal_history[1].outcome {
        AppealOutcome::Lost { reason_hash } => assert_eq!(reason_hash, reason),
        other => panic!("wrong variant: {other:?}"),
    }
}

/// DSL-161 row 6: full PendingSlash tree (evidence + verified +
/// status + per_validator + history) preserved.
///
/// Builds the deepest realistic fixture: evidence with signed
/// headers, verified evidence with indices, ChallengeOpen status,
/// per-validator slash vec, AND two appeal attempts (Won + Lost)
/// in history. Post-roundtrip equality asserts zero drift at ANY
/// level of the nesting.
#[test]
fn test_dsl_161_pending_slash_full_tree() {
    let history = vec![
        AppealAttempt {
            appeal_hash: Bytes32::new([0x91u8; 32]),
            appellant_index: 100,
            filed_epoch: 18,
            outcome: AppealOutcome::Won,
            bond_mojos: 500_000_000,
        },
        AppealAttempt {
            appeal_hash: Bytes32::new([0x92u8; 32]),
            appellant_index: 101,
            filed_epoch: 19,
            outcome: AppealOutcome::Lost {
                reason_hash: Bytes32::new([0x93u8; 32]),
            },
            bond_mojos: 500_000_001,
        },
    ];
    let original = sample_pending(
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch: 18,
            appeal_count: 2,
        },
        history.clone(),
    );

    let bytes = bincode::serialize(&original).expect("bincode ser");
    let decoded: PendingSlash = bincode::deserialize(&bytes).expect("bincode deser");

    assert_eq!(
        original, decoded,
        "full PendingSlash tree survives bincode byte-exact",
    );
    // Spot checks at each nesting level so any single-field drift
    // surfaces with a descriptive message rather than just a top-
    // level struct-eq diff.
    assert_eq!(decoded.evidence_hash, original.evidence_hash);
    assert_eq!(decoded.evidence, original.evidence);
    assert_eq!(decoded.verified, original.verified);
    assert_eq!(
        decoded.base_slash_per_validator,
        original.base_slash_per_validator
    );
    assert_eq!(decoded.appeal_history, history);
}
