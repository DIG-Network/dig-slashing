//! Requirement DSL-116: mempool rejects appeals whose target
//! `PendingSlash` is in a terminal status (`Finalised` or
//! `Reverted`). Non-terminal statuses (`Accepted`,
//! `ChallengeOpen`) must admit.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Mempool pre-filter upstream of DSL-060/061 manager-level
//! terminal-state checks. Reuses
//! `SlashingError::SlashAlreadyFinalised` and
//! `SlashingError::SlashAlreadyReverted` rather than a single
//! combined variant so callers can distinguish without string
//! matching.
//!
//! # Test matrix (maps to DSL-116 Test Plan + acceptance)
//!
//!   1. `test_dsl_116_finalised_rejected` — status=Finalised →
//!      SlashAlreadyFinalised
//!   2. `test_dsl_116_reverted_rejected` — status=Reverted →
//!      SlashAlreadyReverted
//!   3. `test_dsl_116_accepted_ok` — status=Accepted admits
//!   4. `test_dsl_116_challenge_open_ok` — status=ChallengeOpen
//!      admits
//!   5. `test_dsl_116_unknown_hash_skipped` — hash absent from
//!      status map skips (DSL-114 owns that rejection)

use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::{
    PendingSlashStatus, ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal,
    SlashAppealPayload, SlashingError, enforce_slash_appeal_terminal_status_policy,
};

fn appeal_for(evidence_hash: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 11,
        appellant_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-116 row 1: Finalised target rejects with the manager-
/// layer variant (DSL-061 parity).
#[test]
fn test_dsl_116_finalised_rejected() {
    let h = Bytes32::new([0x11u8; 32]);
    let mut map = HashMap::new();
    map.insert(
        h,
        PendingSlashStatus::Finalised {
            finalised_at_epoch: 50,
        },
    );

    let ap = appeal_for(h);
    let err = enforce_slash_appeal_terminal_status_policy(&[ap], &map)
        .expect_err("finalised target must reject");
    assert!(
        matches!(err, SlashingError::SlashAlreadyFinalised),
        "variant: {err:?}",
    );
}

/// DSL-116 row 2: Reverted target rejects with the manager-layer
/// variant (DSL-060 parity).
#[test]
fn test_dsl_116_reverted_rejected() {
    let h = Bytes32::new([0x22u8; 32]);
    let mut map = HashMap::new();
    map.insert(
        h,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0x33u8; 32]),
            reverted_at_epoch: 50,
        },
    );

    let ap = appeal_for(h);
    let err = enforce_slash_appeal_terminal_status_policy(&[ap], &map)
        .expect_err("reverted target must reject");
    assert!(
        matches!(err, SlashingError::SlashAlreadyReverted),
        "variant: {err:?}",
    );
}

/// DSL-116 row 3: Accepted admits — no appeals have been filed
/// yet, so this appeal is the first.
#[test]
fn test_dsl_116_accepted_ok() {
    let h = Bytes32::new([0x44u8; 32]);
    let mut map = HashMap::new();
    map.insert(h, PendingSlashStatus::Accepted);

    let ap = appeal_for(h);
    enforce_slash_appeal_terminal_status_policy(&[ap], &map).expect("Accepted target must admit");
}

/// DSL-116 row 4 (acceptance bullet 4): ChallengeOpen admits —
/// window still open, more appeals may arrive up to
/// MAX_APPEAL_ATTEMPTS_PER_SLASH.
#[test]
fn test_dsl_116_challenge_open_ok() {
    let h = Bytes32::new([0x55u8; 32]);
    let mut map = HashMap::new();
    map.insert(
        h,
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch: 10,
            appeal_count: 1,
        },
    );

    let ap = appeal_for(h);
    enforce_slash_appeal_terminal_status_policy(&[ap], &map)
        .expect("ChallengeOpen target must admit");
}

/// Edge: appeal whose hash is absent from the status map skips.
/// DSL-114 owns the unknown-hash rejection; this function must
/// not double-reject or mask DSL-114's error.
#[test]
fn test_dsl_116_unknown_hash_skipped() {
    let known = Bytes32::new([0x66u8; 32]);
    let unknown = Bytes32::new([0x77u8; 32]);
    let mut map = HashMap::new();
    map.insert(known, PendingSlashStatus::Accepted);

    let ap = appeal_for(unknown);
    enforce_slash_appeal_terminal_status_policy(&[ap], &map)
        .expect("unknown-hash appeal is out of scope here");
}
