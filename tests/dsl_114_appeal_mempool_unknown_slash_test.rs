//! Requirement DSL-114: `enforce_slash_appeal_mempool_policy`
//! rejects any appeal whose `evidence_hash` is NOT present in
//! the `pending_slashes` set, via `SlashingError::UnknownEvidence`
//! carrying the lowercase-hex rendering of the hash.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Mempool pre-filter upstream of DSL-055 manager-level
//! `UnknownEvidence`. Catching stale-target appeals here avoids
//! bond-lock + BLS work on payloads the manager would reject
//! anyway. Reuses the existing SlashingError variant for a
//! unified error surface across mempool and manager layers —
//! operators see the same string shape from either source.
//!
//! # Test matrix (maps to DSL-114 Test Plan + acceptance)
//!
//!   1. `test_dsl_114_unknown_rejected` — evidence_hash absent
//!      from pending_slashes → UnknownEvidence(hex)
//!   2. `test_dsl_114_known_ok` — evidence_hash present → Ok
//!   3. `test_dsl_114_empty_appeals_ok` — vacuous
//!   4. `test_dsl_114_first_unknown_short_circuits` — mixed
//!      batch halts at the first unknown appeal

use std::collections::HashSet;

use dig_protocol::Bytes32;
use dig_slashing::{
    ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal, SlashAppealPayload, SlashingError,
    enforce_slash_appeal_mempool_policy,
};

fn appeal_for(evidence_hash: Bytes32, appellant_idx: u32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: appellant_idx,
        appellant_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        filed_epoch: 42,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-114 row 1: a hash absent from the pending set rejects
/// with `UnknownEvidence`. Error string is 64 lowercase-hex
/// chars — matches the DSL-055 manager diagnostic for consistent
/// log grep.
#[test]
fn test_dsl_114_unknown_rejected() {
    let known = Bytes32::new([0x11u8; 32]);
    let unknown = Bytes32::new([0x22u8; 32]);

    let mut pending = HashSet::new();
    pending.insert(known);

    let ap = appeal_for(unknown, 11);
    let err =
        enforce_slash_appeal_mempool_policy(&[ap], &pending).expect_err("unknown hash must reject");

    let SlashingError::UnknownEvidence(hex_str) = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(hex_str.len(), 64, "Bytes32 hex is 64 chars (no 0x prefix)");
    assert!(
        hex_str
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "lowercase hex only",
    );
    // The hex of an all-0x22 Bytes32 is 64 '2' chars.
    assert_eq!(hex_str, "2".repeat(64));
}

/// DSL-114 row 2: appeal referencing a known pending hash → Ok.
#[test]
fn test_dsl_114_known_ok() {
    let known = Bytes32::new([0x11u8; 32]);
    let mut pending = HashSet::new();
    pending.insert(known);

    let ap = appeal_for(known, 11);
    enforce_slash_appeal_mempool_policy(&[ap], &pending).expect("known pending hash must admit");
}

/// Edge: empty appeals list. Vacuously Ok regardless of pending
/// set — nothing to check.
#[test]
fn test_dsl_114_empty_appeals_ok() {
    let pending: HashSet<Bytes32> = HashSet::new();
    let appeals: Vec<SlashAppeal> = Vec::new();
    enforce_slash_appeal_mempool_policy(&appeals, &pending).expect("empty admits");
}

/// Bonus: multiple appeals, first is unknown → iteration halts
/// on it, later valid appeals never examined. Proves the error
/// carries the FIRST bad hash's hex.
#[test]
fn test_dsl_114_first_unknown_short_circuits() {
    let known = Bytes32::new([0x11u8; 32]);
    let unknown_first = Bytes32::new([0xABu8; 32]);
    let unknown_later = Bytes32::new([0xCDu8; 32]);

    let mut pending = HashSet::new();
    pending.insert(known);

    let appeals = vec![
        appeal_for(unknown_first, 11),
        appeal_for(known, 12),
        appeal_for(unknown_later, 13),
    ];
    let err = enforce_slash_appeal_mempool_policy(&appeals, &pending).unwrap_err();

    let SlashingError::UnknownEvidence(hex_str) = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(
        hex_str,
        "ab".repeat(32),
        "error carries first unknown's hex; later unknowns not reached",
    );
}
