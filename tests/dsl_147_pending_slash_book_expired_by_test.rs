//! Requirement DSL-147: `PendingSlashBook::expired_by(current)`
//! returns hashes of Accepted + ChallengeOpen entries whose
//! `window_expires_at_epoch < current_epoch`. Results in
//! ascending-by-expiry order (via `by_window_expiry` BTreeMap).
//!
//! Traces to: docs/resources/SPEC.md §7.1.
//!
//! # Role
//!
//! Consumed by DSL-029 `finalise_expired_slashes`. Exclusions:
//!
//!   - boundary `window_expires == current` NOT included
//!     (still in window by convention),
//!   - Reverted / Finalised terminal statuses NOT included
//!     (retained for audit, not re-surfaced).
//!
//! # Test matrix (maps to DSL-147 Test Plan + acceptance)
//!
//!   1. `test_dsl_147_returns_expired` — Accepted record past
//!      window is returned
//!   2. `test_dsl_147_boundary_excluded` — `window_expires ==
//!      current` NOT returned (strict `<` cutoff)
//!   3. `test_dsl_147_reverted_excluded` — Reverted status NOT
//!      returned even if past window
//!   4. `test_dsl_147_finalised_excluded` — Finalised status
//!      NOT returned either (parallel terminal state)
//!   5. `test_dsl_147_deterministic_order` — multiple expired
//!      entries sorted ascending by window_expires
//!   6. `test_dsl_147_empty_book_empty_vec` — degenerate case

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealAttempt, BLS_SIGNATURE_SIZE, OffenseType, PendingSlash, PendingSlashBook,
    PendingSlashStatus, PerValidatorSlash, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, VerifiedEvidence,
};

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

fn make_pending(
    hash_byte: u8,
    window_expires_at_epoch: u64,
    status: PendingSlashStatus,
) -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([hash_byte; 32]),
        evidence: SlashingEvidence {
            offense_type: OffenseType::ProposerEquivocation,
            epoch: 12,
            reporter_validator_index: 11,
            reporter_puzzle_hash: Bytes32::new([0xEEu8; 32]),
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
        submitted_at_epoch: window_expires_at_epoch.saturating_sub(8),
        window_expires_at_epoch,
        base_slash_per_validator: vec![PerValidatorSlash {
            validator_index: 7,
            base_slash_amount: 1_000_000,
            effective_balance_at_slash: 32_000_000_000,
            collateral_slashed: 0,
        }],
        reporter_bond_mojos: 500_000_000,
        appeal_history: Vec::<AppealAttempt>::new(),
    }
}

/// DSL-147 row 1: Accepted record past window is returned.
#[test]
fn test_dsl_147_returns_expired() {
    let mut book = PendingSlashBook::new(10);
    let p = make_pending(0x11, 5, PendingSlashStatus::Accepted);
    let hash = p.evidence_hash;
    book.insert(p).unwrap();

    let expired = book.expired_by(10);
    assert_eq!(expired, vec![hash]);
}

/// DSL-147 row 2: boundary (window_expires == current) is
/// EXCLUDED — strict `<` cutoff per spec.
#[test]
fn test_dsl_147_boundary_excluded() {
    let mut book = PendingSlashBook::new(10);
    book.insert(make_pending(0x22, 10, PendingSlashStatus::Accepted))
        .unwrap();
    let expired = book.expired_by(10);
    assert!(
        expired.is_empty(),
        "window_expires == current → still in window",
    );
    // One epoch later, expiry fires.
    assert_eq!(book.expired_by(11).len(), 1);
}

/// DSL-147 row 3: Reverted status excluded even if past window.
#[test]
fn test_dsl_147_reverted_excluded() {
    let mut book = PendingSlashBook::new(10);
    book.insert(make_pending(
        0x33,
        5,
        PendingSlashStatus::Reverted {
            winning_appeal_hash: Bytes32::new([0xAAu8; 32]),
            reverted_at_epoch: 7,
        },
    ))
    .unwrap();
    let expired = book.expired_by(10);
    assert!(expired.is_empty(), "Reverted status excluded");
}

/// DSL-147 row 4: Finalised status also excluded (parallel
/// terminal state).
#[test]
fn test_dsl_147_finalised_excluded() {
    let mut book = PendingSlashBook::new(10);
    book.insert(make_pending(
        0x44,
        5,
        PendingSlashStatus::Finalised {
            finalised_at_epoch: 6,
        },
    ))
    .unwrap();
    let expired = book.expired_by(10);
    assert!(expired.is_empty(), "Finalised status excluded");
}

/// DSL-147 row 5: deterministic ascending order by
/// window_expires. Insert in reverse order, confirm output is
/// sorted.
#[test]
fn test_dsl_147_deterministic_order() {
    let mut book = PendingSlashBook::new(10);
    // Insert out-of-order: expiries 7, 3, 5.
    let p7 = make_pending(0x70, 7, PendingSlashStatus::Accepted);
    let p3 = make_pending(0x30, 3, PendingSlashStatus::Accepted);
    let p5 = make_pending(0x50, 5, PendingSlashStatus::Accepted);
    let h7 = p7.evidence_hash;
    let h3 = p3.evidence_hash;
    let h5 = p5.evidence_hash;
    book.insert(p7).unwrap();
    book.insert(p3).unwrap();
    book.insert(p5).unwrap();

    let expired = book.expired_by(100);
    assert_eq!(
        expired,
        vec![h3, h5, h7],
        "ascending by window_expires (3 < 5 < 7)",
    );
}

/// DSL-147 row 6: empty book returns empty vec.
#[test]
fn test_dsl_147_empty_book_empty_vec() {
    let book = PendingSlashBook::new(10);
    assert!(book.expired_by(100).is_empty());
    assert!(book.expired_by(0).is_empty());
}

/// Bonus: ChallengeOpen is included (same bucket as Accepted).
/// Distinguishes it from Reverted/Finalised terminal statuses.
#[test]
fn test_dsl_147_challenge_open_included() {
    let mut book = PendingSlashBook::new(10);
    let p = make_pending(
        0x55,
        5,
        PendingSlashStatus::ChallengeOpen {
            first_appeal_filed_epoch: 3,
            appeal_count: 1,
        },
    );
    let hash = p.evidence_hash;
    book.insert(p).unwrap();
    assert_eq!(book.expired_by(10), vec![hash]);
}
