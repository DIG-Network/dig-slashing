//! Requirement DSL-146: `PendingSlashBook` basic storage ops.
//!
//!   - `new(capacity)` → empty book.
//!   - `insert(record)` → increments `len()`; `get` returns Some.
//!   - `get(unknown)` → None.
//!   - `remove(hash)` returns the owned record + decrements `len`.
//!   - Insert at capacity → `PendingBookFull` (DSL-027 consumer).
//!
//! Traces to: docs/resources/SPEC.md §7.1.
//!
//! # Role
//!
//! Opens Phase 10 Gap Fills. PendingSlashBook was shipped as a
//! dependency of DSL-024 earlier; DSL-146 pins the basic CRUD
//! contract as a dedicated gate so any future refactor of the
//! internal HashMap/BTreeMap layout cannot drift the observable
//! surface.
//!
//! # Test matrix (maps to DSL-146 Test Plan + acceptance)
//!
//!   1. `test_dsl_146_new_empty` — new(10) → empty + is_empty
//!   2. `test_dsl_146_insert_increments` — insert → len+1 +
//!      get returns Some
//!   3. `test_dsl_146_get_unknown_none` — unknown hash → None
//!   4. `test_dsl_146_remove_returns_record` — insert + remove
//!      returns the owned record; len decrements; subsequent
//!      get returns None
//!   5. `test_dsl_146_insert_at_capacity_rejects` — fills book
//!      then over-fill returns `SlashingError::PendingBookFull`
//!      (DSL-027 interlock)

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealAttempt, BLS_SIGNATURE_SIZE, OffenseType, PendingSlash, PendingSlashBook,
    PendingSlashStatus, PerValidatorSlash, ProposerSlashing, SignedBlockHeader, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, VerifiedEvidence,
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

fn make_pending(hash_byte: u8) -> PendingSlash {
    let evidence_hash = Bytes32::new([hash_byte; 32]);
    PendingSlash {
        evidence_hash,
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
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 15,
        window_expires_at_epoch: 23,
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

/// DSL-146 row 1: fresh book is empty.
#[test]
fn test_dsl_146_new_empty() {
    let book = PendingSlashBook::new(10);
    assert_eq!(book.len(), 0);
    assert!(book.is_empty());
}

/// DSL-146 row 2: insert increments len + get returns Some.
#[test]
fn test_dsl_146_insert_increments() {
    let mut book = PendingSlashBook::new(10);
    let p = make_pending(0x11);
    let hash = p.evidence_hash;

    book.insert(p).expect("insert on empty book");
    assert_eq!(book.len(), 1);
    assert!(!book.is_empty());

    let got = book.get(&hash).expect("get returns Some");
    assert_eq!(got.evidence_hash, hash);
    assert_eq!(got.submitted_at_epoch, 15);
}

/// DSL-146 row 3: unknown hash → None.
#[test]
fn test_dsl_146_get_unknown_none() {
    let book = PendingSlashBook::new(10);
    let unknown = Bytes32::new([0x99u8; 32]);
    assert!(book.get(&unknown).is_none());
    // After inserting one, other hashes still None.
    let mut book = PendingSlashBook::new(10);
    book.insert(make_pending(0x11)).unwrap();
    assert!(book.get(&unknown).is_none());
}

/// DSL-146 row 4: remove returns record; len decrements; post-
/// remove get returns None.
#[test]
fn test_dsl_146_remove_returns_record() {
    let mut book = PendingSlashBook::new(10);
    let p = make_pending(0x22);
    let hash = p.evidence_hash;
    book.insert(p).unwrap();
    assert_eq!(book.len(), 1);

    let removed = book.remove(&hash).expect("remove returns record");
    assert_eq!(removed.evidence_hash, hash);
    assert_eq!(book.len(), 0);
    assert!(book.is_empty());
    assert!(book.get(&hash).is_none(), "post-remove get is None");

    // Double-remove returns None.
    assert!(book.remove(&hash).is_none());
}

/// DSL-146 row 5: insert at capacity → PendingBookFull (DSL-027
/// interlock). Seals the capacity contract so a future change
/// to the storage backend can't silently grow beyond `capacity`.
#[test]
fn test_dsl_146_insert_at_capacity_rejects() {
    let mut book = PendingSlashBook::new(2);
    book.insert(make_pending(0x01)).unwrap();
    book.insert(make_pending(0x02)).unwrap();
    assert_eq!(book.len(), 2);

    // Third insert over capacity rejects.
    let err = book
        .insert(make_pending(0x03))
        .expect_err("over-capacity insert must reject");
    assert!(matches!(err, SlashingError::PendingBookFull));
    assert_eq!(book.len(), 2, "state unchanged on rejected insert");
}
