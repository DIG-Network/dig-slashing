//! Requirement DSL-150: `SlashingManager` query + maintenance
//! surface — `is_processed`, `pending`, `prune`.
//!
//! Traces to: docs/resources/SPEC.md §7.2.
//!
//! # Role
//!
//! Pins the three convenience manager methods that callers rely on
//! without reaching through the lower-level `book()` / `processed`
//! accessors:
//!
//!   - `is_processed(hash) -> bool` — the DSL-026 short-circuit
//!     boolean for `AlreadySlashed` detection during admission.
//!   - `pending(hash) -> Option<&PendingSlash>` — a read-side
//!     lens into the pending book without forcing callers to go
//!     through `manager.book().get(hash)`.
//!   - `prune(before_epoch)` — the epoch-boundary maintenance
//!     entry point. Drops `processed` entries whose stored
//!     admission epoch is `< before_epoch` AND
//!     `slashed_in_window` rows whose slash-epoch key is
//!     `< before_epoch`. Leaves `book` untouched — pending slashes
//!     are retired exclusively via `book.remove` /
//!     `finalise_expired_slashes` which own the lifecycle status
//!     transitions (Accepted → Finalised / Reverted).
//!
//! # Test matrix (maps to DSL-150 Test Plan + acceptance)
//!
//!   1. `test_dsl_150_is_processed_known` — `mark_processed` →
//!      `is_processed(hash)` true.
//!   2. `test_dsl_150_is_processed_unknown` — fresh hash, no seed
//!      → false.
//!   3. `test_dsl_150_pending_returns_ref` — insert a
//!      `PendingSlash` via `book_mut()` → `pending(hash)` returns
//!      Some(&PendingSlash) with matching fields; unknown hash
//!      returns None.
//!   4. `test_dsl_150_prune_processed` — seed two processed
//!      entries at epoch 5 and 10, `prune(8)` retains epoch 10
//!      and drops epoch 5 (strict `<` cutoff).
//!   5. `test_dsl_150_prune_window` — seed two
//!      `slashed_in_window` rows at epochs 5 and 10, `prune(8)`
//!      drops epoch 5 and retains epoch 10 (identical cutoff
//!      semantics to the processed map).
//!   6. `test_dsl_150_prune_leaves_book` — seed a pending slash
//!      at submitted_at_epoch 5 whose evidence hash also lives
//!      in `processed`, call `prune(100)` (evicts every
//!      processed entry) and verify `pending(hash)` still
//!      returns Some — the book is NOT touched by prune.

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealAttempt, BLS_SIGNATURE_SIZE, OffenseType, PendingSlash, PendingSlashStatus,
    PerValidatorSlash, ProposerSlashing, SignedBlockHeader, SlashingEvidence,
    SlashingEvidencePayload, SlashingManager, VerifiedEvidence,
};

// ---------------------------------------------------------------
// Test fixtures — mirror DSL-146/147 to keep the PendingSlash
// shape consistent across the Phase 10 manager-level tests.
// ---------------------------------------------------------------

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

/// Build a `PendingSlash` whose `evidence_hash` is the 32-byte
/// constant `[hash_byte; 32]` — gives deterministic distinct
/// hashes across test cases without recomputing content-address
/// digests.
fn make_pending(hash_byte: u8, submitted_at: u64) -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([hash_byte; 32]),
        evidence: SlashingEvidence {
            offense_type: OffenseType::ProposerEquivocation,
            epoch: submitted_at,
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
        submitted_at_epoch: submitted_at,
        window_expires_at_epoch: submitted_at + 8,
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

// ---------------------------------------------------------------
// DSL-150 row 1: is_processed returns true for seeded hashes.
// Relies on `mark_processed` (DSL-128 public seeding helper) so
// we can probe `is_processed` without running the full
// `submit_evidence` pipeline — the DSL under test is purely the
// query surface, not admission.
// ---------------------------------------------------------------
#[test]
fn test_dsl_150_is_processed_known() {
    let mut m = SlashingManager::new(10);
    let hash = Bytes32::new([0xAAu8; 32]);

    m.mark_processed(hash, 10);

    assert!(
        m.is_processed(&hash),
        "is_processed must return true once mark_processed seeds the hash",
    );
}

// ---------------------------------------------------------------
// DSL-150 row 2: unknown hash returns false.
// ---------------------------------------------------------------
#[test]
fn test_dsl_150_is_processed_unknown() {
    let m = SlashingManager::new(10);
    let never_seen = Bytes32::new([0xBBu8; 32]);
    assert!(
        !m.is_processed(&never_seen),
        "empty manager must report false for every probe hash",
    );

    // After seeding a DIFFERENT hash, the original probe still
    // returns false — ensures the underlying HashMap is hash-keyed
    // and not a permissive catch-all.
    let mut m = SlashingManager::new(10);
    let other = Bytes32::new([0xCCu8; 32]);
    m.mark_processed(other, 10);
    assert!(m.is_processed(&other));
    assert!(!m.is_processed(&never_seen));
}

// ---------------------------------------------------------------
// DSL-150 row 3: `pending(hash)` returns `Some(&PendingSlash)`
// for a seeded record and `None` for missing hashes. Shadows
// `manager.book().get(hash)` — the spec-level sugar guaranteed by
// DSL-150.
// ---------------------------------------------------------------
#[test]
fn test_dsl_150_pending_returns_ref() {
    let mut m = SlashingManager::new(10);
    let pending = make_pending(0x33, 10);
    let hash = pending.evidence_hash;

    m.book_mut().insert(pending).expect("book insert");

    // Known hash — Some, fields round-trip.
    let got = m.pending(&hash).expect("pending returns Some for known");
    assert_eq!(got.evidence_hash, hash);
    assert_eq!(got.submitted_at_epoch, 10);
    assert!(matches!(got.status, PendingSlashStatus::Accepted));

    // Unknown hash — None.
    let unknown = Bytes32::new([0x44u8; 32]);
    assert!(
        m.pending(&unknown).is_none(),
        "pending must return None for hashes not in the book",
    );
}

// ---------------------------------------------------------------
// DSL-150 row 4: `prune(before)` drops processed entries whose
// stored epoch is STRICTLY less than `before_epoch`.
//
// Strict `<` is the documented semantics — entries at exactly
// `before_epoch` are retained so callers using
// `prune(current - CORRELATION_WINDOW_EPOCHS)` keep the oldest
// still-relevant cohort.
// ---------------------------------------------------------------
#[test]
fn test_dsl_150_prune_processed() {
    let mut m = SlashingManager::new(20);
    let old_hash = Bytes32::new([0x01u8; 32]);
    let edge_hash = Bytes32::new([0x02u8; 32]);
    let new_hash = Bytes32::new([0x03u8; 32]);

    m.mark_processed(old_hash, 5);
    m.mark_processed(edge_hash, 8);
    m.mark_processed(new_hash, 10);

    m.prune(8);

    assert!(
        !m.is_processed(&old_hash),
        "epoch 5 < cutoff 8 → must be removed",
    );
    assert!(
        m.is_processed(&edge_hash),
        "epoch 8 == cutoff 8 → strict `<` keeps this entry",
    );
    assert!(m.is_processed(&new_hash), "epoch 10 > cutoff → retained",);
}

// ---------------------------------------------------------------
// DSL-150 row 5: `prune(before)` drops `slashed_in_window` rows
// whose epoch key is `< before_epoch`. Symmetric semantics to the
// processed map — the two stores share the DSL-030 correlation
// window cutoff.
// ---------------------------------------------------------------
#[test]
fn test_dsl_150_prune_window() {
    let mut m = SlashingManager::new(20);

    m.mark_slashed_in_window(5, 11, 32_000_000_000);
    m.mark_slashed_in_window(8, 12, 32_000_000_000);
    m.mark_slashed_in_window(10, 13, 32_000_000_000);

    m.prune(8);

    assert!(
        !m.is_slashed_in_window(5, 11),
        "epoch 5 < cutoff 8 → window entry removed",
    );
    assert!(
        m.is_slashed_in_window(8, 12),
        "epoch 8 == cutoff 8 → strict `<` keeps this entry",
    );
    assert!(
        m.is_slashed_in_window(10, 13),
        "epoch 10 > cutoff → retained",
    );
}

// ---------------------------------------------------------------
// DSL-150 row 6: prune leaves the pending book untouched.
//
// Rationale: pending slashes are retired exclusively via
// `book.remove` (appeals) or `finalise_expired_slashes` (window
// expiry) which carry the `status` transition lifecycle. An
// epoch-boundary prune MUST NOT silently evict live pending
// records or appeal / finalisation data would be lost.
//
// We seed a `processed` entry + a matching `PendingSlash` record
// at the same epoch, prune with an aggressive cutoff that
// clears every processed entry, then verify `pending(hash)`
// still returns Some while `is_processed` is now false.
// ---------------------------------------------------------------
#[test]
fn test_dsl_150_prune_leaves_book() {
    let mut m = SlashingManager::new(20);

    let pending = make_pending(0x77, 5);
    let hash = pending.evidence_hash;
    m.book_mut().insert(pending).expect("book insert");
    m.mark_processed(hash, 5);

    assert!(m.is_processed(&hash), "pre-prune sanity");
    assert!(m.pending(&hash).is_some(), "pre-prune pending present");

    // Cutoff 100 >> 5 so every seeded processed entry falls
    // below the cutoff and is evicted.
    m.prune(100);

    assert!(
        !m.is_processed(&hash),
        "processed entry correctly evicted by prune",
    );
    assert!(
        m.pending(&hash).is_some(),
        "book record survives prune — DSL-150 guarantees prune \
         never touches the pending book",
    );
    assert_eq!(
        m.book().len(),
        1,
        "book len unchanged after prune — only processed + \
         slashed_in_window are purged",
    );
}
