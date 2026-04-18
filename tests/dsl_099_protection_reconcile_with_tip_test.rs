//! Requirement DSL-099:
//! `SlashingProtection::reconcile_with_chain_tip(tip_slot, tip_epoch)`
//! composes the proposal rewind (DSL-156) + attestation rewind
//! (DSL-098) under a single entry point. Called on validator
//! startup (rejoin canonical chain after downtime) and after a
//! reorg detected by the orchestration layer (DSL-130).
//!
//! Contract:
//!
//!   1. Proposal watermark capped at `tip_slot` (never raised).
//!   2. Attestation source/target epochs capped at `tip_epoch`
//!      (never raised), block hash cleared unconditionally.
//!   3. Idempotent — calling with the same `(tip_slot, tip_epoch)`
//!      twice leaves state unchanged.
//!   4. Post-reconcile, the surround-vote self-check (DSL-096) no
//!      longer blocks attestations at coordinates the pre-reorg
//!      state would have rejected.
//!
//! Traces to: docs/resources/SPEC.md §14.3, §22.11.
//!
//! # Role
//!
//! Running validators crash, restart, and get fork-choice signals
//! that drop the canonical tip. The local slashing-protection
//! state is a running record of "what I already signed" — after
//! downtime or a reorg, some of those signings now reference
//! blocks that no longer exist on the canonical chain. Without
//! reconcile, the validator would either:
//!
//!   - refuse to re-sign at-or-below its old high-water mark
//!     (pointless self-protection against ghost chains), OR
//!   - silently double-sign if the orchestrator lied about state.
//!
//! Reconcile is the honest path: cap everything at the new tip,
//! erase the hash binding, resume from a clean slate.
//!
//! # Test matrix (maps to DSL-099 Test Plan + contract bullet 4)
//!
//!   1. `test_dsl_099_both_rewound` — record(slot=20, src=5, tgt=7)
//!      + reconcile(10, 3) → slot=10, src=3, tgt=3, hash=None
//!   2. `test_dsl_099_idempotent` — two back-to-back reconcile
//!      calls leave state identical to the first
//!   3. `test_dsl_099_surround_passes_after_reconcile` — pre-
//!      reorg state would reject a candidate via DSL-096; after
//!      reconcile the candidate is accepted
//!   4. `test_dsl_099_already_below_tip_unchanged` — state at-or-
//!      below the new tip must not be uplifted (tip acts as a CAP
//!      only, never as an assignment)

use dig_protocol::Bytes32;
use dig_slashing::SlashingProtection;

/// DSL-099 row 1: both watermarks get lowered in a single call;
/// the block-hash binding clears unconditionally.
///
/// Seeded state:   slot=20, src=5, tgt=7, hash=Some(0x33...)
/// Reconcile(10, 3) → slot=10, src=3 (capped from 5), tgt=3
/// (capped from 7), hash=None.
#[test]
fn test_dsl_099_both_rewound() {
    let mut p = SlashingProtection::new();
    p.record_proposal(20);
    p.record_attestation(5, 7, &Bytes32::new([0x33u8; 32]));

    // Pre-conditions — make sure the seed actually took.
    assert_eq!(p.last_proposed_slot(), 20);
    assert_eq!(p.last_attested_source_epoch(), 5);
    assert_eq!(p.last_attested_target_epoch(), 7);
    assert!(p.last_attested_block_hash().is_some());

    p.reconcile_with_chain_tip(10, 3);

    assert_eq!(
        p.last_proposed_slot(),
        10,
        "proposal slot capped at tip_slot",
    );
    assert_eq!(
        p.last_attested_source_epoch(),
        3,
        "source capped at tip_epoch",
    );
    assert_eq!(
        p.last_attested_target_epoch(),
        3,
        "target capped at tip_epoch",
    );
    assert!(
        p.last_attested_block_hash().is_none(),
        "hash cleared unconditionally on reconcile",
    );
}

/// DSL-099 row 2: idempotence — two reconciles with the same
/// (tip_slot, tip_epoch) arrive at the same state as one. This is
/// what lets the orchestration layer call reconcile defensively on
/// every tip refresh without worrying about cumulative drift.
#[test]
fn test_dsl_099_idempotent() {
    let mut p = SlashingProtection::new();
    p.record_proposal(20);
    p.record_attestation(5, 7, &Bytes32::new([0x44u8; 32]));

    p.reconcile_with_chain_tip(10, 3);
    let after_first = p.clone();

    p.reconcile_with_chain_tip(10, 3);

    // `SlashingProtection` derives PartialEq so whole-struct
    // comparison catches any subtle regressions in any field,
    // including future fields added by later DSLs.
    assert_eq!(
        p, after_first,
        "second reconcile with identical args must be a no-op",
    );
}

/// DSL-099 row 3: the surround self-check (DSL-096) that would have
/// blocked a candidate BEFORE reconcile must allow it AFTER.
///
/// Pre-reorg:  attested (5, 7). Candidate (4, 8) strictly surrounds
/// → DSL-096 rejects.
/// Reorg drops back to epoch 3. Post-reconcile: stored src=3, tgt=3.
/// Candidate (4, 8): source=4 < 3? no → not a surround → accepted.
#[test]
fn test_dsl_099_surround_passes_after_reconcile() {
    let mut p = SlashingProtection::new();
    p.record_attestation(5, 7, &Bytes32::new([0x55u8; 32]));

    let candidate_hash = Bytes32::new([0x66u8; 32]);

    // Pre-reorg: classic surround — (4,8) strictly surrounds (5,7).
    assert!(
        !p.check_attestation(4, 8, &candidate_hash),
        "pre-reconcile: (4,8) surrounds stored (5,7) — DSL-096 rejects",
    );

    // Reorg to epoch 3.
    p.reconcile_with_chain_tip(10, 3);

    // Post-reconcile: stored (3,3). Candidate (4,8). 4 < 3 is false
    // → would_surround false → candidate accepted.
    assert!(
        p.check_attestation(4, 8, &candidate_hash),
        "post-reconcile: (4,8) no longer surrounds stored (3,3)",
    );
}

/// DSL-099 row 4: state already at-or-below the tip must not be
/// raised. `reconcile_with_chain_tip` is a CAP — calling it with a
/// `tip_slot` ABOVE the stored slot must not move the slot up,
/// because moving up would regress the validator's slashing
/// protection to a weaker position.
///
/// The ONLY thing the hash-leg does is clear — that is the
/// accepted cost (DSL-098 rationale): a reconcile always implies
/// the orchestrator is asserting fresh canonical state, and
/// preserving the pre-reconcile hash would mean the next attestation
/// at those coords gets rejected with a phantom double-vote error.
#[test]
fn test_dsl_099_already_below_tip_unchanged() {
    let mut p = SlashingProtection::new();
    p.record_proposal(5);
    p.record_attestation(2, 3, &Bytes32::new([0x77u8; 32]));

    // Reconcile with a tip WELL above current state.
    p.reconcile_with_chain_tip(100, 50);

    assert_eq!(
        p.last_proposed_slot(),
        5,
        "slot ≤ tip_slot must remain — reconcile is a cap, not assign",
    );
    assert_eq!(
        p.last_attested_source_epoch(),
        2,
        "source ≤ tip_epoch remains",
    );
    assert_eq!(
        p.last_attested_target_epoch(),
        3,
        "target ≤ tip_epoch remains",
    );
    // Hash DOES clear — this is DSL-098's documented unconditional
    // clear, called transitively through reconcile.
    assert!(
        p.last_attested_block_hash().is_none(),
        "hash leg clears unconditionally (DSL-098 semantics)",
    );
}
