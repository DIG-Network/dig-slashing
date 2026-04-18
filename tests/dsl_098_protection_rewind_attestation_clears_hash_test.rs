//! Requirement DSL-098:
//! `SlashingProtection::rewind_attestation_to_epoch(new_tip_epoch)`
//! is invoked on fork-choice reorg or chain-tip refresh.
//!
//! Contract:
//!
//!   1. `last_attested_block_hash` → `None` (unconditionally).
//!   2. `last_attested_source_epoch` and `last_attested_target_epoch`
//!      capped at `new_tip_epoch` (lowered if greater, untouched
//!      if already ≤).
//!   3. After rewind, a re-attestation on the canonical tip passes
//!      `check_attestation` — the point of the rewind is to free
//!      the validator from its pre-reorg vote.
//!
//! Traces to: docs/resources/SPEC.md §14.3, §22.11.
//!
//! # Role
//!
//! On a reorg, the chain the validator previously attested for is
//! no longer canonical. The stored (source, target, hash) triple
//! becomes a ghost watermark — keeping it would block the validator
//! from attesting on the new tip (DSL-095 would reject any
//! different-hash vote at the stale coords, DSL-096 would reject
//! any flanking surround). Rewind resets the local state to a
//! clean slate at-or-below the new tip so honest re-attestation is
//! possible.
//!
//! Hash is cleared UNCONDITIONALLY — even when `new_tip_epoch` is
//! above the stored target. The hash is tied to a specific block,
//! and a reorg invalidates that block regardless of epoch ordering.
//!
//! # Test matrix (maps to DSL-098 Test Plan + contract bullet 3)
//!
//!   1. `test_dsl_098_hash_cleared` — rewind always sets hash=None
//!   2. `test_dsl_098_epochs_lowered` — record(7,9) + rewind(5) →
//!      src=5, tgt=5
//!   3. `test_dsl_098_already_lower_unchanged` — record(2,3) +
//!      rewind(5) → src=2, tgt=3 (no uplift)
//!   4. `test_dsl_098_reattestation_allowed_after_rewind` — post-
//!      rewind check_attestation on the new tip succeeds (the
//!      point of the whole operation)

use dig_protocol::Bytes32;
use dig_slashing::SlashingProtection;

/// DSL-098 row 1: the hash slot is cleared UNCONDITIONALLY. Tested
/// under three conditions to prove the clear is not gated on epoch
/// ordering:
///   a) `new_tip_epoch` well below the stored epochs,
///   b) `new_tip_epoch` equal to the stored target,
///   c) `new_tip_epoch` above the stored target (reorg that only
///      dropped a late block, not the whole epoch).
/// In every case the hash must go to None.
#[test]
fn test_dsl_098_hash_cleared() {
    let hash = Bytes32::new([0x11u8; 32]);

    // (a) rewind below stored coords.
    let mut p = SlashingProtection::new();
    p.record_attestation(7, 9, &hash);
    p.rewind_attestation_to_epoch(5);
    assert!(
        p.last_attested_block_hash().is_none(),
        "hash cleared when rewind target is below stored epochs",
    );

    // (b) rewind to exactly the stored target.
    let mut p = SlashingProtection::new();
    p.record_attestation(7, 9, &hash);
    p.rewind_attestation_to_epoch(9);
    assert!(
        p.last_attested_block_hash().is_none(),
        "hash cleared when rewind target equals stored target",
    );

    // (c) rewind above stored coords.
    let mut p = SlashingProtection::new();
    p.record_attestation(7, 9, &hash);
    p.rewind_attestation_to_epoch(20);
    assert!(
        p.last_attested_block_hash().is_none(),
        "hash cleared even when rewind target exceeds stored epochs",
    );
}

/// DSL-098 row 2: both epochs strictly above `new_tip_epoch` are
/// lowered to `new_tip_epoch`. Neither is lowered to 0 or any other
/// value — the cap is always the tip itself, because anything lower
/// would throw away valid monotonic progress.
#[test]
fn test_dsl_098_epochs_lowered() {
    let mut p = SlashingProtection::new();
    p.record_attestation(7, 9, &Bytes32::new([0x22u8; 32]));

    p.rewind_attestation_to_epoch(5);

    assert_eq!(
        p.last_attested_source_epoch(),
        5,
        "source > tip → capped to tip",
    );
    assert_eq!(
        p.last_attested_target_epoch(),
        5,
        "target > tip → capped to tip",
    );
}

/// DSL-098 row 3: epochs already ≤ `new_tip_epoch` must NOT be
/// raised. The method is a CAP, not an assignment — raising would
/// open the door to regressed monotonic state (the validator would
/// think it attested later than it actually did, blocking legit
/// future attestations via DSL-096 surround check).
///
/// Also covers the mixed case: source ≤ tip, target > tip. Source
/// stays, target gets capped — the two legs are independent.
#[test]
fn test_dsl_098_already_lower_unchanged() {
    // Both below tip — neither changes.
    let mut p = SlashingProtection::new();
    p.record_attestation(2, 3, &Bytes32::new([0x33u8; 32]));
    p.rewind_attestation_to_epoch(5);
    assert_eq!(p.last_attested_source_epoch(), 2, "source ≤ tip unchanged");
    assert_eq!(p.last_attested_target_epoch(), 3, "target ≤ tip unchanged");

    // Mixed — source stays, target caps. Proves each leg is guarded
    // independently.
    let mut p = SlashingProtection::new();
    p.record_attestation(2, 9, &Bytes32::new([0x44u8; 32]));
    p.rewind_attestation_to_epoch(5);
    assert_eq!(p.last_attested_source_epoch(), 2, "source ≤ tip unchanged");
    assert_eq!(p.last_attested_target_epoch(), 5, "target > tip → capped");

    // Target exactly equal to tip — boundary, NOT a strict-greater
    // case, must stay put.
    let mut p = SlashingProtection::new();
    p.record_attestation(1, 5, &Bytes32::new([0x55u8; 32]));
    p.rewind_attestation_to_epoch(5);
    assert_eq!(p.last_attested_source_epoch(), 1);
    assert_eq!(
        p.last_attested_target_epoch(),
        5,
        "target == tip is the boundary; rewind uses `>` not `>=`",
    );
}

/// Contract bullet 3: after rewind the validator can re-attest on
/// the new canonical tip. This is the whole point of the operation
/// — without it rewind would be a cosmetic no-op.
///
/// Pre-reorg: validator attested (7, 9, hash_a). Reorg drops that
/// chain back to epoch 5. Post-rewind, the validator attests
/// (5, 6, hash_b) on the new tip. `check_attestation` must return
/// true because:
///
///   - DSL-096: candidate_source=5 < 5 is false → not a surround
///   - DSL-095: (5,6) != stored (5,5) after rewind → no coord match
///   - hash=None means the DSL-095 same-coord branch can't match
///     anyway
#[test]
fn test_dsl_098_reattestation_allowed_after_rewind() {
    let mut p = SlashingProtection::new();
    let hash_a = Bytes32::new([0x66u8; 32]);
    p.record_attestation(7, 9, &hash_a);

    // Reorg drops the tip to epoch 5.
    p.rewind_attestation_to_epoch(5);

    // Re-attestation on the new tip with a DIFFERENT block.
    let hash_b = Bytes32::new([0x77u8; 32]);
    assert!(
        p.check_attestation(5, 6, &hash_b),
        "post-rewind check_attestation must allow re-attesting on \
         the canonical tip",
    );

    // And recording that re-attestation updates state cleanly.
    p.record_attestation(5, 6, &hash_b);
    assert_eq!(p.last_attested_source_epoch(), 5);
    assert_eq!(p.last_attested_target_epoch(), 6);
    assert!(p.last_attested_block_hash().is_some());
}
