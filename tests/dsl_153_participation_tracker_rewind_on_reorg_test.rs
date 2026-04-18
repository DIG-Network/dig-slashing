//! Requirement DSL-153: `ParticipationTracker::rewind_on_reorg`
//! restores tracker state on fork-choice reorg.
//!
//! Traces to: docs/resources/SPEC.md §8.2, §13.
//!
//! # Semantics (adopted interpretation)
//!
//! The tracker does NOT maintain a ring-buffer of historical
//! snapshots — each `rotate_epoch` overwrites `previous_epoch` in
//! place. On reorg, `rewind_on_reorg(new_tip_epoch,
//! validator_count)`:
//!
//!   - computes `dropped = saturating_sub(current_epoch_number,
//!     new_tip_epoch)`;
//!   - `dropped == 0` (new_tip at or ahead of current): genuine
//!     no-op — preserves flags + epoch_number untouched;
//!   - `dropped > 0`: zero-fills both `current_epoch` +
//!     `previous_epoch` vectors, resizes to the (possibly new)
//!     `validator_count`, and anchors `current_epoch_number` at
//!     `new_tip_epoch`;
//!   - returns `dropped`.
//!
//! Zero-fill (rather than snapshot restore) is the intentional
//! conservative choice: no historical snapshot storage, no ghost
//! reward credits from a rewound chain. The next post-rewind
//! `compute_flag_deltas` reads zeroed `previous_epoch` and awards
//! no rewards for the rewound span — safe.
//!
//! # Test matrix (maps to DSL-153 Test Plan)
//!
//!   1. `test_dsl_153_restores_snapshot` — flags recorded before
//!      rewind are cleared to the zero-snapshot (genesis equivalent).
//!   2. `test_dsl_153_epoch_number_decrements` — current=10 →
//!      rewind(new_tip=7) → current_epoch_number == 7, dropped == 3.
//!   3. `test_dsl_153_resize_applied` — rewind with larger or smaller
//!      validator_count resizes both flag vecs.
//!   4. `test_dsl_153_depth_zero_noop` — new_tip_epoch ==
//!      current_epoch_number → no state change; return 0.

use dig_slashing::{
    AttestationData, Checkpoint, ParticipationFlags, ParticipationTracker, TIMELY_HEAD_FLAG_INDEX,
    TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX,
};

// ── helpers ────────────────────────────────────────────────────────────

/// Construct an AttestationData — `record_attestation` treats the
/// struct as opaque, only `attesting_indices` + `flags` drive the
/// bit-OR pass.
fn sample_data() -> AttestationData {
    AttestationData {
        slot: 42,
        index: 0,
        beacon_block_root: dig_protocol::Bytes32::new([0x11u8; 32]),
        source: Checkpoint {
            epoch: 1,
            root: dig_protocol::Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 2,
            root: dig_protocol::Bytes32::new([0x33u8; 32]),
        },
    }
}

fn flags_all_three() -> ParticipationFlags {
    let mut f = ParticipationFlags::default();
    f.set(TIMELY_SOURCE_FLAG_INDEX);
    f.set(TIMELY_TARGET_FLAG_INDEX);
    f.set(TIMELY_HEAD_FLAG_INDEX);
    f
}

// ── tests ──────────────────────────────────────────────────────────────

/// DSL-153 row 1: flags recorded prior to rewind are dropped — the
/// tracker re-anchors at the conservative zero-snapshot.
///
/// Exercises the full lifecycle: populate `previous_epoch` via a
/// rotate_epoch after recording, populate `current_epoch` with fresh
/// records, then rewind. Both vectors must come back zero-filled.
#[test]
fn test_dsl_153_restores_snapshot() {
    let mut t = ParticipationTracker::new(8, 0);
    let data = sample_data();

    // Epoch 0: record flags, rotate → previous_epoch carries them.
    t.record_attestation(&data, &[0, 1, 2, 3], flags_all_three())
        .expect("record in range");
    t.rotate_epoch(1, 8);
    // Epoch 1: new records in current_epoch.
    t.record_attestation(&data, &[4, 5], flags_all_three())
        .expect("record idx 4+5");

    // Sanity: flags present before rewind.
    assert_ne!(t.current_flags(5), Some(ParticipationFlags::default()));
    assert_ne!(t.previous_flags(0), Some(ParticipationFlags::default()));

    // Rewind to epoch 0 (dropped=1 from current_epoch_number=1).
    let dropped = t.rewind_on_reorg(0, 8);
    assert_eq!(dropped, 1, "dropped = current - new_tip = 1 - 0 = 1");

    // Every slot zero-filled across BOTH epoch vectors — ghost data
    // from the rewound chain must not leak into post-rewind reward
    // deltas.
    for idx in 0u32..8 {
        assert_eq!(
            t.current_flags(idx),
            Some(ParticipationFlags::default()),
            "current_flags idx={idx} must be zero post-rewind",
        );
        assert_eq!(
            t.previous_flags(idx),
            Some(ParticipationFlags::default()),
            "previous_flags idx={idx} must be zero post-rewind",
        );
    }
}

/// DSL-153 row 2: `current_epoch_number` anchors at `new_tip_epoch`.
///
/// Orchestrator calls this as the participation leg of
/// `rewind_all_on_reorg` — the tracker's notion of the current epoch
/// must track the reorged chain tip exactly so subsequent
/// `rotate_epoch` calls at the new tip use the correct epoch number.
#[test]
fn test_dsl_153_epoch_number_decrements() {
    let mut t = ParticipationTracker::new(4, 10);
    assert_eq!(t.current_epoch_number(), 10);

    let dropped = t.rewind_on_reorg(7, 4);

    assert_eq!(dropped, 3, "dropped = 10 - 7 = 3");
    assert_eq!(
        t.current_epoch_number(),
        7,
        "epoch number anchors at new tip",
    );
}

/// DSL-153 row 3: `validator_count` resize applied on non-no-op
/// rewind. Shrink AND grow paths covered — after a hard fork the
/// active validator set may differ from the rewound epoch's.
#[test]
fn test_dsl_153_resize_applied() {
    // Grow: 4 → 7.
    let mut t = ParticipationTracker::new(4, 5);
    let _ = t.rewind_on_reorg(3, 7);
    assert_eq!(t.validator_count(), 7, "grow resize to 7");
    // All slots (including newly-grown ones 4..7) readable as
    // zero-flags without IndexOutOfRange.
    for idx in 0u32..7 {
        assert_eq!(t.current_flags(idx), Some(ParticipationFlags::default()));
        assert_eq!(t.previous_flags(idx), Some(ParticipationFlags::default()));
    }

    // Shrink: 10 → 3.
    let mut t = ParticipationTracker::new(10, 5);
    let _ = t.rewind_on_reorg(3, 3);
    assert_eq!(t.validator_count(), 3, "shrink resize to 3");
    // Out-of-range indices return None now.
    assert!(t.current_flags(3).is_none(), "idx 3 now out of range");
    assert!(t.current_flags(9).is_none(), "idx 9 now out of range");
}

/// DSL-153 row 4: `depth == 0` (new_tip_epoch at or ahead of
/// current_epoch_number) is a genuine no-op — neither flag vec nor
/// epoch_number are touched.
///
/// This pins the short-circuit guard recently added to
/// `rewind_on_reorg`. Orchestrator occasionally fires the full
/// rewind pipeline defensively with `new_tip == current` after a
/// recovery restart; those callers MUST observe zero mutation.
#[test]
fn test_dsl_153_depth_zero_noop() {
    let mut t = ParticipationTracker::new(4, 10);
    let data = sample_data();

    // Seed both flag vectors so we can detect any mutation.
    t.record_attestation(&data, &[0, 1], flags_all_three())
        .expect("record");
    t.rotate_epoch(11, 4);
    t.record_attestation(&data, &[2, 3], flags_all_three())
        .expect("record");

    // Snapshot pre-rewind state.
    let pre_current: Vec<_> = (0u32..4).map(|i| t.current_flags(i).unwrap()).collect();
    let pre_previous: Vec<_> = (0u32..4).map(|i| t.previous_flags(i).unwrap()).collect();
    let pre_epoch = t.current_epoch_number();

    // new_tip == current_epoch_number → dropped == 0 → short-circuit.
    let dropped = t.rewind_on_reorg(pre_epoch, 4);
    assert_eq!(dropped, 0, "no epochs dropped when tip at current");

    // Post-rewind: every field identical.
    assert_eq!(
        t.current_epoch_number(),
        pre_epoch,
        "epoch number untouched on no-op rewind",
    );
    for idx in 0u32..4 {
        assert_eq!(
            t.current_flags(idx).unwrap(),
            pre_current[idx as usize],
            "current_flags idx={idx} must be unchanged",
        );
        assert_eq!(
            t.previous_flags(idx).unwrap(),
            pre_previous[idx as usize],
            "previous_flags idx={idx} must be unchanged",
        );
    }

    // Also test the "ahead" branch — tip > current still saturates
    // dropped to 0 so short-circuit fires.
    let dropped_ahead = t.rewind_on_reorg(pre_epoch + 5, 4);
    assert_eq!(
        dropped_ahead, 0,
        "tip ahead of current saturates dropped to 0",
    );
    assert_eq!(
        t.current_epoch_number(),
        pre_epoch,
        "epoch number still untouched when tip is ahead",
    );
}
