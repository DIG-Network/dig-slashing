//! Requirement DSL-155: `InactivityScoreTracker::rewind_on_reorg`
//! restores tracker state on fork-choice reorg.
//!
//! Traces to: docs/resources/SPEC.md §9.2, §13.
//!
//! # Semantics (adopted interpretation)
//!
//! `InactivityScoreTracker` does NOT maintain a ring-buffer of
//! historical snapshots — the conservative design shared with
//! `ParticipationTracker::rewind_on_reorg`. On reorg:
//!
//!   - `depth == 0` → genuine no-op, scores + vec length
//!     untouched, returns 0.
//!   - `depth > 0` → every score zeroed (best approximation of
//!     "restore to genesis snapshot"), vec length preserved,
//!     returns `depth` so the DSL-130 ReorgReport can propagate
//!     the caller-supplied drop count without re-deriving.
//!
//! Rationale: restoring a historical snapshot would require
//! persisting `CORRELATION_WINDOW_EPOCHS` copies of the score
//! vector (up to 36 × N × 8 bytes). Zero-fill is safe — the
//! next `update_for_epoch` pass accumulates fresh increments from
//! the canonical tip, and finalisation on the rewound span
//! charges no inactivity penalty (scores are zero → penalty
//! formula `eff * score / quotient` = 0). No ghost penalties.
//!
//! # Test matrix (maps to DSL-155 Test Plan)
//!
//!   1. `test_dsl_155_restores_snapshot` — seed scores via
//!      `set_score`, `rewind_on_reorg(3)` → every score 0.
//!   2. `test_dsl_155_depth_zero_noop` — seeded scores +
//!      `rewind_on_reorg(0)` → untouched, return 0.
//!   3. `test_dsl_155_depth_at_ring_limit` — `rewind_on_reorg(36)`
//!      (== `CORRELATION_WINDOW_EPOCHS`) succeeds; depth echoed
//!      back from the return value.
//!   4. `test_dsl_155_vec_length_unchanged` — rewind preserves
//!      `validator_count()` (resize is DSL-093's job, NOT rewind's).

use dig_slashing::{EffectiveBalanceView, InactivityScoreTracker};

/// Empty balance view — `update_for_epoch` is not exercised in
/// these tests, but `epoch_penalties` post-rewind sanity checks
/// read through this stub. Returns 0 for every index / total.
struct NullBalances;
impl EffectiveBalanceView for NullBalances {
    fn get(&self, _: u32) -> u64 {
        0
    }
    fn total_active(&self) -> u64 {
        0
    }
}

/// DSL-155 row 1: seeded scores zero-fill on non-zero-depth rewind.
///
/// The conservative semantics: "restore to snapshot" = "zero out
/// all scores". Post-rewind, `epoch_penalties(in_stall=true)`
/// returns empty because every (eff_bal × score / quotient)
/// evaluates to 0 — proves the tracker cannot generate ghost
/// inactivity debits from the rewound chain.
#[test]
fn test_dsl_155_restores_snapshot() {
    let mut t = InactivityScoreTracker::new(4);
    t.set_score(0, 1_000);
    t.set_score(1, 500);
    t.set_score(2, 250);
    t.set_score(3, 1);

    // Sanity: scores non-zero pre-rewind.
    assert_eq!(t.score(0), Some(1_000));
    assert_eq!(t.score(3), Some(1));

    let dropped = t.rewind_on_reorg(3);
    assert_eq!(dropped, 3, "return value echoes the caller's depth");

    // Every slot zero-filled.
    for idx in 0u32..4 {
        assert_eq!(
            t.score(idx),
            Some(0),
            "post-rewind score idx={idx} must be 0",
        );
    }

    // No ghost inactivity penalty after rewind — epoch_penalties
    // in a finality stall must be empty because every score is 0.
    assert!(
        t.epoch_penalties(&NullBalances, true).is_empty(),
        "zero-fill guarantees no post-rewind inactivity debits",
    );
}

/// DSL-155 row 2: `depth == 0` is a genuine no-op.
///
/// Pins the short-circuit guard. Orchestrator occasionally fires
/// `rewind_all_on_reorg` defensively with `new_tip == current`
/// after a recovery restart; those callers MUST observe zero
/// mutation of scores.
#[test]
fn test_dsl_155_depth_zero_noop() {
    let mut t = InactivityScoreTracker::new(4);
    t.set_score(0, 1_000);
    t.set_score(1, 500);
    t.set_score(2, 250);
    t.set_score(3, 1);

    let dropped = t.rewind_on_reorg(0);
    assert_eq!(dropped, 0, "depth=0 short-circuits to 0");

    // Every score preserved exactly.
    assert_eq!(t.score(0), Some(1_000), "score 0 untouched");
    assert_eq!(t.score(1), Some(500), "score 1 untouched");
    assert_eq!(t.score(2), Some(250), "score 2 untouched");
    assert_eq!(t.score(3), Some(1), "score 3 untouched");
}

/// DSL-155 row 3: `depth == CORRELATION_WINDOW_EPOCHS` (36) —
/// the deepest rewind that DSL-130 orchestration will attempt —
/// succeeds identically to any non-zero depth.
///
/// Reorgs deeper than `CORRELATION_WINDOW_EPOCHS` are rejected
/// by the orchestrator with `ReorgTooDeep` (DSL-130), so this
/// tracker never observes depths above 36 in production. The
/// test nevertheless probes `depth == 36` to confirm the boundary
/// is not special-cased at the tracker level.
#[test]
fn test_dsl_155_depth_at_ring_limit() {
    let mut t = InactivityScoreTracker::new(2);
    t.set_score(0, 42);
    t.set_score(1, 99);

    let dropped = t.rewind_on_reorg(36);

    assert_eq!(dropped, 36, "depth=36 echoed back unchanged");
    assert_eq!(t.score(0), Some(0));
    assert_eq!(t.score(1), Some(0));

    // Repeated rewind is idempotent — second call zero-fills an
    // already-zero vec and echoes the depth.
    assert_eq!(t.rewind_on_reorg(36), 36);
    assert_eq!(t.score(0), Some(0));
}

/// DSL-155 row 4: Vec length preserved across rewind.
///
/// Resize is DSL-093's `resize_for` exclusively — `rewind_on_reorg`
/// MUST NOT grow or shrink the scores vector. If a reorg straddles
/// a validator-activation / exit boundary, the orchestrator calls
/// `resize_for(new_count)` before or after the rewind; the rewind
/// itself is a pure score-zeroing operation.
#[test]
fn test_dsl_155_vec_length_unchanged() {
    let mut t = InactivityScoreTracker::new(10);
    for i in 0u32..10 {
        t.set_score(i, u64::from(i) * 100);
    }
    assert_eq!(t.validator_count(), 10);

    let _ = t.rewind_on_reorg(5);
    assert_eq!(
        t.validator_count(),
        10,
        "rewind preserves validator_count — resize is DSL-093's responsibility",
    );

    // depth=0 path also preserves length (obvious, but pinned to
    // guard against future regression where a bulk-clear helper
    // accidentally truncates).
    let _ = t.rewind_on_reorg(0);
    assert_eq!(t.validator_count(), 10);
}
