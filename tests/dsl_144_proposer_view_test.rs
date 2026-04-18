//! Requirement DSL-144: `ProposerView::proposer_at_slot(slot)`
//! returns `Some(idx)` for committed slots with an assigned
//! proposer, `None` otherwise (future, missed, or uncommitted).
//! `current_slot()` is the current L2 slot and advances
//! monotonically.
//!
//! Traces to: docs/resources/SPEC.md §15.3.
//!
//! # Role
//!
//! DSL-025 submit_evidence looks up the proposer at
//! `current_slot()` to route the proposer-inclusion reward.
//! The `None` branches (future + missed + uncommitted) collapse
//! into a uniform "skip reward" path at the caller — the trait
//! doesn't distinguish them.
//!
//! # Test matrix (maps to DSL-144 Test Plan + acceptance)
//!
//!   1. `test_dsl_144_committed_some` — past slot with
//!      assigned proposer → Some(idx)
//!   2. `test_dsl_144_future_none` — slot > current_slot →
//!      None
//!   3. `test_dsl_144_missed_slot_none` — slot <= current with
//!      no proposer → None
//!   4. `test_dsl_144_current_slot_monotonic` — advance mock
//!      clock → `current_slot()` increases
//!   5. `test_dsl_144_boundary_current_slot_committed` —
//!      `slot == current_slot()` (the just-committed slot)
//!      returns Some when the proposer is assigned

use std::cell::Cell;
use std::collections::HashMap;

use dig_slashing::ProposerView;

struct MockProposer {
    /// slot → proposer validator index (missing slot = missed).
    proposers: HashMap<u64, u32>,
    /// Current L2 slot. Cell<u64> so advance() can mutate
    /// through `&self` in tests.
    current: Cell<u64>,
}

impl MockProposer {
    fn new(current: u64) -> Self {
        Self {
            proposers: HashMap::new(),
            current: Cell::new(current),
        }
    }
    fn assign(&mut self, slot: u64, proposer: u32) {
        self.proposers.insert(slot, proposer);
    }
    fn advance(&self, to: u64) {
        assert!(to >= self.current.get(), "monotonic advance only");
        self.current.set(to);
    }
}

impl ProposerView for MockProposer {
    fn proposer_at_slot(&self, slot: u64) -> Option<u32> {
        // Future: past the chain tip → None per SPEC §15.3.
        if slot > self.current.get() {
            return None;
        }
        self.proposers.get(&slot).copied()
    }
    fn current_slot(&self) -> u64 {
        self.current.get()
    }
}

/// DSL-144 row 1: committed past slot with proposer → Some.
#[test]
fn test_dsl_144_committed_some() {
    let mut p = MockProposer::new(100);
    p.assign(50, 7);
    p.assign(51, 8);

    assert_eq!(p.proposer_at_slot(50), Some(7));
    assert_eq!(p.proposer_at_slot(51), Some(8));
}

/// DSL-144 row 2: future slot (beyond current_slot) → None.
#[test]
fn test_dsl_144_future_none() {
    let p = MockProposer::new(100);
    assert!(p.proposer_at_slot(101).is_none(), "one past tip");
    assert!(p.proposer_at_slot(1_000_000).is_none());
    assert!(p.proposer_at_slot(u64::MAX).is_none());
}

/// DSL-144 row 3: missed slot (past, no proposer assigned) →
/// None. Indistinguishable from future at the trait level —
/// DSL-025 caller treats both as "skip proposer reward".
#[test]
fn test_dsl_144_missed_slot_none() {
    let mut p = MockProposer::new(100);
    p.assign(50, 7);
    // Slots 51..=99 never assigned.
    for slot in 51u64..=99 {
        assert!(
            p.proposer_at_slot(slot).is_none(),
            "missed slot {slot} is None",
        );
    }
    // And slot 50 still has its proposer.
    assert_eq!(p.proposer_at_slot(50), Some(7));
}

/// DSL-144 row 4: current_slot advances monotonically.
#[test]
fn test_dsl_144_current_slot_monotonic() {
    let p = MockProposer::new(0);
    assert_eq!(p.current_slot(), 0);

    for target in [1u64, 5, 10, 100, 1_000_000] {
        p.advance(target);
        assert_eq!(p.current_slot(), target);
    }
}

/// DSL-144 boundary: slot == current_slot returns Some when
/// proposer is assigned. Verifies the future-cutoff uses
/// strict `>` (exclusive past-tip), not `>=`. DSL-025 typically
/// queries the just-committed slot, so this equality case is
/// load-bearing.
#[test]
fn test_dsl_144_boundary_current_slot_committed() {
    let mut p = MockProposer::new(100);
    p.assign(100, 42);
    assert_eq!(
        p.proposer_at_slot(100),
        Some(42),
        "slot == current_slot is INCLUSIVE (strict `>` for future)",
    );
}
