//! Requirement DSL-143: `JustificationView` full 5-method
//! contract.
//!
//!   - `latest_finalized_epoch` — DSL-127 minimum (finality-
//!     stall derivation).
//!   - `current_justified_checkpoint` / `previous_justified_checkpoint`
//!     — DSL-075 source-justified check.
//!   - `finalized_checkpoint` — DSL-076 target-canonical.
//!   - `canonical_block_root_at_slot` — DSL-076/077 head check;
//!     `None` past chain tip.
//!   - `canonical_target_root_for_epoch` — DSL-076 target root;
//!     `None` past chain tip.
//!
//! Traces to: docs/resources/SPEC.md §15.3.
//!
//! # Role
//!
//! Consumed by appeal verifiers that need fork-choice
//! visibility: DSL-075 source-justified, DSL-076 head + target
//! canonical, DSL-077 timeliness. DSL-127 touches the surface
//! via `latest_finalized_epoch` alone; default impls keep
//! DSL-127 fixtures working with a minimal one-method override
//! (demonstrated by existing dsl_127_epoch_boundary_order_test).
//!
//! # Test matrix (maps to DSL-143 Test Plan + acceptance)
//!
//!   1. `test_dsl_143_checkpoints_return_data` — all three
//!      checkpoint accessors return structured data
//!   2. `test_dsl_143_canonical_block_root_committed` — known
//!      slot returns Some(root)
//!   3. `test_dsl_143_canonical_block_root_future` — future
//!      slot returns None
//!   4. `test_dsl_143_canonical_target_root_past_tip` — epoch
//!      past tip returns None
//!   5. `test_dsl_143_read_only` — repeated calls return the
//!      same values; no internal mutation

use std::collections::HashMap;

use dig_protocol::Bytes32;
use dig_slashing::{Checkpoint, JustificationView};

/// Full reference impl. Backing tables map slot → root and
/// epoch → target_root so the `None`-past-tip contract can
/// be exercised explicitly.
struct FullJustification {
    latest_finalized: u64,
    current_just: Checkpoint,
    previous_just: Checkpoint,
    finalized: Checkpoint,
    block_roots: HashMap<u64, Bytes32>,
    target_roots: HashMap<u64, Bytes32>,
    /// Highest committed slot; reads past this return None.
    chain_tip_slot: u64,
    /// Highest committed epoch; reads past this return None.
    chain_tip_epoch: u64,
}

impl JustificationView for FullJustification {
    fn latest_finalized_epoch(&self) -> u64 {
        self.latest_finalized
    }
    fn current_justified_checkpoint(&self) -> Checkpoint {
        self.current_just
    }
    fn previous_justified_checkpoint(&self) -> Checkpoint {
        self.previous_just
    }
    fn finalized_checkpoint(&self) -> Checkpoint {
        self.finalized
    }
    fn canonical_block_root_at_slot(&self, slot: u64) -> Option<Bytes32> {
        if slot > self.chain_tip_slot {
            return None;
        }
        self.block_roots.get(&slot).copied()
    }
    fn canonical_target_root_for_epoch(&self, epoch: u64) -> Option<Bytes32> {
        if epoch > self.chain_tip_epoch {
            return None;
        }
        self.target_roots.get(&epoch).copied()
    }
}

fn fixture() -> FullJustification {
    let mut block_roots = HashMap::new();
    block_roots.insert(10, Bytes32::new([0xAAu8; 32]));
    block_roots.insert(20, Bytes32::new([0xBBu8; 32]));

    let mut target_roots = HashMap::new();
    target_roots.insert(1, Bytes32::new([0x11u8; 32]));
    target_roots.insert(2, Bytes32::new([0x22u8; 32]));

    FullJustification {
        latest_finalized: 2,
        current_just: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0xC1u8; 32]),
        },
        previous_just: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0xC0u8; 32]),
        },
        finalized: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0xF0u8; 32]),
        },
        block_roots,
        target_roots,
        chain_tip_slot: 20,
        chain_tip_epoch: 2,
    }
}

/// DSL-143 row 1: all three checkpoint accessors return
/// structured `Checkpoint { epoch, root }` data.
#[test]
fn test_dsl_143_checkpoints_return_data() {
    let jv = fixture();

    let cur = jv.current_justified_checkpoint();
    assert_eq!(cur.epoch, 3);
    assert_eq!(cur.root, Bytes32::new([0xC1u8; 32]));

    let prev = jv.previous_justified_checkpoint();
    assert_eq!(prev.epoch, 2);
    assert_eq!(prev.root, Bytes32::new([0xC0u8; 32]));

    let fin = jv.finalized_checkpoint();
    assert_eq!(fin.epoch, 2);
    assert_eq!(fin.root, Bytes32::new([0xF0u8; 32]));
    // Consistency: finalized_checkpoint.epoch == latest_finalized_epoch.
    assert_eq!(fin.epoch, jv.latest_finalized_epoch());
}

/// DSL-143 row 2: committed slot returns Some(root).
#[test]
fn test_dsl_143_canonical_block_root_committed() {
    let jv = fixture();
    assert_eq!(
        jv.canonical_block_root_at_slot(10),
        Some(Bytes32::new([0xAAu8; 32])),
    );
    assert_eq!(
        jv.canonical_block_root_at_slot(20),
        Some(Bytes32::new([0xBBu8; 32])),
    );
    // Known-slot-without-root (e.g., skipped slot) returns None
    // by the mock's lookup-table absence. Still within chain tip.
    assert!(jv.canonical_block_root_at_slot(15).is_none());
}

/// DSL-143 row 3: slot past chain tip returns None.
#[test]
fn test_dsl_143_canonical_block_root_future() {
    let jv = fixture();
    assert!(
        jv.canonical_block_root_at_slot(21).is_none(),
        "one past tip",
    );
    assert!(jv.canonical_block_root_at_slot(1_000_000).is_none());
    assert!(jv.canonical_block_root_at_slot(u64::MAX).is_none());
}

/// DSL-143 row 4: epoch past chain tip returns None.
#[test]
fn test_dsl_143_canonical_target_root_past_tip() {
    let jv = fixture();
    assert_eq!(
        jv.canonical_target_root_for_epoch(1),
        Some(Bytes32::new([0x11u8; 32])),
    );
    assert_eq!(
        jv.canonical_target_root_for_epoch(2),
        Some(Bytes32::new([0x22u8; 32])),
    );
    assert!(jv.canonical_target_root_for_epoch(3).is_none(), "past tip");
    assert!(jv.canonical_target_root_for_epoch(u64::MAX).is_none());
}

/// DSL-143 row 5: read-only invariance. Repeated calls yield
/// the same values.
#[test]
fn test_dsl_143_read_only() {
    let jv = fixture();
    let finalized_first = jv.finalized_checkpoint();
    for _ in 0..10 {
        assert_eq!(jv.finalized_checkpoint(), finalized_first);
        assert_eq!(jv.latest_finalized_epoch(), 2);
    }
}

/// Bonus: the DEFAULT impls are observable on a minimal impl
/// that overrides ONLY `latest_finalized_epoch` — proves the
/// DSL-127 backward-compat story holds (old one-method fixtures
/// still work).
#[test]
fn test_dsl_143_defaults_when_only_finalized_epoch_implemented() {
    struct Minimal;
    impl JustificationView for Minimal {
        fn latest_finalized_epoch(&self) -> u64 {
            5
        }
        // All other methods use defaults.
    }

    let m = Minimal;
    assert_eq!(m.latest_finalized_epoch(), 5);
    // Default: finalized_checkpoint.epoch delegates to
    // latest_finalized_epoch; root is zero.
    let fin = m.finalized_checkpoint();
    assert_eq!(fin.epoch, 5);
    assert_eq!(fin.root, Bytes32::new([0u8; 32]));
    // Default: zero-checkpoint for current/previous justified.
    assert_eq!(m.current_justified_checkpoint().epoch, 0);
    assert_eq!(m.previous_justified_checkpoint().epoch, 0);
    // Default: None for both root queries.
    assert!(m.canonical_block_root_at_slot(0).is_none());
    assert!(m.canonical_target_root_for_epoch(0).is_none());
}
