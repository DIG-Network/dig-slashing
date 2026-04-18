//! Requirement DSL-170: `SlashingSystem` carries the genesis `network_id` in a private field; `SlashingSystem::network_id()` returns a borrow.
//!
//! Traces to: docs/resources/SPEC.md §11.
//!
//! # Role
//!
//! `GenesisParameters::network_id` was previously reserved — stored in the params struct but never propagated to the `SlashingSystem` aggregate. DSL-170 closes that wiring gap so downstream flows (notably DSL-168 `process_block_admissions`) can read the network identity from the aggregate rather than requiring every embedder call site to thread it through a separate argument.
//!
//! # Contract
//!
//! - Construction: `SlashingSystem::genesis(&params)` stores `params.network_id` verbatim on a private field.
//! - Accessor: `pub fn network_id(&self) -> &Bytes32` — borrow with `&self` lifetime.
//! - Shape: `GenesisParameters` unchanged (DSL-128 invariant); `SlashingManager::submit_evidence` signature unchanged (still takes its own `network_id: &Bytes32` arg — embedder passes `sys.network_id()`).
//!
//! # Test matrix (maps to DSL-170 Test Plan)
//!
//!   1. `test_dsl_170_genesis_stores_network_id` — distinctive `[0xAA; 32]` round-trips verbatim through genesis.
//!   2. `test_dsl_170_accessor_returns_reference` — borrow lifetime tied to `&self`; no clone happens.
//!   3. `test_dsl_170_distinct_network_ids` — two systems with different ids keep their ids distinct (no shared static storage).
//!   4. `test_dsl_170_genesis_params_unchanged` — GenesisParameters still constructs with the same 3 public fields in the existing order.

use dig_protocol::Bytes32;
use dig_slashing::{GenesisParameters, SlashingSystem};

// ── tests ──────────────────────────────────────────────────

/// DSL-170 row 1: `genesis` stores `params.network_id` verbatim.
///
/// Uses a distinctive all-`0xAA` pattern so any accidental
/// overwrite (zero-init, partial copy, etc.) surfaces as a
/// byte-level diff rather than a silent equality.
#[test]
fn test_dsl_170_genesis_stores_network_id() {
    let nid = Bytes32::new([0xAAu8; 32]);
    let params = GenesisParameters {
        genesis_epoch: 0,
        initial_validator_count: 4,
        network_id: nid,
    };

    let sys = SlashingSystem::genesis(&params);

    assert_eq!(
        sys.network_id(),
        &nid,
        "network_id round-trips through genesis byte-exact",
    );
    // Sibling invariants from DSL-128 still hold — the added field
    // must not disturb the other genesis post-conditions.
    assert_eq!(sys.manager.current_epoch(), 0);
    assert_eq!(sys.participation.current_epoch_number(), 0);
    assert_eq!(sys.inactivity.validator_count(), 4);
}

/// DSL-170 row 2: accessor returns a borrow with lifetime tied
/// to `&self`.
///
/// The compiler enforces borrow-checker invariants statically; this
/// test exists as a runtime smoke check that dereferencing the
/// borrow yields the expected bytes across multiple calls (no
/// hidden mutation, no race). Also asserts `Bytes32: Copy` is
/// still available so callers that want an owned value can
/// dereference the borrow with `*sys.network_id()`.
#[test]
fn test_dsl_170_accessor_returns_reference() {
    let nid = Bytes32::new([0x42u8; 32]);
    let params = GenesisParameters {
        genesis_epoch: 0,
        initial_validator_count: 0,
        network_id: nid,
    };
    let sys = SlashingSystem::genesis(&params);

    let borrowed_a: &Bytes32 = sys.network_id();
    let borrowed_b: &Bytes32 = sys.network_id();

    // Multiple borrows from the SAME &self reference — both point
    // to the same stable backing storage.
    assert_eq!(borrowed_a, borrowed_b);
    assert_eq!(borrowed_a, &nid);

    // Dereference + copy yields an owned Bytes32 identical to the
    // genesis input (Bytes32 is Copy).
    let owned: Bytes32 = *borrowed_a;
    assert_eq!(owned, nid);
}

/// DSL-170 row 3: two systems with distinct network_ids keep
/// them distinct.
///
/// Rules out any shared-static-storage bug where a secondary
/// SlashingSystem inherits the first's network_id. Each aggregate
/// must own its own private field.
#[test]
fn test_dsl_170_distinct_network_ids() {
    let nid_a = Bytes32::new([0x11u8; 32]);
    let nid_b = Bytes32::new([0x22u8; 32]);

    let sys_a = SlashingSystem::genesis(&GenesisParameters {
        genesis_epoch: 0,
        initial_validator_count: 1,
        network_id: nid_a,
    });
    let sys_b = SlashingSystem::genesis(&GenesisParameters {
        genesis_epoch: 0,
        initial_validator_count: 1,
        network_id: nid_b,
    });

    assert_eq!(sys_a.network_id(), &nid_a);
    assert_eq!(sys_b.network_id(), &nid_b);
    assert_ne!(
        sys_a.network_id(),
        sys_b.network_id(),
        "two systems with distinct genesis params must carry distinct network_ids",
    );
}

/// DSL-170 row 4: `GenesisParameters` shape unchanged.
///
/// Constructor syntax still takes the same three fields in the
/// same positional order. Guards against an accidental refactor
/// that adds / reorders fields on the parameter struct, which
/// would break every existing embedder.
#[test]
fn test_dsl_170_genesis_params_unchanged() {
    // Explicit struct-literal construction exercises the exact
    // three fields — this is a compile-gate as much as a runtime
    // check. If a field disappears or gets renamed, this test
    // fails to compile.
    let params = GenesisParameters {
        genesis_epoch: 100,
        initial_validator_count: 7,
        network_id: Bytes32::new([0x33u8; 32]),
    };

    assert_eq!(params.genesis_epoch, 100);
    assert_eq!(params.initial_validator_count, 7);
    assert_eq!(params.network_id, Bytes32::new([0x33u8; 32]));

    // Derived sanity — genesis consumes without taking ownership
    // of the struct (Clone-derive preserved per DSL-128).
    let _sys1 = SlashingSystem::genesis(&params);
    let _sys2 = SlashingSystem::genesis(&params);
}
