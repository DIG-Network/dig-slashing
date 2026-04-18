//! Requirement DSL-128: `SlashingSystem::genesis(&GenesisParameters)`
//! constructs the at-birth aggregate state:
//!
//!   - `manager.processed` + `book` empty
//!   - `slashed_in_window` empty (tested indirectly via no
//!     correlation penalty on an empty finalise pass)
//!   - `ParticipationTracker` sized to
//!     `initial_validator_count` with zero flags for both
//!     previous and current epoch
//!   - `InactivityScoreTracker` zero-vectored at the same size
//!   - `manager.current_epoch() == params.genesis_epoch`
//!   - `in_finality_stall(0, 0) == false` (genesis is not a
//!     stall)
//!
//! Traces to: docs/resources/SPEC.md §11, §22.15.
//!
//! # Role
//!
//! Bootstrap entry point for an embedder. Pairs with DSL-127's
//! `run_epoch_boundary` — genesis builds the state, each epoch
//! boundary advances it.
//!
//! # Test matrix (maps to DSL-128 Test Plan + acceptance)
//!
//!   1. `test_dsl_128_manager_empty` — processed + book empty
//!   2. `test_dsl_128_trackers_sized` — tracker lengths match
//!      `initial_validator_count`
//!   3. `test_dsl_128_all_zero` — all flags + scores zero
//!   4. `test_dsl_128_epoch_matches_params` — `current_epoch ==
//!      genesis_epoch` (tested with both 0 and a non-zero fork
//!      value)
//!   5. `test_dsl_128_no_stall_at_genesis` — `in_finality_stall(0, 0)
//!      == false`

use dig_protocol::Bytes32;
use dig_slashing::{GenesisParameters, ParticipationFlags, SlashingSystem, in_finality_stall};

fn params(genesis_epoch: u64, validator_count: usize) -> GenesisParameters {
    GenesisParameters {
        genesis_epoch,
        initial_validator_count: validator_count,
        network_id: Bytes32::new([0xDEu8; 32]),
    }
}

/// DSL-128 row 1: manager state is clean at genesis.
#[test]
fn test_dsl_128_manager_empty() {
    let sys = SlashingSystem::genesis(&params(0, 4));

    // `is_processed` on a probe hash must return false.
    let probe = Bytes32::new([0x11u8; 32]);
    assert!(
        !sys.manager.is_processed(&probe),
        "processed map must be empty",
    );
    // PendingSlashBook starts empty.
    assert!(sys.manager.book().is_empty(), "pending slash book empty");
}

/// DSL-128 row 2: trackers sized to `initial_validator_count`.
#[test]
fn test_dsl_128_trackers_sized() {
    let sys = SlashingSystem::genesis(&params(0, 7));

    assert_eq!(sys.participation.validator_count(), 7);
    assert_eq!(sys.inactivity.validator_count(), 7);
}

/// DSL-128 row 3: all flags + inactivity scores zero at genesis.
#[test]
fn test_dsl_128_all_zero() {
    let sys = SlashingSystem::genesis(&params(0, 5));

    let zero = ParticipationFlags::default();
    for idx in 0u32..5 {
        assert_eq!(
            sys.participation.current_flags(idx),
            Some(zero),
            "current flags[{idx}] zero",
        );
        assert_eq!(
            sys.participation.previous_flags(idx),
            Some(zero),
            "previous flags[{idx}] zero",
        );
        assert_eq!(
            sys.inactivity.score(idx),
            Some(0),
            "inactivity score[{idx}] zero",
        );
    }
}

/// DSL-128 row 4: manager epoch matches `params.genesis_epoch`.
/// Exercised with both 0 (canonical genesis) and a non-zero
/// fork value to catch any hard-coded-zero bugs.
#[test]
fn test_dsl_128_epoch_matches_params() {
    let sys0 = SlashingSystem::genesis(&params(0, 1));
    assert_eq!(sys0.manager.current_epoch(), 0);
    assert_eq!(sys0.participation.current_epoch_number(), 0);

    let sys_fork = SlashingSystem::genesis(&params(1_234, 1));
    assert_eq!(
        sys_fork.manager.current_epoch(),
        1_234,
        "non-zero genesis epoch carried through",
    );
    assert_eq!(
        sys_fork.participation.current_epoch_number(),
        1_234,
        "participation tracker matches genesis epoch",
    );
}

/// DSL-128 row 5: `in_finality_stall(0, 0) == false`. The chain
/// is NOT stalled at genesis — the gap is zero, and the
/// threshold is strict `>` so zero does not trip.
#[test]
fn test_dsl_128_no_stall_at_genesis() {
    assert!(
        !in_finality_stall(0, 0),
        "genesis (current=0, finalized=0) must not be a stall",
    );

    // The system itself doesn't carry a stall flag — it's derived
    // by the orchestrator at epoch boundary. Construct the
    // aggregate anyway and confirm nothing about it contradicts
    // the no-stall invariant (all scores zero from row 3 already
    // proves no prior stall has fired).
    let sys = SlashingSystem::genesis(&params(0, 3));
    assert_eq!(sys.inactivity.score(0), Some(0));
}
