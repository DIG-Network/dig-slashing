//! Requirement DSL-125: `APPELLANT_BOND_MOJOS` equals
//! `MIN_EFFECTIVE_BALANCE / 64` and equals `REPORTER_BOND_MOJOS`
//! for symmetric economic pressure.
//!
//! Traces to: docs/resources/SPEC.md §2.6, §22.14.
//!
//! # Role
//!
//! Dedicated constant-pin test. DSL-062 already exercises
//! `submit_appeal` with the BondEscrow lock call; DSL-125 pins
//! the constant invariants so a future constants refactor cannot
//! drift the value or break symmetry with the reporter side
//! without the gate firing.
//!
//! # Why symmetry with reporter
//!
//! Reporter and appellant both risk their bond in an adversarial
//! challenge: a reporter whose evidence is sustained-appealed
//! loses the reporter bond; an appellant whose appeal is rejected
//! loses the appellant bond. Equal bond sizes = equal grief-vector
//! costs = neutral economic pressure. Breaking symmetry would
//! create a strictly dominant strategy on one side.
//!
//! # Test matrix (maps to DSL-125 Test Plan + acceptance)
//!
//!   1. `test_dsl_125_value_is_min_div_64` — exact arithmetic
//!   2. `test_dsl_125_exact_divides` — no truncation
//!   3. `test_dsl_125_equal_to_reporter` — symmetry invariant
//!   4. `test_dsl_125_not_runtime_configurable` — compile-time
//!      const assertion

use dig_slashing::{APPELLANT_BOND_MOJOS, MIN_EFFECTIVE_BALANCE, REPORTER_BOND_MOJOS};

/// DSL-125 row 1: exact value equality to `MIN / 64`.
#[test]
fn test_dsl_125_value_is_min_div_64() {
    assert_eq!(
        APPELLANT_BOND_MOJOS,
        MIN_EFFECTIVE_BALANCE / 64,
        "APPELLANT_BOND_MOJOS must equal MIN_EFFECTIVE_BALANCE / 64",
    );
    assert_eq!(
        APPELLANT_BOND_MOJOS, 500_000_000,
        "numeric pin against MIN_EFFECTIVE_BALANCE = 32_000_000_000",
    );
}

/// DSL-125 row 2: integer division is exact (same divisor as
/// DSL-124, so the same no-truncation invariant applies).
#[test]
fn test_dsl_125_exact_divides() {
    assert_eq!(
        APPELLANT_BOND_MOJOS * 64,
        MIN_EFFECTIVE_BALANCE,
        "MIN / 64 * 64 must reconstruct MIN without truncation",
    );
}

/// DSL-125 row 3: symmetry invariant. REPORTER_BOND_MOJOS and
/// APPELLANT_BOND_MOJOS MUST match; any drift breaks the neutral
/// grief-cost assumption embedded in SPEC §2.6.
#[test]
fn test_dsl_125_equal_to_reporter() {
    assert_eq!(
        APPELLANT_BOND_MOJOS, REPORTER_BOND_MOJOS,
        "reporter + appellant bonds must be equal for symmetric economic pressure",
    );
}

/// DSL-125 row 4: compile-time-fixed value (any future move to
/// OnceLock / static mut fails to compile here).
#[test]
fn test_dsl_125_not_runtime_configurable() {
    const _CONST_CHECK: u64 = APPELLANT_BOND_MOJOS;
    const _DERIVED: u64 = MIN_EFFECTIVE_BALANCE / 64;
    const _: () = assert!(_CONST_CHECK == _DERIVED);
    assert_eq!(_CONST_CHECK, _DERIVED);
}
