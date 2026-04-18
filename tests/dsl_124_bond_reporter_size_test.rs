//! Requirement DSL-124: `REPORTER_BOND_MOJOS` equals
//! `MIN_EFFECTIVE_BALANCE / 64` and is not runtime-configurable.
//!
//! Traces to: docs/resources/SPEC.md §2.6, §22.14.
//!
//! # Role
//!
//! Dedicated constant-pin test. DSL-023 already exercises the
//! full `submit_evidence` pipeline and asserts `BondEscrow::lock`
//! is called with exactly `REPORTER_BOND_MOJOS`; DSL-124 focuses
//! on the standalone constant invariants so a future constants
//! refactor cannot drift the value without the gate firing.
//!
//! # Why the size is chosen the way it is
//!
//! `MIN_EFFECTIVE_BALANCE / 64` is ≈1.5% of the minimum validator
//! balance — small enough that low-stake validators can afford to
//! report, large enough to make grief-reporting (repeat-spam of
//! false evidence that gets caught by a sustained appeal) a
//! losing strategy in expectation.
//!
//! # Test matrix (maps to DSL-124 Test Plan + acceptance)
//!
//!   1. `test_dsl_124_value_is_min_div_64` — asserts the exact
//!      arithmetic relationship at runtime
//!   2. `test_dsl_124_exact_divides` — `MIN_EFFECTIVE_BALANCE`
//!      cleanly divides by 64 so `MIN / 64 * 64 == MIN` with no
//!      truncation loss
//!   3. `test_dsl_124_not_runtime_configurable` — static assertion
//!      via `const` block proves the value is compile-time fixed
//!      (any future move to `static mut` or `OnceLock` would
//!      break the compile here)
//!   4. `test_dsl_124_symmetric_with_appellant` — DSL-125 sets
//!      `APPELLANT_BOND_MOJOS` to the same value so reporter and
//!      appellant face equal grief-vector costs; pin the
//!      symmetry here

use dig_slashing::{APPELLANT_BOND_MOJOS, MIN_EFFECTIVE_BALANCE, REPORTER_BOND_MOJOS};

/// DSL-124 row 1: exact value equality.
#[test]
fn test_dsl_124_value_is_min_div_64() {
    assert_eq!(
        REPORTER_BOND_MOJOS,
        MIN_EFFECTIVE_BALANCE / 64,
        "REPORTER_BOND_MOJOS must equal MIN_EFFECTIVE_BALANCE / 64 per SPEC §2.6",
    );

    // Concrete numeric — MIN_EFFECTIVE_BALANCE = 32_000_000_000
    // (32 DIG), so bond is 500_000_000 mojos = 0.5 DIG.
    assert_eq!(
        REPORTER_BOND_MOJOS, 500_000_000,
        "numeric pin against MIN_EFFECTIVE_BALANCE = 32_000_000_000",
    );
}

/// DSL-124 row 2: integer division is exact. If `MIN_EFFECTIVE_BALANCE`
/// is not divisible by 64 the bond would lose a remainder to
/// floor-division, and two consecutive formulas would silently
/// disagree by that remainder. Pin the no-truncation invariant
/// so any future bump to MIN_EFFECTIVE_BALANCE that breaks 64-
/// divisibility surfaces here.
#[test]
fn test_dsl_124_exact_divides() {
    let reconstructed = REPORTER_BOND_MOJOS * 64;
    assert_eq!(
        reconstructed, MIN_EFFECTIVE_BALANCE,
        "MIN / 64 * 64 must reconstruct MIN with no truncation loss",
    );
    assert_eq!(
        MIN_EFFECTIVE_BALANCE % 64,
        0,
        "MIN_EFFECTIVE_BALANCE must be divisible by 64",
    );
}

/// DSL-124 row 3: the value is compile-time-fixed. A `const
/// fn`-style assertion inside a `const` block executes at
/// compile time — any future refactor moving the value to a
/// runtime cell (OnceLock, atomic, etc.) would fail to compile
/// because those are not `const` contexts.
#[test]
fn test_dsl_124_not_runtime_configurable() {
    // This block is evaluated at compile time. `REPORTER_BOND_MOJOS`
    // must be a `const`, not a `static mut` or OnceLock.
    const _CONST_CHECK: u64 = REPORTER_BOND_MOJOS;
    const _DERIVED: u64 = MIN_EFFECTIVE_BALANCE / 64;
    const _: () = assert!(
        _CONST_CHECK == _DERIVED,
        "REPORTER_BOND_MOJOS must be a `const` evaluable at compile time",
    );

    // Runtime corroboration of the same fact.
    assert_eq!(_CONST_CHECK, _DERIVED);
}

/// DSL-124 row 4: reporter and appellant bonds are the same size.
/// SPEC §2.6 requires symmetry so neither side bears an asymmetric
/// grief-vector cost; DSL-125 pins the appellant side directly,
/// this row ties the two together.
#[test]
fn test_dsl_124_symmetric_with_appellant() {
    assert_eq!(
        REPORTER_BOND_MOJOS, APPELLANT_BOND_MOJOS,
        "reporter + appellant bonds must match for symmetric grief cost",
    );
}
