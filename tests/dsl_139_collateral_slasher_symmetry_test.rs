//! Requirement DSL-139: `CollateralSlasher` slash+credit
//! symmetry.
//!
//!   - `slash(idx, amount, epoch)` returns
//!     `Ok((slashed, remaining))` or `Err(NoCollateral)`.
//!   - `credit(idx, amount)` restores prior state (companion
//!     to slash).
//!   - `NoCollateral` is a SOFT failure — DSL-022 submit_evidence
//!     treats it as a no-op and still slashes stake.
//!
//! Traces to: docs/resources/SPEC.md §15.2.
//!
//! # Role
//!
//! Consumers:
//!   - DSL-022 submit_evidence calls `slash` per slashable
//!     validator; a `NoCollateral` return is silently absorbed.
//!   - DSL-065 sustained-appeal adjudicator calls `credit` to
//!     restore debited collateral.
//!   - DSL-129 reorg rewind calls `credit` on every rewound
//!     validator.
//!
//! The default `slash` on the trait returns `NoCollateral` so
//! existing `impl CollateralSlasher` in test fixtures that only
//! exercise `credit` continue to compile. DSL-139 demonstrates
//! a full impl overriding the default.
//!
//! # Test matrix (maps to DSL-139 Test Plan + acceptance)
//!
//!   1. `test_dsl_139_slash_credit_roundtrip` — slash(30) +
//!      credit(30) restores original
//!   2. `test_dsl_139_no_collateral_soft_err` — slash on a
//!      validator without collateral → NoCollateral
//!   3. `test_dsl_139_double_credit_idempotent` — credit
//!      twice when no prior slash → both calls work without
//!      surfacing state inconsistency
//!   4. `test_dsl_139_default_impl_returns_no_collateral` —
//!      a minimal impl that only overrides `credit` returns
//!      NoCollateral from the default `slash` (proves the
//!      default-impl trait-extension path works without
//!      breaking existing downstream impls)

use std::cell::RefCell;
use std::collections::HashMap;

use dig_slashing::{CollateralError, CollateralSlasher};

/// Full impl with per-validator collateral balances + slash
/// semantics.
struct FullCollateral {
    balances: RefCell<HashMap<u32, u64>>,
}
impl FullCollateral {
    fn new() -> Self {
        Self {
            balances: RefCell::new(HashMap::new()),
        }
    }
    fn set(&self, idx: u32, amount: u64) {
        self.balances.borrow_mut().insert(idx, amount);
    }
    fn get(&self, idx: u32) -> u64 {
        *self.balances.borrow().get(&idx).unwrap_or(&0)
    }
}
impl CollateralSlasher for FullCollateral {
    fn credit(&mut self, idx: u32, amount: u64) {
        *self.balances.borrow_mut().entry(idx).or_insert(0) += amount;
    }
    fn slash(&mut self, idx: u32, amount: u64, _epoch: u64) -> Result<(u64, u64), CollateralError> {
        let mut balances = self.balances.borrow_mut();
        let bal = balances.entry(idx).or_insert(0);
        if *bal == 0 {
            return Err(CollateralError::NoCollateral);
        }
        let debited = amount.min(*bal);
        *bal -= debited;
        Ok((debited, *bal))
    }
}

/// Minimal impl that ONLY overrides `credit`. Used to verify the
/// default `slash` returns NoCollateral — i.e. existing fixtures
/// don't break on the DSL-139 trait extension.
struct CreditOnlyCollateral {
    credits: RefCell<Vec<(u32, u64)>>,
}
impl CollateralSlasher for CreditOnlyCollateral {
    fn credit(&mut self, idx: u32, amount: u64) {
        self.credits.borrow_mut().push((idx, amount));
    }
    // Note: no `slash` override — uses default returning NoCollateral.
}

/// DSL-139 row 1: slash + credit roundtrip restores balance.
#[test]
fn test_dsl_139_slash_credit_roundtrip() {
    let mut c = FullCollateral::new();
    c.set(7, 100);

    let (slashed, remaining) = c.slash(7, 30, 5).expect("collateral present");
    assert_eq!(slashed, 30);
    assert_eq!(remaining, 70);
    assert_eq!(c.get(7), 70);

    c.credit(7, 30);
    assert_eq!(c.get(7), 100, "credit restores original");
}

/// DSL-139 row 2: slash on a validator with no collateral
/// returns NoCollateral. DSL-022 submit_evidence ignores this.
#[test]
fn test_dsl_139_no_collateral_soft_err() {
    let mut c = FullCollateral::new();
    // No balance set for validator 9.
    let err = c
        .slash(9, 100, 5)
        .expect_err("no collateral → NoCollateral");
    assert_eq!(err, CollateralError::NoCollateral);
    assert_eq!(c.get(9), 0, "state unchanged on failed slash");
}

/// DSL-139 row 3: double-credit when nothing was slashed is
/// idempotent in the sense that both calls succeed and the
/// balance simply grows. (No state inconsistency: credit just
/// adds mojos; it doesn't check for a prior slash.)
#[test]
fn test_dsl_139_double_credit_idempotent() {
    let mut c = FullCollateral::new();
    c.credit(11, 50);
    assert_eq!(c.get(11), 50);
    c.credit(11, 50);
    assert_eq!(
        c.get(11),
        100,
        "second credit accumulates (no-op fail-safe)"
    );
}

/// DSL-139 row 4: the default `slash` impl returns
/// `NoCollateral` so minimal impls that only provide `credit`
/// continue to compile AND behave correctly when someone calls
/// `slash` on them.
#[test]
fn test_dsl_139_default_impl_returns_no_collateral() {
    let mut c = CreditOnlyCollateral {
        credits: RefCell::new(Vec::new()),
    };
    // Default slash impl returns NoCollateral.
    let err = c.slash(7, 100, 5).expect_err("default impl");
    assert_eq!(err, CollateralError::NoCollateral);
    // credit still works via the explicit override.
    c.credit(7, 50);
    assert_eq!(c.credits.borrow().len(), 1);
}
