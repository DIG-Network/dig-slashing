//! Requirement DSL-137: `EffectiveBalanceView` contract.
//!
//!   - `get(idx)` returns the validator's effective balance in
//!     mojos, or `0` for unknown indices.
//!   - `total_active()` returns the sum of active-validator
//!     effective balances.
//!   - Both are read-only — no internal mutation.
//!
//! Traces to: docs/resources/SPEC.md §15.2.
//!
//! # Role
//!
//! Consumers: base_reward (DSL-081), correlation-penalty math
//! (DSL-030), inactivity penalty formula (DSL-092). All three
//! accept `&dyn EffectiveBalanceView` and call `.get()` per
//! validator; `total_active()` feeds the denominators.
//!
//! # Why `get(unknown) == 0`
//!
//! Defensive default: a panic or `None` return would force every
//! caller to carry branch-on-missing logic. Treating unknown as
//! zero makes the math converge to the correct answer (a validator
//! with zero effective balance contributes nothing to cohort-sum
//! or total-active).
//!
//! # Test matrix (maps to DSL-137 Test Plan + acceptance)
//!
//!   1. `test_dsl_137_get_known_idx` — distinct balances per
//!      validator round-trip through `get`
//!   2. `test_dsl_137_get_unknown_zero` — `get(u32::MAX)` and
//!      other out-of-range indices return 0 (no panic)
//!   3. `test_dsl_137_total_active_sum` — `total_active()` ==
//!      sum of `get(0..n)` for an all-active set
//!   4. `test_dsl_137_read_only` — repeated calls yield the
//!      same value (no internal state drift)

use dig_slashing::EffectiveBalanceView;

struct MockBalances {
    balances: Vec<u64>,
}

impl MockBalances {
    fn with(balances: &[u64]) -> Self {
        Self {
            balances: balances.to_vec(),
        }
    }
}

impl EffectiveBalanceView for MockBalances {
    fn get(&self, idx: u32) -> u64 {
        // SPEC §15.2: unknown indices return 0.
        self.balances.get(idx as usize).copied().unwrap_or(0)
    }
    fn total_active(&self) -> u64 {
        self.balances.iter().sum()
    }
}

/// DSL-137 row 1: per-validator balance round-trips through
/// `get(idx)`. Distinct values catch any index-offset bug that
/// would swap balances across indices.
#[test]
fn test_dsl_137_get_known_idx() {
    let b = MockBalances::with(&[10, 20, 30]);
    assert_eq!(b.get(0), 10);
    assert_eq!(b.get(1), 20);
    assert_eq!(b.get(2), 30);
}

/// DSL-137 row 2: unknown indices return 0 (no panic).
#[test]
fn test_dsl_137_get_unknown_zero() {
    let b = MockBalances::with(&[10, 20, 30]);
    assert_eq!(b.get(3), 0, "len boundary");
    assert_eq!(b.get(4), 0);
    assert_eq!(b.get(u32::MAX), 0, "u32::MAX stress");

    // Empty set: every index is unknown → 0.
    let empty = MockBalances::with(&[]);
    for idx in [0u32, 1, u32::MAX] {
        assert_eq!(empty.get(idx), 0);
    }
    assert_eq!(empty.total_active(), 0);
}

/// DSL-137 row 3: `total_active()` equals the sum of all
/// `get(idx)` across the registered range.
#[test]
fn test_dsl_137_total_active_sum() {
    let balances = [32_000_000_000u64, 24_000_000_000, 16_000_000_000];
    let b = MockBalances::with(&balances);

    let manual_sum: u64 = (0u32..balances.len() as u32).map(|i| b.get(i)).sum();
    assert_eq!(b.total_active(), manual_sum);
    assert_eq!(b.total_active(), 72_000_000_000);
}

/// DSL-137 row 4: both methods are read-only — repeated calls
/// yield the same value. Guards against a buggy impl that
/// advances an internal cursor on each call.
#[test]
fn test_dsl_137_read_only() {
    let b = MockBalances::with(&[100, 200, 300]);
    let first = b.total_active();
    let second = b.total_active();
    assert_eq!(first, second);

    for _ in 0..10 {
        assert_eq!(b.get(1), 200);
    }
}
