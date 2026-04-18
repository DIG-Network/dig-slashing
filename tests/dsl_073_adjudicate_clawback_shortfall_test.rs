//! Requirement DSL-073: the DSL-067 clawback shortfall MUST be
//! absorbed into the DSL-068 burn leg. If the forfeited bond is
//! insufficient, the residue is surfaced for telemetry; the
//! adjudication proceeds.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §22.8.
//!
//! # Role
//!
//! Closes the appeal adjudicator. Ties DSL-067 (reward clawback
//! shortfall) to DSL-068 (reporter bond split burn leg) so the
//! protocol conserves mojos: if a reporter already withdrew the
//! optimistic rewards, their forfeited bond absorbs the debt.
//!
//! # Math
//!
//! `final_burn = original_burn + clawback_shortfall`
//! `residue   = max(0, final_burn - forfeited)`
//!
//! # Test matrix (maps to DSL-073 Test Plan)
//!
//!   1. `test_dsl_073_zero_shortfall_no_op` — shortfall=0 →
//!      final_burn == original_burn, residue=0
//!   2. `test_dsl_073_partial_clawback_absorbed` — non-zero
//!      shortfall → added to burn
//!   3. `test_dsl_073_shortfall_in_result` — struct field
//!      propagation
//!   4. `test_dsl_073_residue_logged` — shortfall > bond →
//!      residue > 0, no panic (adjudication proceeds)

use dig_slashing::{
    BondSplitResult, ClawbackResult, ShortfallAbsorption, adjudicate_absorb_clawback_shortfall,
};

/// Helper: fabricate a `ClawbackResult` with a specific shortfall.
/// Other fields are self-consistent but not load-bearing for
/// DSL-073.
fn clawback_with_shortfall(shortfall: u64) -> ClawbackResult {
    ClawbackResult {
        wb_amount: 1_000,
        prop_amount: 125,
        wb_clawed: 1_000u64.saturating_sub(shortfall),
        prop_clawed: 125,
        shortfall,
    }
}

/// Helper: fabricate a `BondSplitResult` with a specific
/// forfeited + burn pair.
fn bond_split(forfeited: u64, winner_award: u64) -> BondSplitResult {
    BondSplitResult {
        forfeited,
        winner_award,
        burn: forfeited - winner_award,
    }
}

/// DSL-073 row 1: zero shortfall → `final_burn == original_burn`,
/// `residue == 0`. Passthrough of DSL-068 math.
#[test]
fn test_dsl_073_zero_shortfall_no_op() {
    let cb = clawback_with_shortfall(0);
    let bs = bond_split(1_000, 500); // burn = 500

    let r = adjudicate_absorb_clawback_shortfall(&cb, &bs);
    assert_eq!(
        r,
        ShortfallAbsorption {
            clawback_shortfall: 0,
            original_burn: 500,
            final_burn: 500,
            residue: 0,
        },
    );
}

/// DSL-073 row 2: 200 shortfall + 500 original burn → final_burn
/// = 700. Bond (1000) covers it → residue = 0.
#[test]
fn test_dsl_073_partial_clawback_absorbed() {
    let cb = clawback_with_shortfall(200);
    let bs = bond_split(1_000, 500);

    let r = adjudicate_absorb_clawback_shortfall(&cb, &bs);
    assert_eq!(r.clawback_shortfall, 200);
    assert_eq!(r.original_burn, 500);
    assert_eq!(r.final_burn, 700);
    assert_eq!(r.residue, 0, "bond sufficient; no residue");
}

/// DSL-073 row 3: struct propagation — the `ClawbackResult.shortfall`
/// value appears verbatim on the absorption result so consumers
/// can serialise it into the DSL-164 `AppealAdjudicationResult`
/// without re-deriving.
#[test]
fn test_dsl_073_shortfall_in_result() {
    let cb = clawback_with_shortfall(313);
    let bs = bond_split(5_000, 2_500);

    let r = adjudicate_absorb_clawback_shortfall(&cb, &bs);
    assert_eq!(r.clawback_shortfall, 313);
    assert_eq!(r.original_burn, bs.burn);
    assert_eq!(r.final_burn, bs.burn + 313);
}

/// DSL-073 row 4: shortfall exceeds what the bond can absorb.
/// `forfeited = 100`, `burn = 50`, `shortfall = 200` →
/// `final_burn = 250`, `residue = 250 - 100 = 150`.
/// Adjudication returns normally — no panic.
#[test]
fn test_dsl_073_residue_logged() {
    let cb = clawback_with_shortfall(200);
    let bs = bond_split(100, 50);

    let r = adjudicate_absorb_clawback_shortfall(&cb, &bs);
    assert_eq!(r.clawback_shortfall, 200);
    assert_eq!(r.original_burn, 50);
    assert_eq!(r.final_burn, 250);
    assert_eq!(
        r.residue, 150,
        "final_burn exceeds forfeited; residue surfaces",
    );
}
