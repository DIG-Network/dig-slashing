//! Evidence verification dispatcher.
//!
//! Traces to: [SPEC.md §5.1](../../docs/resources/SPEC.md), catalogue rows
//! [DSL-011..021](../../docs/requirements/domains/evidence/specs/).
//!
//! # Role
//!
//! `verify_evidence` is the sole entry point every `SlashingEvidence`
//! flows through on its way to:
//!
//! - `SlashingManager::submit_evidence` (DSL-022) — state-mutating.
//! - Block-admission / mempool pipelines — via
//!   `verify_evidence_for_inclusion` (DSL-021), which must be identical
//!   minus state mutation.
//!
//! The function runs per-envelope preconditions in a fixed order, then
//! dispatches per payload variant. Preconditions are split into
//! "cheap filters" (epoch lookback, reporter registration / self-accuse)
//! and "crypto-heavy" (BLS verify, oracle re-execution) — cheap first.
//!
//! # Implementation status
//!
//! This module currently implements the OffenseTooOld precondition
//! (DSL-011) and emits a placeholder success result for every other
//! path. The remaining preconditions (DSL-012 reporter self-accuse,
//! DSL-013..020 per-payload dispatch) land in subsequent commits. Each
//! DSL row adds one conditional, never mutating the structure of the
//! function.

use dig_protocol::Bytes32;

use crate::error::SlashingError;
use crate::evidence::envelope::SlashingEvidence;
use crate::evidence::offense::OffenseType;
use crate::traits::ValidatorView;

/// Successful-verification return shape.
///
/// Traces to [SPEC §3.9](../../docs/resources/SPEC.md).
///
/// # Invariants
///
/// - `offense_type == evidence.offense_type` (verifier never reclassifies).
/// - `slashable_validator_indices == evidence.slashable_validators()`
///   (same ordering + cardinality; ascending for Attester per DSL-010).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct VerifiedEvidence {
    /// Classification of the confirmed offense. Drives base-penalty
    /// lookup (DSL-001) and downstream reward routing.
    pub offense_type: OffenseType,
    /// Validator indices the manager will debit. For Proposer /
    /// InvalidBlock this is a single-element vec; for Attester it is
    /// the sorted intersection (DSL-007).
    pub slashable_validator_indices: Vec<u32>,
}

/// Verify a `SlashingEvidence` envelope against the current validator
/// set + epoch context.
///
/// Implements [DSL-011](../../docs/requirements/domains/evidence/specs/DSL-011.md)
/// (OffenseTooOld precondition). Subsequent DSLs extend this function
/// rather than replace it — verifier ordering is protocol.
///
/// # Current precondition order
///
/// 1. **OffenseTooOld** (DSL-011): `evidence.epoch + SLASH_LOOKBACK_EPOCHS
///    >= current_epoch`. Addition on the LHS avoids underflow at network
///    boot (`current_epoch < SLASH_LOOKBACK_EPOCHS`).
///
/// # Not yet enforced (placeholder accept)
///
/// - DSL-012: `reporter_validator_index ∉ slashable_validators()`.
/// - DSL-013: proposer-slashing preconditions.
/// - DSL-014/015: attester double-vote / surround-vote predicates.
/// - DSL-016/017: attester intersection / predicate failure.
/// - DSL-018/019/020: invalid-block signature / epoch / oracle.
///
/// Until those land, envelopes passing the lookback check return a
/// placeholder `VerifiedEvidence` — consumers MUST NOT treat this
/// function as fully soundness-complete yet. The placeholder is
/// observable only in test fixtures (DSL-011 test only exercises the
/// boundary + error path).
///
/// # Parameters
///
/// - `evidence`: the envelope to verify.
/// - `_validator_view`: validator set handle. Consumed by DSL-012+
///   (currently unused but locked into the signature per SPEC §5.1).
/// - `_network_id`: chain id for BLS signing-root derivation. Consumed
///   by DSL-013/018 (currently unused).
/// - `current_epoch`: epoch the verifier is running in. ONLY required
///   right now for the OffenseTooOld check.
pub fn verify_evidence(
    evidence: &SlashingEvidence,
    _validator_view: &dyn ValidatorView,
    _network_id: &Bytes32,
    current_epoch: u64,
) -> Result<VerifiedEvidence, SlashingError> {
    // DSL-011: OffenseTooOld. Phrased with `evidence.epoch + LOOKBACK`
    // on the LHS so `current_epoch = 0` cannot underflow the RHS.
    // `u64::saturating_add` is the defensive belt — `evidence.epoch`
    // arriving as `u64::MAX - LOOKBACK` would overflow a naïve `+`.
    let lookback_sum = evidence
        .epoch
        .saturating_add(dig_epoch::SLASH_LOOKBACK_EPOCHS);
    if lookback_sum < current_epoch {
        return Err(SlashingError::OffenseTooOld {
            offense_epoch: evidence.epoch,
            current_epoch,
        });
    }

    // Placeholder success — see module docs. Every future DSL extends
    // this function rather than replacing this return.
    Ok(VerifiedEvidence {
        offense_type: evidence.offense_type,
        slashable_validator_indices: evidence.slashable_validators(),
    })
}
