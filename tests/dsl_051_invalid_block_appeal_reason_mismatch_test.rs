//! Requirement DSL-051: `InvalidBlockAppealGround::FailureReasonMismatch`
//! sustains when the oracle's re-execution classifies the block as
//! `Invalid(actual_reason)` with `actual_reason != evidence.failure_reason`.
//!
//! Traces to: docs/resources/SPEC.md §6.4, §22.6.
//!
//! # Role
//!
//! The block IS invalid, so DSL-049 (`BlockActuallyValid`) does NOT
//! apply — but the slasher tagged the failure with the wrong
//! `InvalidBlockReason`. Sustain reverts the slash so the reporter
//! can re-file under the correct classification (paying fresh
//! reporter bond).
//!
//! # Test matrix (maps to DSL-051 Test Plan)
//!
//!   1. `test_dsl_051_reason_differs_sustained`
//!      — claimed `BadStateRoot`, oracle returns `Invalid(BadTimestamp)`
//!   2. `test_dsl_051_reason_matches_rejected`
//!      — claimed `BadStateRoot`, oracle returns `Invalid(BadStateRoot)`
//!   3. `test_dsl_051_valid_rejected`
//!      — oracle returns `Valid` (DSL-049 is the right ground there)
//!   4. `test_dsl_051_no_oracle_missing_err`
//!      — `oracle: None` → `Rejected{MissingOracle}`

use std::cell::RefCell;

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, ExecutionOutcome,
    InvalidBlockOracle, InvalidBlockProof, InvalidBlockReason, SignedBlockHeader, SlashingError,
    verify_invalid_block_appeal_failure_reason_mismatch,
};

struct RecOracle {
    calls: RefCell<u32>,
    verdict: Result<ExecutionOutcome, SlashingError>,
}

impl RecOracle {
    fn with(verdict: Result<ExecutionOutcome, SlashingError>) -> Self {
        Self {
            calls: RefCell::new(0),
            verdict,
        }
    }
}

impl InvalidBlockOracle for RecOracle {
    fn re_execute(
        &self,
        _header: &L2BlockHeader,
        _witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError> {
        *self.calls.borrow_mut() += 1;
        self.verdict.clone()
    }
}

fn sample_header() -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        5,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        1,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn evidence_claiming(reason: InvalidBlockReason) -> InvalidBlockProof {
    InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: sample_header(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        failure_witness: b"slasher".to_vec(),
        failure_reason: reason,
    }
}

/// DSL-051 row 1: claimed `BadStateRoot`, oracle says
/// `Invalid(BadTimestamp)` → reasons differ → Sustained.
#[test]
fn test_dsl_051_reason_differs_sustained() {
    let oracle = RecOracle::with(Ok(ExecutionOutcome::Invalid(
        InvalidBlockReason::BadTimestamp,
    )));
    let evidence = evidence_claiming(InvalidBlockReason::BadStateRoot);

    let v = verify_invalid_block_appeal_failure_reason_mismatch(
        &evidence,
        b"appeal witness",
        Some(&oracle as &dyn InvalidBlockOracle),
    );
    assert_eq!(
        v,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::FailureReasonMismatch,
        },
    );
    assert_eq!(*oracle.calls.borrow(), 1);
}

/// DSL-051 row 2: claimed `BadStateRoot`, oracle says
/// `Invalid(BadStateRoot)` → reasons match → Rejected (the slasher
/// was correct; use DSL-054 negative control).
#[test]
fn test_dsl_051_reason_matches_rejected() {
    let oracle = RecOracle::with(Ok(ExecutionOutcome::Invalid(
        InvalidBlockReason::BadStateRoot,
    )));
    let evidence = evidence_claiming(InvalidBlockReason::BadStateRoot);

    let v = verify_invalid_block_appeal_failure_reason_mismatch(
        &evidence,
        b"appeal witness",
        Some(&oracle as &dyn InvalidBlockOracle),
    );
    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-051 row 3: oracle says `Valid` → this ground does NOT apply
/// (DSL-049 `BlockActuallyValid` is the correct ground) →
/// Rejected{GroundDoesNotHold}. Guards against a verifier that
/// conflates "block is valid" with "reason mismatch".
#[test]
fn test_dsl_051_valid_rejected() {
    let oracle = RecOracle::with(Ok(ExecutionOutcome::Valid));
    let evidence = evidence_claiming(InvalidBlockReason::BadStateRoot);

    let v = verify_invalid_block_appeal_failure_reason_mismatch(
        &evidence,
        b"appeal witness",
        Some(&oracle as &dyn InvalidBlockOracle),
    );
    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-051 row 4: `oracle: None` → `Rejected{MissingOracle}`.
/// This ground always needs oracle support — there is no
/// cheap-local way to re-classify the failure.
#[test]
fn test_dsl_051_no_oracle_missing_err() {
    let evidence = evidence_claiming(InvalidBlockReason::BadStateRoot);

    let v = verify_invalid_block_appeal_failure_reason_mismatch(&evidence, b"appeal witness", None);
    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::MissingOracle,
        },
    );
}
