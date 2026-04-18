//! Requirement DSL-049: `InvalidBlockAppealGround::BlockActuallyValid`
//! sustains when the oracle's `re_execute` returns
//! `ExecutionOutcome::Valid` on the accused block.
//!
//! Traces to: docs/resources/SPEC.md §6.4, §15.3, §22.6.
//!
//! # Role
//!
//! Opens the invalid-block appeal section. The evidence claims the
//! block is invalid; the appellant disagrees and supplies fresh
//! replay material (the appeal's own witness) to a full-node
//! oracle. Oracle agrees block is valid → slash reverted.
//!
//! # Test matrix (maps to DSL-049 Test Plan)
//!
//!   1. `test_dsl_049_oracle_valid_sustained` — oracle returns Valid
//!   2. `test_dsl_049_oracle_invalid_rejected` — oracle returns Invalid
//!   3. `test_dsl_049_no_oracle_missing_oracle_err` — `oracle: None`
//!      → `Rejected{MissingOracle}`
//!   4. `test_dsl_049_witness_passed_through` — oracle records
//!      `(header, witness)`; appeal's witness reaches oracle byte-equal
//!      (NOT `evidence.failure_witness`)

use std::cell::RefCell;

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, ExecutionOutcome,
    InvalidBlockOracle, InvalidBlockProof, InvalidBlockReason, SignedBlockHeader, SlashingError,
    verify_invalid_block_appeal_block_actually_valid,
};

/// Recording oracle — stores every `re_execute` call + verdict to
/// return. Allows tests to assert both the verdict AND the bytes
/// that reached the oracle.
struct RecOracle {
    calls: RefCell<Vec<(L2BlockHeader, Vec<u8>)>>,
    verdict: Result<ExecutionOutcome, SlashingError>,
}

impl RecOracle {
    fn valid() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            verdict: Ok(ExecutionOutcome::Valid),
        }
    }
    fn invalid(reason: InvalidBlockReason) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            verdict: Ok(ExecutionOutcome::Invalid(reason)),
        }
    }
}

impl InvalidBlockOracle for RecOracle {
    fn re_execute(
        &self,
        header: &L2BlockHeader,
        witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError> {
        self.calls
            .borrow_mut()
            .push((header.clone(), witness.to_vec()));
        self.verdict.clone()
    }
}

/// Sample block header — body irrelevant to DSL-049, the oracle is
/// mocked.
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

/// Build an `InvalidBlockProof` with the given failure witness.
/// Signature bytes are placeholder — DSL-049 does not verify them
/// (that is DSL-050's job).
fn evidence_with_failure_witness(bytes: Vec<u8>) -> InvalidBlockProof {
    InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: sample_header(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        failure_witness: bytes,
        failure_reason: InvalidBlockReason::BadStateRoot,
    }
}

/// DSL-049 row 1: oracle returns `Valid` → Sustained.
#[test]
fn test_dsl_049_oracle_valid_sustained() {
    let oracle = RecOracle::valid();
    let evidence = evidence_with_failure_witness(b"slasher witness".to_vec());
    let appeal_witness: &[u8] = b"appellant witness";

    let v = verify_invalid_block_appeal_block_actually_valid(
        &evidence,
        appeal_witness,
        Some(&oracle as &dyn InvalidBlockOracle),
    );

    assert_eq!(
        v,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::BlockActuallyValid,
        },
    );
}

/// DSL-049 row 2: oracle returns `Invalid(_)` → Rejected
/// (`GroundDoesNotHold`) — the oracle disagrees with the appellant's
/// "block is valid" claim.
#[test]
fn test_dsl_049_oracle_invalid_rejected() {
    let oracle = RecOracle::invalid(InvalidBlockReason::BadStateRoot);
    let evidence = evidence_with_failure_witness(b"slasher witness".to_vec());

    let v = verify_invalid_block_appeal_block_actually_valid(
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

/// DSL-049 row 3: `oracle: None` → `Rejected{MissingOracle}`. The
/// appeal requires external state the crate does not own; without
/// the oracle there is no way to adjudicate validity.
#[test]
fn test_dsl_049_no_oracle_missing_oracle_err() {
    let evidence = evidence_with_failure_witness(b"slasher witness".to_vec());

    let v = verify_invalid_block_appeal_block_actually_valid(&evidence, b"appeal witness", None);

    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::MissingOracle,
        },
    );
}

/// DSL-049 row 4: the appeal's witness reaches the oracle byte-equal
/// — NOT `evidence.failure_witness`. This guards against a regression
/// where the verifier might forward the slasher's witness instead of
/// the appellant's fresh replay material.
#[test]
fn test_dsl_049_witness_passed_through() {
    let oracle = RecOracle::valid();
    let appeal_witness = b"APPELLANT-FRESH-WITNESS-BYTES".to_vec();
    // Slasher's witness is deliberately different so the record can
    // distinguish which one the verifier forwarded.
    let evidence = evidence_with_failure_witness(b"SLASHER-STALE-WITNESS".to_vec());

    let _v = verify_invalid_block_appeal_block_actually_valid(
        &evidence,
        &appeal_witness,
        Some(&oracle as &dyn InvalidBlockOracle),
    );

    let calls = oracle.calls.borrow();
    assert_eq!(calls.len(), 1, "oracle must be called exactly once");
    // Header reaches oracle unchanged.
    assert_eq!(calls[0].0, sample_header());
    // Witness is the APPEAL's bytes — not the slasher's.
    assert_eq!(calls[0].1, appeal_witness);
    assert_ne!(calls[0].1, b"SLASHER-STALE-WITNESS");
}
