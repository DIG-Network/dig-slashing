//! Requirement DSL-145: `InvalidBlockOracle::re_execute(header,
//! witness)` MUST be deterministic — identical inputs always
//! yield identical `ExecutionOutcome`. No I/O, no RNG, no
//! hidden mutable state.
//!
//! Traces to: docs/resources/SPEC.md §15.3.
//!
//! # Role
//!
//! Closes Phase 9 External-State Traits. Underpins invalid-block
//! appeal grounds DSL-049 (`BlockActuallyValid` — a sustained
//! appeal requires the oracle to return `Valid`) and DSL-051
//! (`FailureReasonMismatch` — sustained requires `Invalid(other)`
//! matching a different reason). Determinism across oracle
//! instances means a verifier can independently confirm the
//! appellant's witness.
//!
//! # Test matrix (maps to DSL-145 Test Plan + acceptance)
//!
//!   1. `test_dsl_145_deterministic_valid` — two calls, same
//!      inputs → both Valid
//!   2. `test_dsl_145_deterministic_invalid` — two calls, same
//!      invalid inputs → both Invalid with same reason
//!   3. `test_dsl_145_distinct_witness_may_differ` — different
//!      witness bytes can produce different outcomes
//!   4. `test_dsl_145_no_hidden_state` — interleave re_execute
//!      calls with verify_failure; outcome unchanged
//!   5. `test_dsl_145_verify_failure_default_ok` — default
//!      impl of verify_failure returns Ok(()) (bootstrap path)

use std::cell::Cell;

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{ExecutionOutcome, InvalidBlockOracle, InvalidBlockReason, SlashingError};

fn sample_header(state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_byte; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        9,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

/// Deterministic reference oracle. Returns Valid when witness
/// is empty OR starts with 0x00; Invalid(BadStateRoot) when
/// witness starts with 0xFF. No mutable state.
///
/// `call_count` exists only for `test_dsl_145_no_hidden_state`
/// to prove that call counting does NOT affect the outcome —
/// the Cell is observation-only, not logic-influencing.
struct DeterministicOracle {
    call_count: Cell<u32>,
}

impl DeterministicOracle {
    fn new() -> Self {
        Self {
            call_count: Cell::new(0),
        }
    }
    fn calls(&self) -> u32 {
        self.call_count.get()
    }
}

impl InvalidBlockOracle for DeterministicOracle {
    fn re_execute(
        &self,
        _header: &L2BlockHeader,
        witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError> {
        self.call_count.set(self.call_count.get() + 1);
        // Deterministic rule: first byte of witness.
        match witness.first() {
            None | Some(0x00) => Ok(ExecutionOutcome::Valid),
            Some(0xFF) => Ok(ExecutionOutcome::Invalid(InvalidBlockReason::BadStateRoot)),
            Some(0xEE) => Ok(ExecutionOutcome::Invalid(InvalidBlockReason::BadParentRoot)),
            _ => Ok(ExecutionOutcome::Valid),
        }
    }
    // verify_failure uses the default impl (Ok(())).
}

/// DSL-145 row 1: deterministic Valid across repeated calls.
#[test]
fn test_dsl_145_deterministic_valid() {
    let o = DeterministicOracle::new();
    let header = sample_header(0x02);
    let witness = &[0x00u8, 0x01, 0x02];

    let a = o.re_execute(&header, witness).unwrap();
    let b = o.re_execute(&header, witness).unwrap();
    assert!(matches!(a, ExecutionOutcome::Valid));
    assert!(matches!(b, ExecutionOutcome::Valid));
    assert_eq!(o.calls(), 2);
}

/// DSL-145 row 2: deterministic Invalid with the same reason.
#[test]
fn test_dsl_145_deterministic_invalid() {
    let o = DeterministicOracle::new();
    let header = sample_header(0x02);
    let witness = &[0xFFu8, 0x01];

    let a = o.re_execute(&header, witness).unwrap();
    let b = o.re_execute(&header, witness).unwrap();

    match (a, b) {
        (ExecutionOutcome::Invalid(r1), ExecutionOutcome::Invalid(r2)) => {
            assert_eq!(r1, r2);
            assert_eq!(r1, InvalidBlockReason::BadStateRoot);
        }
        other => panic!("expected Invalid on both calls, got {other:?}"),
    }
}

/// DSL-145 row 3: different witness may yield different outcome.
/// The trait PERMITS divergence on different inputs — it only
/// requires determinism on IDENTICAL inputs.
#[test]
fn test_dsl_145_distinct_witness_may_differ() {
    let o = DeterministicOracle::new();
    let header = sample_header(0x02);

    let a = o.re_execute(&header, &[0x00u8]).unwrap();
    let b = o.re_execute(&header, &[0xFFu8]).unwrap();

    assert!(matches!(a, ExecutionOutcome::Valid));
    assert!(matches!(b, ExecutionOutcome::Invalid(_)));

    // Different reasons across distinct witness bytes.
    let c = o.re_execute(&header, &[0xFFu8]).unwrap();
    let d = o.re_execute(&header, &[0xEEu8]).unwrap();
    let (ExecutionOutcome::Invalid(r_c), ExecutionOutcome::Invalid(r_d)) = (c, d) else {
        panic!("both should be Invalid");
    };
    assert_ne!(r_c, r_d, "distinct witness → distinct reason");
}

/// DSL-145 row 4: no hidden state. Interleaving re_execute with
/// verify_failure (which also has access to &self) must not
/// perturb re_execute's outcome.
#[test]
fn test_dsl_145_no_hidden_state() {
    let o = DeterministicOracle::new();
    let header = sample_header(0x02);
    let witness = &[0xFFu8];

    let initial = o.re_execute(&header, witness).unwrap();

    // Interleave verify_failure + re_execute + verify_failure.
    o.verify_failure(&header, witness, InvalidBlockReason::BadStateRoot)
        .unwrap();
    let after_verify = o.re_execute(&header, witness).unwrap();
    o.verify_failure(&header, witness, InvalidBlockReason::BadParentRoot)
        .unwrap();
    let after_second_verify = o.re_execute(&header, witness).unwrap();

    // All three should match by variant + reason.
    for outcome in [initial, after_verify, after_second_verify] {
        let ExecutionOutcome::Invalid(reason) = outcome else {
            panic!("expected Invalid");
        };
        assert_eq!(reason, InvalidBlockReason::BadStateRoot);
    }
}

/// DSL-145 row 5: default `verify_failure` returns Ok(()). The
/// bootstrap path (oracle is not yet consulting a real oracle
/// backend) must accept any claim without error. DSL-049 /
/// DSL-051 will provide stricter impls in production.
#[test]
fn test_dsl_145_verify_failure_default_ok() {
    let o = DeterministicOracle::new();
    let header = sample_header(0x02);
    // Any witness + any reason: default accepts.
    o.verify_failure(&header, &[], InvalidBlockReason::BadStateRoot)
        .expect("default impl returns Ok");
    o.verify_failure(&header, &[0xFFu8; 64], InvalidBlockReason::BadTimestamp)
        .expect("default impl returns Ok");
}
