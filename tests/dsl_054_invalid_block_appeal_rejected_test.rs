//! Requirement DSL-054: An `InvalidBlockAppeal` whose ground does
//! NOT hold against a genuinely invalid block MUST be Rejected.
//!
//! Traces to: docs/resources/SPEC.md §6.4, §22.6.
//!
//! # Role
//!
//! Mirror of DSL-040 (proposer) / DSL-048 (attester) for the
//! invalid-block side. Builds a single fixture representing a
//! GENUINE invalid-block offense — header honestly signed by the
//! accused, envelope epoch matches header epoch, oracle classifies
//! the block as `Invalid(BadStateRoot)` with the reason matching
//! `evidence.failure_reason` — then drives each of the four
//! invalid-block appeal verifiers through it and asserts each
//! returns `Rejected{GroundDoesNotHold}`. Any verifier that
//! sustained here would let a genuinely malicious slashed
//! validator escape DSL-071 bond forfeiture.
//!
//! # Test matrix (maps to DSL-054 Test Plan — one row per ground)
//!
//!   1. `test_dsl_054_block_valid_false_claim_rejected`
//!      → `BlockActuallyValid` with oracle=`Invalid` → Rejected
//!   2. `test_dsl_054_sig_invalid_false_claim_rejected`
//!      → `ProposerSignatureInvalid` with valid sig → Rejected
//!   3. `test_dsl_054_reason_mismatch_false_rejected`
//!      → `FailureReasonMismatch` with matching reason → Rejected
//!   4. `test_dsl_054_epoch_mismatch_false_rejected`
//!      → `EvidenceEpochMismatch` with matching epochs → Rejected

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealVerdict, ExecutionOutcome, InvalidBlockOracle, InvalidBlockProof,
    InvalidBlockReason, SignedBlockHeader, SlashingError, ValidatorEntry, ValidatorView,
    block_signing_message, verify_invalid_block_appeal_block_actually_valid,
    verify_invalid_block_appeal_evidence_epoch_mismatch,
    verify_invalid_block_appeal_failure_reason_mismatch,
    verify_invalid_block_appeal_proposer_signature_invalid,
};

// ── Validator view ──────────────────────────────────────────────────────

struct TestValidator {
    pk: PublicKey,
}

impl ValidatorEntry for TestValidator {
    fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    fn puzzle_hash(&self) -> Bytes32 {
        Bytes32::new([0u8; 32])
    }
    fn effective_balance(&self) -> u64 {
        32_000_000_000
    }
    fn is_slashed(&self) -> bool {
        false
    }
    fn activation_epoch(&self) -> u64 {
        0
    }
    fn exit_epoch(&self) -> u64 {
        u64::MAX
    }
    fn is_active_at_epoch(&self, _epoch: u64) -> bool {
        true
    }
    fn slash_absolute(&mut self, _: u64, _: u64) -> u64 {
        0
    }
    fn credit_stake(&mut self, _: u64) -> u64 {
        0
    }
    fn restore_status(&mut self) -> bool {
        false
    }
    fn schedule_exit(&mut self, _: u64) {}
}

struct MapView(HashMap<u32, TestValidator>);

impl ValidatorView for MapView {
    fn get(&self, index: u32) -> Option<&dyn ValidatorEntry> {
        self.0.get(&index).map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, index: u32) -> Option<&mut dyn ValidatorEntry> {
        self.0.get_mut(&index).map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

// ── Genuine-invalid oracle ──────────────────────────────────────────────

/// Oracle that always classifies the block as `Invalid(reason)`
/// for a fixed reason — simulates a full node that confirms the
/// block is genuinely invalid for exactly the reason the slasher
/// claimed.
struct InvalidOracle {
    reason: InvalidBlockReason,
    calls: RefCell<u32>,
}

impl InvalidOracle {
    fn new(reason: InvalidBlockReason) -> Self {
        Self {
            reason,
            calls: RefCell::new(0),
        }
    }
}

impl InvalidBlockOracle for InvalidOracle {
    fn re_execute(
        &self,
        _header: &L2BlockHeader,
        _witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError> {
        *self.calls.borrow_mut() += 1;
        Ok(ExecutionOutcome::Invalid(self.reason))
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

const PROPOSER_INDEX: u32 = 7;
const HEADER_EPOCH: u64 = 5;

fn sample_header() -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        HEADER_EPOCH,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        PROPOSER_INDEX,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

/// Honestly-signed genuine-invalid evidence. `failure_reason =
/// BadStateRoot` is also the reason the oracle will report, so
/// DSL-051 cannot hold against this fixture.
fn genuine() -> (InvalidBlockProof, MapView) {
    let sk = SecretKey::from_seed(&[0x01u8; 32]);
    let pk = sk.public_key();
    let header = sample_header();
    let msg = block_signing_message(&network_id(), header.epoch, &header.hash(), PROPOSER_INDEX);
    let sig = chia_bls::sign(&sk, &msg);

    let evidence = InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: header,
            signature: sig.to_bytes().to_vec(),
        },
        failure_witness: b"slasher witness".to_vec(),
        failure_reason: InvalidBlockReason::BadStateRoot,
    };

    let mut map = HashMap::new();
    map.insert(PROPOSER_INDEX, TestValidator { pk });
    (evidence, MapView(map))
}

fn rejected() -> AppealVerdict {
    AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    }
}

/// DSL-054 row 1: oracle returns `Invalid(BadStateRoot)` →
/// `BlockActuallyValid` ground does NOT hold → Rejected.
#[test]
fn test_dsl_054_block_valid_false_claim_rejected() {
    let (evidence, _view) = genuine();
    let oracle = InvalidOracle::new(InvalidBlockReason::BadStateRoot);

    assert_eq!(
        verify_invalid_block_appeal_block_actually_valid(
            &evidence,
            b"appeal witness",
            Some(&oracle as &dyn InvalidBlockOracle),
        ),
        rejected(),
    );
}

/// DSL-054 row 2: header is honestly signed →
/// `ProposerSignatureInvalid` ground does NOT hold → Rejected.
#[test]
fn test_dsl_054_sig_invalid_false_claim_rejected() {
    let (evidence, view) = genuine();
    assert_eq!(
        verify_invalid_block_appeal_proposer_signature_invalid(&evidence, &view, &network_id()),
        rejected(),
    );
}

/// DSL-054 row 3: oracle returns `Invalid(BadStateRoot)` and the
/// evidence claimed `BadStateRoot` → reasons match →
/// `FailureReasonMismatch` ground does NOT hold → Rejected.
#[test]
fn test_dsl_054_reason_mismatch_false_rejected() {
    let (evidence, _view) = genuine();
    let oracle = InvalidOracle::new(InvalidBlockReason::BadStateRoot);

    assert_eq!(
        verify_invalid_block_appeal_failure_reason_mismatch(
            &evidence,
            b"appeal witness",
            Some(&oracle as &dyn InvalidBlockOracle),
        ),
        rejected(),
    );
}

/// DSL-054 row 4: envelope epoch matches `header.epoch` (both = 5)
/// → `EvidenceEpochMismatch` ground does NOT hold → Rejected.
#[test]
fn test_dsl_054_epoch_mismatch_false_rejected() {
    let (evidence, _view) = genuine();
    assert_eq!(
        verify_invalid_block_appeal_evidence_epoch_mismatch(&evidence, HEADER_EPOCH),
        rejected(),
    );
}
