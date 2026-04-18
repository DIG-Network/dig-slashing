//! Requirement DSL-053: InvalidBlock appeal grounds are split by
//! their oracle-dependency:
//!
//!   - Oracle-REQUIRING: `BlockActuallyValid` (DSL-049),
//!     `FailureReasonMismatch` (DSL-051). With `oracle: None`
//!     they MUST return `Rejected{MissingOracle}`.
//!   - Oracle-INDEPENDENT: `ProposerSignatureInvalid` (DSL-050),
//!     `EvidenceEpochMismatch` (DSL-052). These do not take an
//!     oracle at all and MUST produce a proper verdict regardless
//!     of whether a full node is reachable.
//!
//! Traces to: docs/resources/SPEC.md §6.4, §15.3, §22.6.
//!
//! # Role
//!
//! Contract fixture for light-client deployments — they cannot
//! re-execute blocks, so two of the four invalid-block grounds are
//! unavailable to them. Any drift in the verifier split (e.g., a
//! refactor that accidentally makes DSL-050 also require the
//! oracle) would break light-client parity and fail these tests.
//!
//! # Test matrix (maps to DSL-053 Test Plan)
//!
//!   1. `test_dsl_053_block_valid_no_oracle_err`
//!      — Ground `BlockActuallyValid`, `oracle: None` →
//!      `Rejected{MissingOracle}`
//!   2. `test_dsl_053_reason_mismatch_no_oracle_err`
//!      — Ground `FailureReasonMismatch`, `oracle: None` →
//!      `Rejected{MissingOracle}`
//!   3. `test_dsl_053_sig_invalid_no_oracle_ok`
//!      — Ground `ProposerSignatureInvalid` — verifier has NO
//!      oracle parameter; produces verdict normally (Rejected on
//!      an honest sig fixture)
//!   4. `test_dsl_053_epoch_mismatch_no_oracle_ok`
//!      — Ground `EvidenceEpochMismatch` — verifier has NO oracle
//!      parameter; produces verdict normally (Sustained on a
//!      mismatched fixture)

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, BLS_SIGNATURE_SIZE, InvalidBlockProof,
    InvalidBlockReason, SignedBlockHeader, ValidatorEntry, ValidatorView, block_signing_message,
    verify_invalid_block_appeal_block_actually_valid,
    verify_invalid_block_appeal_evidence_epoch_mismatch,
    verify_invalid_block_appeal_failure_reason_mismatch,
    verify_invalid_block_appeal_proposer_signature_invalid,
};

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

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn header_with_epoch(epoch: u64, proposer_index: u32) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        epoch,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        proposer_index,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn placeholder_evidence() -> InvalidBlockProof {
    InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: header_with_epoch(5, 1),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    }
}

/// DSL-053 row 1: `BlockActuallyValid` verifier called with
/// `oracle: None` MUST return `Rejected{MissingOracle}` — the
/// light-client bootstrap contract.
#[test]
fn test_dsl_053_block_valid_no_oracle_err() {
    let evidence = placeholder_evidence();

    let v = verify_invalid_block_appeal_block_actually_valid(&evidence, b"witness", None);
    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::MissingOracle,
        },
    );
}

/// DSL-053 row 2: `FailureReasonMismatch` with `oracle: None`
/// MUST return `Rejected{MissingOracle}`. Mirrors row 1 for the
/// other oracle-requiring ground.
#[test]
fn test_dsl_053_reason_mismatch_no_oracle_err() {
    let evidence = placeholder_evidence();

    let v = verify_invalid_block_appeal_failure_reason_mismatch(&evidence, b"witness", None);
    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::MissingOracle,
        },
    );
}

/// DSL-053 row 3: `ProposerSignatureInvalid` does NOT take an
/// oracle parameter — it is pure BLS. The verifier MUST produce a
/// normal verdict on an oracle-less call path. We prove this by
/// building a well-signed evidence fixture and asserting the
/// verifier rejects (sig is honest; ground does not hold).
#[test]
fn test_dsl_053_sig_invalid_no_oracle_ok() {
    // Build an honestly-signed evidence that the DSL-050 verifier
    // will REJECT (sig verifies). Any deterministic verdict proves
    // the verifier runs end-to-end without an oracle.
    let sk = SecretKey::from_seed(&[0x01u8; 32]);
    let pk = sk.public_key();
    let header = header_with_epoch(5, 7);
    let msg = block_signing_message(&network_id(), header.epoch, &header.hash(), 7);
    let sig = chia_bls::sign(&sk, &msg);

    let evidence = InvalidBlockProof {
        signed_header: SignedBlockHeader {
            message: header,
            signature: sig.to_bytes().to_vec(),
        },
        failure_witness: vec![],
        failure_reason: InvalidBlockReason::BadStateRoot,
    };

    let mut map = HashMap::new();
    map.insert(7u32, TestValidator { pk });
    let view = MapView(map);

    let v = verify_invalid_block_appeal_proposer_signature_invalid(&evidence, &view, &network_id());
    assert_eq!(
        v,
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-053 row 4: `EvidenceEpochMismatch` does NOT take an oracle
/// parameter — it is a pure local comparison. The verifier MUST
/// run without oracle and produce a verdict. We drive a mismatch
/// case and expect `Sustained{EvidenceEpochMismatch}`.
#[test]
fn test_dsl_053_epoch_mismatch_no_oracle_ok() {
    let evidence = placeholder_evidence(); // header.epoch = 5

    let v = verify_invalid_block_appeal_evidence_epoch_mismatch(&evidence, 6);
    assert_eq!(
        v,
        AppealVerdict::Sustained {
            reason: AppealSustainReason::EvidenceEpochMismatch,
        },
    );
}
