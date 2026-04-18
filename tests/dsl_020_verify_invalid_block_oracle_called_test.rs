//! Requirement DSL-020: when a caller supplies an `InvalidBlockOracle`,
//! `verify_invalid_block` MUST call `oracle.verify_failure(header,
//! witness, reason)` and propagate any `Err`. Without an oracle, the
//! default path accepts — bootstrap mode defers correctness to the
//! challenge window.
//!
//! Traces to: docs/resources/SPEC.md §5.4, §15.3, §22.2.
//!
//! # Role
//!
//! Full-nodes re-execute the accused block to confirm invalidity
//! before admitting evidence — the oracle hook is how `dig-slashing`
//! outsources the re-execution to `dig-block` / `dig-clvm` (the
//! execution engines). Light clients pass `None`, trusting the 8-epoch
//! appeal window to surface false positives.
//!
//! # Default impl
//!
//! `InvalidBlockOracle::verify_failure` has a default body returning
//! `Ok(())` — bootstrap semantics. Real full-node impls override. The
//! `re_execute` method has NO default (every real impl must actually
//! re-execute). Tests exercise both.
//!
//! # Appeal mirror
//!
//! `InvalidBlockAppeal::BlockActuallyValid` (DSL-049) uses
//! `re_execute` to adjudicate. `MissingOracle` error (DSL-053) is
//! raised by appeal code when the appellant tries the `BlockActuallyValid`
//! ground without an oracle configured.
//!
//! # Test matrix (maps to DSL-020 Test Plan)
//!
//!   1. `test_dsl_020_oracle_called_when_supplied` — records args
//!   2. `test_dsl_020_oracle_error_propagates`
//!   3. `test_dsl_020_oracle_none_skipped`
//!   4. `test_dsl_020_default_impl_accepts`
//!   5. `test_dsl_020_called_with_matching_args` — header/witness/reason
//!   6. `test_dsl_020_runs_after_bls_verify` — ordering

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    ExecutionOutcome, InvalidBlockOracle, InvalidBlockProof, InvalidBlockReason, OffenseType,
    SignedBlockHeader, SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry,
    ValidatorView, block_signing_message, verify_evidence, verify_invalid_block,
};

// ── Validator fixtures ──────────────────────────────────────────────────

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

// ── Oracle mocks ────────────────────────────────────────────────────────

/// Counting oracle: records each `verify_failure` call + the arguments.
struct RecordingOracle {
    calls: RefCell<Vec<(L2BlockHeader, Vec<u8>, InvalidBlockReason)>>,
    verdict: Result<(), SlashingError>,
}

impl RecordingOracle {
    fn accepting() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            verdict: Ok(()),
        }
    }
}

impl InvalidBlockOracle for RecordingOracle {
    fn verify_failure(
        &self,
        header: &L2BlockHeader,
        witness: &[u8],
        reason: InvalidBlockReason,
    ) -> Result<(), SlashingError> {
        self.calls
            .borrow_mut()
            .push((header.clone(), witness.to_vec(), reason));
        self.verdict.clone()
    }
    fn re_execute(
        &self,
        _header: &L2BlockHeader,
        _witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError> {
        unreachable!("re_execute not called by DSL-020 path")
    }
}

/// Oracle that relies ENTIRELY on the default `verify_failure` impl
/// (no override). Proves the bootstrap default returns `Ok(())`.
struct DefaultOnlyOracle;

impl InvalidBlockOracle for DefaultOnlyOracle {
    fn re_execute(
        &self,
        _header: &L2BlockHeader,
        _witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError> {
        unreachable!("re_execute not called by DSL-020 path")
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn sample_header(proposer_index: u32, epoch: u64) -> L2BlockHeader {
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

/// Build a honestly-signed invalid-block evidence fixture. Returns
/// (evidence, view, witness, reason) so tests can cross-check the
/// oracle's recorded args.
fn fixture() -> (
    SlashingEvidence,
    MapView,
    Vec<u8>,
    InvalidBlockReason,
    L2BlockHeader,
) {
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header = sample_header(9, 3);
    let msg = block_signing_message(
        &network_id(),
        header.epoch,
        &header.hash(),
        header.proposer_index,
    );
    let sig = chia_bls::sign(&sk, msg).to_bytes().to_vec();

    let witness = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let reason = InvalidBlockReason::BadStateRoot;

    let mut map = HashMap::new();
    map.insert(9u32, TestValidator { pk });

    let ev = SlashingEvidence {
        offense_type: OffenseType::InvalidBlock,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 3,
        payload: SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: SignedBlockHeader {
                message: header.clone(),
                signature: sig,
            },
            failure_witness: witness.clone(),
            failure_reason: reason,
        }),
    };
    (ev, MapView(map), witness, reason, header)
}

fn payload(ev: &SlashingEvidence) -> &InvalidBlockProof {
    match &ev.payload {
        SlashingEvidencePayload::InvalidBlock(p) => p,
        _ => panic!("expected invalid-block"),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-020 row 1: oracle supplied → `verify_failure` called exactly
/// once. Counter on the mock confirms the call count.
#[test]
fn test_dsl_020_oracle_called_when_supplied() {
    let (ev, view, _, _, _) = fixture();
    let oracle = RecordingOracle::accepting();
    let result = verify_invalid_block(&ev, payload(&ev), &view, &network_id(), Some(&oracle));
    assert!(
        result.is_ok(),
        "honest fixture + default-ok oracle must verify"
    );
    assert_eq!(oracle.calls.borrow().len(), 1, "oracle must be called once");
}

/// DSL-020 row 2: oracle returns `Err` → error propagates verbatim.
#[test]
fn test_dsl_020_oracle_error_propagates() {
    let (ev, view, _, _, _) = fixture();
    let oracle = RecordingOracle {
        calls: RefCell::new(Vec::new()),
        verdict: Err(SlashingError::InvalidSlashingEvidence(
            "oracle disagrees: re-execution was valid".into(),
        )),
    };
    let err = verify_invalid_block(&ev, payload(&ev), &view, &network_id(), Some(&oracle))
        .expect_err("oracle err must propagate");
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(ref s) if s.contains("oracle disagrees")),
        "got {err:?}",
    );
    assert_eq!(oracle.calls.borrow().len(), 1);
}

/// DSL-020 row 3: oracle = None → bootstrap mode; oracle never called.
/// Confirmed by using the dispatcher path (which always passes `None`)
/// and a direct call with explicit `None`.
#[test]
fn test_dsl_020_oracle_none_skipped() {
    let (ev, view, _, _, _) = fixture();
    // Direct call with None.
    let direct = verify_invalid_block(&ev, payload(&ev), &view, &network_id(), None);
    assert!(direct.is_ok(), "None oracle must accept: {direct:?}");
    // Dispatcher path.
    let dispatch = verify_evidence(&ev, &view, &network_id(), 3);
    assert!(dispatch.is_ok(), "dispatcher must accept: {dispatch:?}");
}

/// DSL-020 row 4: the default `verify_failure` impl returns `Ok(())`.
/// Proves the trait default is bootstrap-safe — a minimal impl that
/// only provides `re_execute` still admits evidence under DSL-020.
#[test]
fn test_dsl_020_default_impl_accepts() {
    let (ev, view, _, _, _) = fixture();
    let oracle = DefaultOnlyOracle;
    let result = verify_invalid_block(&ev, payload(&ev), &view, &network_id(), Some(&oracle));
    assert!(
        result.is_ok(),
        "default verify_failure must return Ok: {result:?}",
    );
}

/// DSL-020 row 5: oracle receives the EXACT header / witness / reason
/// from the evidence payload. Guards against an argument shuffle in
/// the call site.
#[test]
fn test_dsl_020_called_with_matching_args() {
    let (ev, view, witness, reason, header) = fixture();
    let oracle = RecordingOracle::accepting();
    verify_invalid_block(&ev, payload(&ev), &view, &network_id(), Some(&oracle))
        .expect("must verify");

    let calls = oracle.calls.borrow();
    assert_eq!(calls.len(), 1);
    let (got_header, got_witness, got_reason) = &calls[0];
    assert_eq!(got_header, &header, "header argument must match");
    assert_eq!(got_witness, &witness, "witness argument must match");
    assert_eq!(got_reason, &reason, "reason argument must match");
}

/// DSL-020 row 6: oracle runs AFTER BLS verify. Corrupt the signature
/// and supply an oracle that would record its call — the BLS failure
/// MUST surface first and the oracle MUST NOT be called.
#[test]
fn test_dsl_020_runs_after_bls_verify() {
    let (mut ev, view, _, _, _) = fixture();
    // Corrupt sig — keep 96 bytes so it passes width/decode checks
    // (0x00 often decodes to identity; use a wrong honest-style sig).
    let wrong_sk = make_sk(0xEE);
    if let SlashingEvidencePayload::InvalidBlock(p) = &mut ev.payload {
        let msg = block_signing_message(
            &network_id(),
            p.signed_header.message.epoch,
            &p.signed_header.message.hash(),
            p.signed_header.message.proposer_index,
        );
        p.signed_header.signature = chia_bls::sign(&wrong_sk, msg).to_bytes().to_vec();
    }
    let oracle = RecordingOracle::accepting();
    let err = verify_invalid_block(&ev, payload(&ev), &view, &network_id(), Some(&oracle))
        .expect_err("bad sig must reject");
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(ref s) if s.contains("signature")),
        "BLS failure must surface before oracle; got {err:?}",
    );
    assert_eq!(
        oracle.calls.borrow().len(),
        0,
        "oracle MUST NOT be called after BLS failure",
    );
}
