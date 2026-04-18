//! Requirement DSL-055: `SlashingManager::submit_appeal` MUST
//! reject `SlashingError::UnknownEvidence(hex_hash)` when
//! `appeal.evidence_hash` is not in the pending-slash book. Bond
//! MUST NOT be locked on this failure path.
//!
//! Traces to: docs/resources/SPEC.md §6.1, §7.2, §22.7.
//!
//! # Role
//!
//! Opens the submit_appeal precondition section. Subsequent DSLs
//! (DSL-056..063) extend the pipeline; this first slice locks in
//! the most basic invariant: a stale or misrouted appeal is
//! rejected cheaply, BEFORE any collateral operation.
//!
//! # Test matrix (maps to DSL-055 Test Plan)
//!
//!   1. `test_dsl_055_unknown_evidence_rejected`
//!      — fresh evidence_hash (book empty) → `UnknownEvidence`
//!   2. `test_dsl_055_bond_not_locked`
//!      — `TrackingBond` records zero `lock` calls on the reject path
//!   3. `test_dsl_055_hash_in_error`
//!      — `UnknownEvidence(String)` payload carries 64-char lowercase
//!      hex of the evidence hash

use dig_protocol::Bytes32;
use dig_slashing::{
    AttesterAppealGround, AttesterSlashingAppeal, BondError, BondEscrow, BondTag, SlashAppeal,
    SlashAppealPayload, SlashingError, SlashingManager,
};

/// Bond escrow that records every `lock` call. Tests assert
/// zero calls on the reject path — the precondition check must
/// run BEFORE any bond touch.
struct TrackingBond {
    lock_calls: u32,
}

impl TrackingBond {
    fn new() -> Self {
        Self { lock_calls: 0 }
    }
}

impl BondEscrow for TrackingBond {
    fn lock(&mut self, _principal_idx: u32, _amount: u64, _tag: BondTag) -> Result<(), BondError> {
        self.lock_calls += 1;
        Ok(())
    }
    fn release(
        &mut self,
        _principal_idx: u32,
        _amount: u64,
        _tag: BondTag,
    ) -> Result<(), BondError> {
        Ok(())
    }
    fn forfeit(
        &mut self,
        _principal_idx: u32,
        amount: u64,
        _tag: BondTag,
    ) -> Result<u64, BondError> {
        Ok(amount)
    }
    fn escrowed(&self, _principal_idx: u32, _tag: BondTag) -> u64 {
        0
    }
}

/// Build a minimal `SlashAppeal` for a given `evidence_hash`. The
/// payload shape is irrelevant for DSL-055 (only the hash lookup
/// runs). We pick an attester-appeal variant arbitrarily.
fn sample_appeal(evidence_hash: Bytes32) -> SlashAppeal {
    SlashAppeal {
        evidence_hash,
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        filed_epoch: 10,
        payload: SlashAppealPayload::Attester(AttesterSlashingAppeal {
            ground: AttesterAppealGround::AttestationsIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-055 row 1: fresh hash (empty book) → `UnknownEvidence`.
#[test]
fn test_dsl_055_unknown_evidence_rejected() {
    let mut manager = SlashingManager::new(10);
    let mut bond = TrackingBond::new();
    let hash = Bytes32::new([0xAAu8; 32]);
    let appeal = sample_appeal(hash);

    let err = manager.submit_appeal(&appeal, &mut bond).unwrap_err();
    assert!(
        matches!(err, SlashingError::UnknownEvidence(_)),
        "expected UnknownEvidence, got {err:?}"
    );
}

/// DSL-055 row 2: no bond lock on the UnknownEvidence path. The
/// precondition check MUST run before `BondEscrow::lock`. A
/// regression that moves the check after bond lock would make
/// this fail.
#[test]
fn test_dsl_055_bond_not_locked() {
    let mut manager = SlashingManager::new(10);
    let mut bond = TrackingBond::new();
    let appeal = sample_appeal(Bytes32::new([0xBBu8; 32]));

    let _ = manager.submit_appeal(&appeal, &mut bond);
    assert_eq!(
        bond.lock_calls, 0,
        "UnknownEvidence path must not touch the bond escrow"
    );
}

/// DSL-055 row 3: error variant carries lowercase hex of the
/// 32-byte evidence hash (64 chars). The stamp is
/// diagnostic-only; callers MUST NOT parse it for flow control
/// (they hold the original `Bytes32`).
#[test]
fn test_dsl_055_hash_in_error() {
    let mut manager = SlashingManager::new(10);
    let mut bond = TrackingBond::new();

    // Use a byte pattern where each byte is distinct so the hex
    // string has discriminating content.
    let mut raw = [0u8; 32];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = i as u8;
    }
    let hash = Bytes32::new(raw);
    let appeal = sample_appeal(hash);

    let err = manager.submit_appeal(&appeal, &mut bond).unwrap_err();
    match err {
        SlashingError::UnknownEvidence(hex) => {
            assert_eq!(hex.len(), 64, "32 bytes → 64 lowercase hex chars");
            assert!(
                hex.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "hex must be lowercase: {hex}"
            );
            // Expected encoding: 0x00, 0x01, ..., 0x1f
            let expected: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, expected);
        }
        other => panic!("expected UnknownEvidence, got {other:?}"),
    }
}
