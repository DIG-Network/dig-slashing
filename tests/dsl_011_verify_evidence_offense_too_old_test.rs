//! Requirement DSL-011: `verify_evidence` enforces the `SLASH_LOOKBACK_EPOCHS`
//! window as its FIRST precondition. Evidence with
//! `evidence.epoch + SLASH_LOOKBACK_EPOCHS < current_epoch` returns
//! `SlashingError::OffenseTooOld` before any BLS or validator-view work.
//!
//! Traces to: docs/resources/SPEC.md §5.1, §2.7, §22.2.
//!
//! # Role
//!
//! Cheap defensive filter. Two reasons the check is first:
//!
//!   - **Liveness:** the node prunes `SlashingManager::processed` entries
//!     older than `SLASH_LOOKBACK_EPOCHS + 1` (SPEC §1.11 pruning). Stale
//!     evidence past the window could be replayed through a dropped-dedup
//!     hole; rejecting at verify locks the dedup property even if pruning
//!     has already run.
//!   - **Cost:** lookback rejection costs a single `u64` compare;
//!     BLS aggregate verify costs ≥1 pairing. Putting the cheap filter
//!     first bounds mempool adversary cost.
//!
//! # Underflow safety
//!
//! The check is phrased `evidence.epoch + SLASH_LOOKBACK_EPOCHS <
//! current_epoch` — addition on the LHS — so `current_epoch = 0` cannot
//! underflow the RHS. Network boot and reorg-induced rollback to epoch 0
//! do not panic.
//!
//! # Test matrix (maps to DSL-011 Test Plan)
//!
//!   1. `test_dsl_011_at_boundary_accepted`        — epoch at exact boundary
//!   2. `test_dsl_011_beyond_boundary_rejected`    — one epoch past
//!   3. `test_dsl_011_error_fields_match`          — error carries inputs
//!   4. `test_dsl_011_current_zero_no_underflow`   — current = 0 stable
//!   5. `test_dsl_011_uses_dig_epoch_constant`     — re-export parity
//!   6. `test_dsl_011_same_epoch_accepted`         — epoch == current

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, InvalidBlockProof, InvalidBlockReason, OffenseType, SLASH_LOOKBACK_EPOCHS,
    SignedBlockHeader, SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry,
    ValidatorView, verify_evidence,
};

/// Empty validator set. DSL-011 short-circuits before any
/// `ValidatorView` method is called, so all impls can remain
/// unimplemented — but we still need a concrete type to pass by `&dyn`.
struct EmptyValidators;

impl ValidatorView for EmptyValidators {
    fn get(&self, _index: u32) -> Option<&dyn ValidatorEntry> {
        None
    }
    fn get_mut(&mut self, _index: u32) -> Option<&mut dyn ValidatorEntry> {
        None
    }
    fn len(&self) -> usize {
        0
    }
}

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn sample_header() -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
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

/// Build a minimal InvalidBlock envelope. DSL-011 is a
/// dispatcher-precondition test — payload content is irrelevant as long
/// as it reaches the OffenseTooOld branch. InvalidBlock is chosen
/// because its downstream verifier is still a placeholder accept
/// (DSL-018..020 land later), so the "accepted" paths in this suite
/// don't require a full BLS / validator-view setup. Proposer and
/// Attester variants would now drive their real verifiers (DSL-013,
/// DSL-014), which is out of scope here.
fn sample_evidence(offense_epoch: u64) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::InvalidBlock,
        reporter_validator_index: 17,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: offense_epoch,
        payload: SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: SignedBlockHeader {
                message: sample_header(),
                signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
            },
            failure_witness: vec![1, 2, 3],
            failure_reason: InvalidBlockReason::BadStateRoot,
        }),
    }
}

/// DSL-011 row 1: offense_epoch exactly at the boundary
/// `current_epoch - SLASH_LOOKBACK_EPOCHS` is accepted.
///
/// Using 2_000 as current means the boundary is 1_000 (since
/// SLASH_LOOKBACK_EPOCHS = 1_000): `1_000 + 1_000 = 2_000 >= 2_000`
/// satisfies the predicate.
#[test]
fn test_dsl_011_at_boundary_accepted() {
    let current_epoch = 2_000;
    let offense_epoch = current_epoch - SLASH_LOOKBACK_EPOCHS;
    let ev = sample_evidence(offense_epoch);
    let vv = EmptyValidators;

    let result = verify_evidence(&ev, &vv, &network_id(), current_epoch);
    assert!(result.is_ok(), "at-boundary must be accepted: {result:?}");
}

/// DSL-011 row 2: offense_epoch one epoch earlier than the boundary
/// is rejected with `OffenseTooOld`.
#[test]
fn test_dsl_011_beyond_boundary_rejected() {
    let current_epoch = 2_000;
    let offense_epoch = current_epoch - SLASH_LOOKBACK_EPOCHS - 1; // 999
    let ev = sample_evidence(offense_epoch);
    let vv = EmptyValidators;

    let err = verify_evidence(&ev, &vv, &network_id(), current_epoch)
        .expect_err("beyond-boundary must reject");
    assert!(
        matches!(err, SlashingError::OffenseTooOld { .. }),
        "must be OffenseTooOld, got {err:?}",
    );
}

/// DSL-011 row 3: the error variant carries both `offense_epoch` and
/// `current_epoch` set to exactly the input values — adjudicators use
/// these fields without re-deriving the delta.
#[test]
fn test_dsl_011_error_fields_match() {
    let current_epoch = 5_000;
    let offense_epoch = 100; // far older than 4_000 boundary
    let ev = sample_evidence(offense_epoch);
    let vv = EmptyValidators;

    let err = verify_evidence(&ev, &vv, &network_id(), current_epoch).unwrap_err();
    match err {
        SlashingError::OffenseTooOld {
            offense_epoch: got_offense,
            current_epoch: got_current,
        } => {
            assert_eq!(got_offense, offense_epoch);
            assert_eq!(got_current, current_epoch);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

/// DSL-011 row 4: `current_epoch = 0` must not underflow or panic.
///
/// The check is `evidence.epoch + SLASH_LOOKBACK_EPOCHS < 0`, which is
/// vacuously false for any non-negative u64 sum → evidence is accepted.
/// Also covers reorg-induced rollback to epoch 0.
#[test]
fn test_dsl_011_current_zero_no_underflow() {
    let ev = sample_evidence(0);
    let vv = EmptyValidators;
    let result = verify_evidence(&ev, &vv, &network_id(), 0);
    assert!(
        result.is_ok(),
        "current_epoch = 0 must not panic or underflow: {result:?}",
    );

    // Also: offense_epoch near u64::MAX with current=0 must not
    // overflow. `saturating_add` keeps the sum at u64::MAX.
    let ev_huge = sample_evidence(u64::MAX - 500);
    let result = verify_evidence(&ev_huge, &vv, &network_id(), 0);
    assert!(
        result.is_ok(),
        "saturating_add must guard against overflow on huge offense_epoch",
    );
}

/// DSL-011 row 5: the re-exported `SLASH_LOOKBACK_EPOCHS` MUST be
/// identical to the `dig_epoch` upstream value.
///
/// Guards against an accidental local redefinition.
#[test]
fn test_dsl_011_uses_dig_epoch_constant() {
    assert_eq!(SLASH_LOOKBACK_EPOCHS, dig_epoch::SLASH_LOOKBACK_EPOCHS);
    // Sanity: upstream value is 1_000 per CON-005.
    assert_eq!(SLASH_LOOKBACK_EPOCHS, 1_000u64);
}

/// DSL-011 row 6: `offense_epoch == current_epoch` is accepted (the
/// offense just happened). Guards against an off-by-one that would
/// reject same-epoch evidence.
#[test]
fn test_dsl_011_same_epoch_accepted() {
    let current_epoch = 42;
    let ev = sample_evidence(current_epoch);
    let vv = EmptyValidators;
    let result = verify_evidence(&ev, &vv, &network_id(), current_epoch);
    assert!(result.is_ok(), "same-epoch must be accepted: {result:?}");
}
