//! Requirement DSL-106: `enforce_slashing_evidence_mempool_policy`
//! rejects any evidence whose
//! `epoch + SLASH_LOOKBACK_EPOCHS < current_epoch` via the
//! `OffenseTooOld` error variant (SPEC §17.1 folds the
//! doc-level `OutsideLookback` name into the unified
//! `SlashingError::OffenseTooOld`; the mempool guard and
//! DSL-011 `verify_evidence` share the same predicate).
//!
//! Traces to: docs/resources/SPEC.md §16.3, §2.7, §22.12.
//!
//! # Role
//!
//! Mempool policy runs BEFORE admission (DSL-104) as a cheap
//! pre-filter: stale evidence for an offense outside the lookback
//! window can never be slashed regardless of verifier outcome, so
//! there is no point spending BLS work on it. Matches DSL-011 at
//! the verify layer — the two checks are redundant by design so
//! the mempool drops the payload before it ever reaches an
//! evaluator.
//!
//! # Boundary arithmetic
//!
//! The check is phrased with addition on the LHS
//! (`ev.epoch + SLASH_LOOKBACK_EPOCHS < current_epoch`) to avoid
//! underflow when `current_epoch < SLASH_LOOKBACK_EPOCHS`
//! (genesis / network boot). At the exact boundary
//! `ev.epoch == current_epoch - SLASH_LOOKBACK_EPOCHS`, the
//! condition is `current_epoch < current_epoch` → false → ok.
//!
//! # Test matrix (maps to DSL-106 Test Plan + acceptance)
//!
//!   1. `test_dsl_106_expired_rejected` — ev.epoch=0, current=
//!      LOOKBACK + 50 → OffenseTooOld with both fields
//!      populated correctly
//!   2. `test_dsl_106_boundary_ok` — ev.epoch == current -
//!      LOOKBACK → Ok (strict `<` excludes the boundary)
//!   3. `test_dsl_106_within_window_ok` — ev.epoch = current -
//!      5 → Ok (well inside the window)
//!   4. `test_dsl_106_pre_lookback_network_ok` — current_epoch
//!      <= LOOKBACK → every evidence passes (underflow guard)
//!   5. `test_dsl_106_first_expired_short_circuits` — mixed
//!      bundle; first expired evidence halts iteration

use std::collections::HashMap;

use chia_bls::Signature;
use chia_protocol::{Bytes, Coin, CoinSpend, Program, SpendBundle};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, OffenseType, ProposerSlashing, SLASH_LOOKBACK_EPOCHS, SignedBlockHeader,
    SlashingError, SlashingEvidence, SlashingEvidencePayload,
    encode_slashing_evidence_remark_payload_v1, enforce_slashing_evidence_mempool_policy,
    slashing_evidence_remark_puzzle_hash_v1, slashing_evidence_remark_puzzle_reveal_v1,
};

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

fn evidence_at_epoch(epoch: u64, state_byte: u8) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        epoch,
        reporter_validator_index: 11,
        reporter_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: SignedBlockHeader {
                message: sample_header(state_byte),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            signed_header_b: SignedBlockHeader {
                message: sample_header(state_byte ^ 0xFF),
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
        }),
    }
}

/// Build a single-spend bundle carrying the given evidence as the
/// sole REMARK payload. Returns (bundle, conditions) so tests can
/// pass them into the policy check directly.
///
/// The coin's `puzzle_hash` is set to the DSL-103-derived value
/// even though DSL-106 itself ignores puzzle-hash commitment
/// (that's DSL-104/105's job). This keeps fixtures re-usable
/// across the whole DSL-104..109 family.
fn bundle_with(ev: &SlashingEvidence) -> (SpendBundle, HashMap<Bytes32, Vec<Vec<u8>>>) {
    let reveal = slashing_evidence_remark_puzzle_reveal_v1(ev).unwrap();
    let ph = slashing_evidence_remark_puzzle_hash_v1(ev).unwrap();
    let coin = Coin::new(Bytes32::new([0u8; 32]), ph, 1);
    let spend = CoinSpend::new(
        coin,
        Program::from(Bytes::new(reveal)),
        Program::from(Bytes::new(vec![0x80])),
    );
    let wire = encode_slashing_evidence_remark_payload_v1(ev).unwrap();
    let mut conditions: HashMap<Bytes32, Vec<Vec<u8>>> = HashMap::new();
    conditions.insert(spend.coin.coin_id(), vec![wire]);
    let bundle = SpendBundle::new(vec![spend], Signature::default());
    (bundle, conditions)
}

/// DSL-106 row 1: epoch-0 evidence + current_epoch well beyond
/// the lookback window is rejected with OffenseTooOld carrying
/// both epochs verbatim.
#[test]
fn test_dsl_106_expired_rejected() {
    let current = SLASH_LOOKBACK_EPOCHS + 50;
    let ev = evidence_at_epoch(0, 0x02);
    let (bundle, conditions) = bundle_with(&ev);

    let err = enforce_slashing_evidence_mempool_policy(&bundle, &conditions, current)
        .expect_err("expired evidence must reject");

    let SlashingError::OffenseTooOld {
        offense_epoch,
        current_epoch,
    } = err
    else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(offense_epoch, 0, "error carries the evidence's epoch");
    assert_eq!(
        current_epoch, current,
        "error carries the current_epoch argument",
    );
}

/// DSL-106 row 2 (acceptance bullet 2): boundary case — the
/// exact epoch `current - LOOKBACK` is still admissible because
/// the predicate uses strict `<`, not `<=`.
#[test]
fn test_dsl_106_boundary_ok() {
    let current = SLASH_LOOKBACK_EPOCHS + 50;
    let boundary = current - SLASH_LOOKBACK_EPOCHS;
    let ev = evidence_at_epoch(boundary, 0x11);
    let (bundle, conditions) = bundle_with(&ev);

    enforce_slashing_evidence_mempool_policy(&bundle, &conditions, current)
        .expect("boundary epoch must admit (strict `<` excludes equality)");
}

/// DSL-106 row 3 (acceptance bullet 3): well-inside case — an
/// epoch a few steps before current is obviously fine.
#[test]
fn test_dsl_106_within_window_ok() {
    let current = SLASH_LOOKBACK_EPOCHS + 100;
    let ev = evidence_at_epoch(current - 5, 0x22);
    let (bundle, conditions) = bundle_with(&ev);

    enforce_slashing_evidence_mempool_policy(&bundle, &conditions, current)
        .expect("in-window evidence must admit");
}

/// DSL-106 underflow guard: when the chain is younger than the
/// lookback window, the "too old" predicate cannot fire. Any
/// evidence epoch <= current_epoch must pass. We test at
/// boundary `current_epoch == SLASH_LOOKBACK_EPOCHS` AND at
/// `current_epoch = 0`.
#[test]
fn test_dsl_106_pre_lookback_network_ok() {
    // current == LOOKBACK — boundary of the guard
    let current = SLASH_LOOKBACK_EPOCHS;
    let ev = evidence_at_epoch(0, 0x33);
    let (bundle, conditions) = bundle_with(&ev);
    enforce_slashing_evidence_mempool_policy(&bundle, &conditions, current)
        .expect("current == LOOKBACK + ev.epoch=0 must admit (guard)");

    // genesis: current == 0, ev at epoch 0 (only admissible epoch)
    let genesis_ev = evidence_at_epoch(0, 0x44);
    let (bundle, conditions) = bundle_with(&genesis_ev);
    enforce_slashing_evidence_mempool_policy(&bundle, &conditions, 0)
        .expect("current == 0 + ev.epoch=0 must admit");
}

/// DSL-106 bonus: in a multi-spend bundle the policy fails fast
/// on the first expired evidence. A later still-valid evidence
/// behind it is NOT evaluated — this is important for DoS cost
/// containment because the policy runs on un-verified payloads.
#[test]
fn test_dsl_106_first_expired_short_circuits() {
    let current = SLASH_LOOKBACK_EPOCHS + 100;
    let expired = evidence_at_epoch(0, 0x55);
    let still_ok = evidence_at_epoch(current - 2, 0x66);

    let (mut bundle, mut conditions) = bundle_with(&expired);
    // Append the still-ok spend.
    let (ok_bundle, ok_conds) = bundle_with(&still_ok);
    bundle.coin_spends.extend(ok_bundle.coin_spends);
    for (k, v) in ok_conds {
        conditions.insert(k, v);
    }

    let err = enforce_slashing_evidence_mempool_policy(&bundle, &conditions, current)
        .expect_err("expired evidence anywhere in the bundle must reject");

    let SlashingError::OffenseTooOld { offense_epoch, .. } = err else {
        panic!("wrong variant: {err:?}");
    };
    assert_eq!(
        offense_epoch, 0,
        "error must carry the FIRST expired evidence's epoch (0), \
         not the later still-ok one",
    );
}
