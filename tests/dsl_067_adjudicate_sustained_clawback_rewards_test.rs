//! Requirement DSL-067: on `AppealVerdict::Sustained` the
//! adjudicator MUST claw back the optimistic whistleblower +
//! proposer rewards via `RewardClawback::claw_back`. Shortfall
//! (`expected - actually clawed`) is captured in
//! `ClawbackResult::shortfall` for DSL-073 bond absorption.
//!
//! Traces to: docs/resources/SPEC.md §6.5, §12.2, §22.8.
//!
//! # Formula
//!
//! `wb_amount = total_eff_bal / WHISTLEBLOWER_REWARD_QUOTIENT`
//! `prop_amount = wb_amount / PROPOSER_REWARD_QUOTIENT`
//!
//! Amounts are recomputed from
//! `pending.base_slash_per_validator[*].effective_balance_at_slash`
//! — same formula as DSL-022/025, so admission + adjudication
//! numbers agree by construction.
//!
//! # Test matrix (maps to DSL-067 Test Plan)
//!
//!   1. `test_dsl_067_wb_clawback_called` — call 0 is the
//!      reporter with `wb_amount`
//!   2. `test_dsl_067_prop_clawback_called` — call 1 is the
//!      proposer with `prop_amount`
//!   3. `test_dsl_067_full_clawback_no_shortfall` — mock returns
//!      full amount → shortfall == 0
//!   4. `test_dsl_067_partial_clawback_shortfall` — mock returns
//!      half → shortfall == expected - got

use std::cell::RefCell;

use dig_protocol::Bytes32;
use dig_slashing::{
    AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE,
    Checkpoint, ClawbackResult, IndexedAttestation, MIN_EFFECTIVE_BALANCE, OffenseType,
    PROPOSER_REWARD_QUOTIENT, PendingSlash, PendingSlashStatus, PerValidatorSlash, RewardClawback,
    SLASH_APPEAL_WINDOW_EPOCHS, SlashingEvidence, SlashingEvidencePayload, VerifiedEvidence,
    WHISTLEBLOWER_REWARD_QUOTIENT, adjudicate_sustained_clawback_rewards,
};

/// Recording clawback that replays a caller-supplied fraction of
/// the requested amount. `fraction_bps` of 10_000 means full; 0
/// means zero-return.
struct RecClawback {
    calls: RefCell<Vec<(Bytes32, u64)>>,
    fraction_bps: u64,
}

impl RecClawback {
    fn full() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            fraction_bps: 10_000,
        }
    }
    fn fraction(bps: u64) -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            fraction_bps: bps,
        }
    }
}

impl RewardClawback for RecClawback {
    fn claw_back(&mut self, principal_ph: Bytes32, amount: u64) -> u64 {
        self.calls.borrow_mut().push((principal_ph, amount));
        amount * self.fraction_bps / 10_000
    }
}

fn reporter_ph() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn proposer_ph() -> Bytes32 {
    Bytes32::new([0xBBu8; 32])
}

fn attester_evidence(reporter: Bytes32) -> SlashingEvidence {
    let data = AttestationData {
        slot: 0,
        index: 0,
        beacon_block_root: Bytes32::new([0u8; 32]),
        source: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
        target: Checkpoint {
            epoch: 0,
            root: Bytes32::new([0u8; 32]),
        },
    };
    let att = IndexedAttestation {
        attesting_indices: vec![1, 2],
        data,
        signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
    };
    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 99,
        reporter_puzzle_hash: reporter,
        epoch: 5,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    }
}

/// Build a pending slash with 2 validators at full
/// `MIN_EFFECTIVE_BALANCE` each → `total_eff_bal = 2 * MEB`.
fn pending_two_val() -> PendingSlash {
    PendingSlash {
        evidence_hash: Bytes32::new([0x11u8; 32]),
        evidence: attester_evidence(reporter_ph()),
        verified: VerifiedEvidence {
            offense_type: OffenseType::AttesterDoubleVote,
            slashable_validator_indices: vec![1, 2],
        },
        status: PendingSlashStatus::Accepted,
        submitted_at_epoch: 10,
        window_expires_at_epoch: 10 + SLASH_APPEAL_WINDOW_EPOCHS,
        base_slash_per_validator: vec![
            PerValidatorSlash {
                validator_index: 1,
                base_slash_amount: 1_000_000_000,
                effective_balance_at_slash: MIN_EFFECTIVE_BALANCE,
                collateral_slashed: 0,
            },
            PerValidatorSlash {
                validator_index: 2,
                base_slash_amount: 1_000_000_000,
                effective_balance_at_slash: MIN_EFFECTIVE_BALANCE,
                collateral_slashed: 0,
            },
        ],
        reporter_bond_mojos: 0,
        appeal_history: vec![],
    }
}

fn sustained() -> AppealVerdict {
    AppealVerdict::Sustained {
        reason: AppealSustainReason::AttestationsIdentical,
    }
}

fn expected_amounts() -> (u64, u64) {
    let total = 2 * MIN_EFFECTIVE_BALANCE;
    let wb = total / WHISTLEBLOWER_REWARD_QUOTIENT;
    let prop = wb / PROPOSER_REWARD_QUOTIENT;
    (wb, prop)
}

/// DSL-067 row 1: first `claw_back` call is the reporter with
/// `wb_amount`.
#[test]
fn test_dsl_067_wb_clawback_called() {
    let pending = pending_two_val();
    let (wb, _prop) = expected_amounts();
    let mut cb = RecClawback::full();

    let _ = adjudicate_sustained_clawback_rewards(&pending, &sustained(), &mut cb, proposer_ph());

    let calls = cb.calls.borrow();
    assert!(!calls.is_empty());
    assert_eq!(calls[0].0, reporter_ph(), "first call targets reporter");
    assert_eq!(calls[0].1, wb, "first call amount = wb_amount");
}

/// DSL-067 row 2: second call is the proposer with
/// `prop_amount`.
#[test]
fn test_dsl_067_prop_clawback_called() {
    let pending = pending_two_val();
    let (_wb, prop) = expected_amounts();
    let mut cb = RecClawback::full();

    let _ = adjudicate_sustained_clawback_rewards(&pending, &sustained(), &mut cb, proposer_ph());

    let calls = cb.calls.borrow();
    assert_eq!(calls.len(), 2, "exactly two claw_back calls");
    assert_eq!(calls[1].0, proposer_ph(), "second call targets proposer");
    assert_eq!(calls[1].1, prop, "second call amount = prop_amount");
}

/// DSL-067 row 3: full clawback (mock returns full amount) →
/// shortfall == 0.
#[test]
fn test_dsl_067_full_clawback_no_shortfall() {
    let pending = pending_two_val();
    let (wb, prop) = expected_amounts();
    let mut cb = RecClawback::full();

    let r = adjudicate_sustained_clawback_rewards(&pending, &sustained(), &mut cb, proposer_ph());
    assert_eq!(
        r,
        ClawbackResult {
            wb_amount: wb,
            prop_amount: prop,
            wb_clawed: wb,
            prop_clawed: prop,
            shortfall: 0,
        },
    );
}

/// DSL-067 row 4: partial clawback (mock returns 50%) →
/// shortfall = `(wb + prop) - (wb_clawed + prop_clawed)`.
#[test]
fn test_dsl_067_partial_clawback_shortfall() {
    let pending = pending_two_val();
    let (wb, prop) = expected_amounts();
    let mut cb = RecClawback::fraction(5_000); // 50%

    let r = adjudicate_sustained_clawback_rewards(&pending, &sustained(), &mut cb, proposer_ph());
    let wb_got = wb / 2;
    let prop_got = prop / 2;
    assert_eq!(r.wb_amount, wb);
    assert_eq!(r.prop_amount, prop);
    assert_eq!(r.wb_clawed, wb_got);
    assert_eq!(r.prop_clawed, prop_got);
    assert_eq!(r.shortfall, (wb + prop) - (wb_got + prop_got));
}
