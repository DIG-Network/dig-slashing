//! Requirement DSL-171: `AppealVerdict::to_appeal_outcome()` maps producer-side verdict to recorded-side `AppealOutcome` deterministically.
//!
//! Traces to: docs/resources/SPEC.md §3.8, §6.5.
//!
//! # Role
//!
//! Bridges the producer-side `AppealVerdict` (`Sustained { reason: AppealSustainReason }` / `Rejected { reason: AppealRejectReason }`) and the recorded-side `AppealOutcome` (`Won` / `Lost { reason_hash }` / `Pending`) with ONE canonical conversion. Consumed by DSL-167 `adjudicate_appeal` dispatcher to populate `AppealAdjudicationResult::outcome` + `AppealAttempt::outcome`.
//!
//! Before DSL-171, each adjudicator slice wrote its own ad-hoc conversion. With this canonical helper there's a single place the mapping lives, so:
//!
//!   - DSL-070 (Sustained → status Reverted, append AppealAttempt {outcome: Won}) uses this.
//!   - DSL-072 (Rejected → status ChallengeOpen, append AppealAttempt {outcome: Lost {reason_hash}}) uses this.
//!
//! # Mapping
//!
//! - `Sustained { .. }` → `Won`.
//! - `Rejected { reason }` → `Lost { reason_hash: SHA-256(bincode::serialize(reason)) }`.
//!
//! The hash is deterministic (bincode canonical + SHA-256). Distinct `AppealRejectReason` variants produce distinct hashes because the bincode variant-tag byte contributes.
//!
//! # Test matrix (maps to DSL-171 Test Plan)
//!
//!   1. `test_dsl_171_sustained_to_won` — every `AppealSustainReason` variant under `Sustained` maps to `Won`.
//!   2. `test_dsl_171_rejected_to_lost` — every `AppealRejectReason` variant under `Rejected` maps to `Lost { reason_hash }`; manually reconstruct `SHA-256(bincode(reason))` and assert byte-exact match.
//!   3. `test_dsl_171_deterministic` — repeated calls on the same verdict yield equal outputs.
//!   4. `test_dsl_171_distinct_reasons_distinct_hashes` — pairwise-distinct `reason_hash` across all `AppealRejectReason` variants.
//!   5. `test_dsl_171_never_pending` — exhaustive over every `AppealVerdict` value the crate can produce; no branch yields `Pending`.

use chia_sha2::Sha256;
use dig_protocol::Bytes32;
use dig_slashing::{AppealOutcome, AppealRejectReason, AppealSustainReason, AppealVerdict};

// ── helpers ──────────────────────────────────────────────────

/// Every sustain-reason variant — keep in sync with `src/appeal/verdict.rs`.
fn all_sustain_reasons() -> Vec<AppealSustainReason> {
    vec![
        AppealSustainReason::HeadersIdentical,
        AppealSustainReason::ProposerIndexMismatch,
        AppealSustainReason::SignatureAInvalid,
        AppealSustainReason::SignatureBInvalid,
        AppealSustainReason::SlotMismatch,
        AppealSustainReason::ValidatorNotActiveAtEpoch,
        AppealSustainReason::AttestationsIdentical,
        AppealSustainReason::NotSlashableByPredicate,
        AppealSustainReason::EmptyIntersection,
        AppealSustainReason::AttesterSignatureAInvalid,
        AppealSustainReason::AttesterSignatureBInvalid,
        AppealSustainReason::InvalidIndexedAttestationStructure,
        AppealSustainReason::ValidatorNotInIntersection,
        AppealSustainReason::BlockActuallyValid,
        AppealSustainReason::ProposerSignatureInvalid,
        AppealSustainReason::FailureReasonMismatch,
        AppealSustainReason::EvidenceEpochMismatch,
    ]
}

fn all_reject_reasons() -> Vec<AppealRejectReason> {
    vec![
        AppealRejectReason::GroundDoesNotHold,
        AppealRejectReason::MalformedWitness,
        AppealRejectReason::MissingOracle,
    ]
}

/// Manual reconstruction of the hash formula so row 2 is not a
/// tautology against the impl.
fn manual_reason_hash(reason: &AppealRejectReason) -> Bytes32 {
    let encoded = bincode::serialize(reason).expect("bincode ser");
    let mut h = Sha256::new();
    h.update(&encoded);
    let out: [u8; 32] = h.finalize();
    Bytes32::new(out)
}

// ── tests ──────────────────────────────────────────────────

/// DSL-171 row 1: `Sustained { .. }` maps to `Won` regardless of
/// inner reason variant. Exhaustive over all 17 sustain reasons.
///
/// Sustain reasons carry NO cryptographic contribution to the
/// outcome — the `Won` variant is a flat unit, not `Won { reason }`.
/// This is deliberate: downstream `AppealAttempt` records the
/// winning appeal via `winning_appeal_hash` (DSL-070), which
/// carries the full appeal identity. The verdict reason is
/// already captured in `AppealVerdict` itself — duplicating it
/// into AppealOutcome would diverge from the DSL-161 serde shape.
#[test]
fn test_dsl_171_sustained_to_won() {
    for reason in all_sustain_reasons() {
        let verdict = AppealVerdict::Sustained { reason };
        let outcome = verdict.to_appeal_outcome();
        assert_eq!(
            outcome,
            AppealOutcome::Won,
            "Sustained {{ reason: {reason:?} }} must map to Won",
        );
    }
}

/// DSL-171 row 2: `Rejected { reason }` maps to `Lost { reason_hash }`
/// where `reason_hash = SHA-256(bincode(reason))`.
///
/// Independently reconstructs the hash formula via
/// `manual_reason_hash` so the test is not a self-referential
/// tautology against the impl's code path.
#[test]
fn test_dsl_171_rejected_to_lost() {
    for reason in all_reject_reasons() {
        let verdict = AppealVerdict::Rejected { reason };
        let outcome = verdict.to_appeal_outcome();
        let expected = manual_reason_hash(&reason);

        match outcome {
            AppealOutcome::Lost { reason_hash } => {
                assert_eq!(
                    reason_hash, expected,
                    "Rejected {{ reason: {reason:?} }} must hash to SHA-256(bincode(reason))",
                );
            }
            other => panic!("expected Lost, got {other:?} for reason={reason:?}"),
        }
    }
}

/// DSL-171 row 3: conversion is deterministic — repeated calls on
/// the same verdict yield equal outputs.
///
/// Covers both branches: Sustained (trivial — `Won` is a unit
/// variant so equality follows) AND Rejected (non-trivial — the
/// bincode + SHA-256 path must be stateless across calls).
#[test]
fn test_dsl_171_deterministic() {
    let sustained = AppealVerdict::Sustained {
        reason: AppealSustainReason::HeadersIdentical,
    };
    assert_eq!(
        sustained.to_appeal_outcome(),
        sustained.to_appeal_outcome(),
        "Sustained deterministic",
    );

    let rejected = AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    };
    assert_eq!(
        rejected.to_appeal_outcome(),
        rejected.to_appeal_outcome(),
        "Rejected deterministic (bincode + SHA-256 is stateless)",
    );

    // Multiple rounds — guards against any hidden state that might
    // surface after repeated calls.
    for _ in 0..10 {
        assert_eq!(rejected.to_appeal_outcome(), rejected.to_appeal_outcome());
    }
}

/// DSL-171 row 4: distinct `AppealRejectReason` variants produce
/// distinct `reason_hash` values.
///
/// Critical for audit: `AppealAttempt { outcome: Lost { reason_hash } }`
/// is the only record linking a rejection back to its category.
/// If two reasons collided on hash, downstream analytics would
/// conflate GroundDoesNotHold rejections with MissingOracle
/// rejections, losing the distinction between "appeal is wrong
/// about the evidence" and "appeal is structurally incomplete".
///
/// Pairwise comparison across the full enum — O(n²) but n=3.
#[test]
fn test_dsl_171_distinct_reasons_distinct_hashes() {
    let reasons = all_reject_reasons();
    let hashes: Vec<Bytes32> = reasons
        .iter()
        .map(|r| {
            let verdict = AppealVerdict::Rejected { reason: *r };
            match verdict.to_appeal_outcome() {
                AppealOutcome::Lost { reason_hash } => reason_hash,
                _ => unreachable!("Rejected → Lost"),
            }
        })
        .collect();

    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "hashes for {:?} vs {:?} must differ",
                reasons[i], reasons[j],
            );
        }
    }
}

/// DSL-171 row 5: conversion NEVER yields `Pending`.
///
/// `Pending` is a transient state used INSIDE `AppealAttempt`
/// before adjudication runs (a mid-adjudication record). This
/// conversion runs AFTER adjudication produces a verdict, so the
/// output is always terminal (Won or Lost).
///
/// Exhaustive over every AppealVerdict value the crate can
/// construct — cross-products of variant × every sustain reason
/// + every reject reason.
#[test]
fn test_dsl_171_never_pending() {
    for reason in all_sustain_reasons() {
        let verdict = AppealVerdict::Sustained { reason };
        assert!(
            !matches!(verdict.to_appeal_outcome(), AppealOutcome::Pending),
            "Sustained must never yield Pending (reason={reason:?})",
        );
    }

    for reason in all_reject_reasons() {
        let verdict = AppealVerdict::Rejected { reason };
        assert!(
            !matches!(verdict.to_appeal_outcome(), AppealOutcome::Pending),
            "Rejected must never yield Pending (reason={reason:?})",
        );
    }
}
