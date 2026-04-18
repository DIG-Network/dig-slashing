//! Requirement DSL-016: `verify_attester_slashing` rejects with
//! `SlashingError::EmptySlashableIntersection` when
//! `AttesterSlashing::slashable_indices()` returns an empty set —
//! i.e. no validator participated in BOTH attestations.
//!
//! Traces to: docs/resources/SPEC.md §5.3, §22.2.
//!
//! # Role
//!
//! Even when the double-vote (DSL-014) or surround-vote (DSL-015)
//! predicate holds on the `AttestationData`s, the evidence is only
//! actionable if at least one validator is caught on both sides. A
//! disjoint-committee "equivocation" is cryptographically well-formed
//! but slashes nobody — reject early.
//!
//! # Ordering guarantee
//!
//! The check MUST run:
//!   - AFTER structure validation (DSL-005)
//!   - AFTER byte-identical rejection
//!   - AFTER predicate decision (DSL-014/015)
//!   - BEFORE BLS aggregate verify (DSL-006)
//!
//! Rationale: aggregate BLS verify is the single most expensive
//! operation in the verifier. Disjoint-committee evidence is a
//! trivially-constructed DoS vector; rejecting at the cheap
//! intersection check before BLS bounds adversary cost.
//!
//! Mirrored at the appeal layer by `AttesterAppealGround::EmptyIntersection`
//! (DSL-043).
//!
//! # Test matrix (maps to DSL-016 Test Plan)
//!
//!   1. `test_dsl_016_disjoint_rejected`
//!   2. `test_dsl_016_non_empty_passes`
//!   3. `test_dsl_016_runs_before_bls_verify` — disjoint + bad sigs,
//!      still EmptySlashableIntersection (not BlsVerifyFailed)
//!   4. `test_dsl_016_single_element_intersection_passes` — boundary
//!   5. `test_dsl_016_runs_after_predicate_decision` — disjoint + no
//!      predicate holds → AttesterSlashingNotSlashable wins (predicate
//!      runs first)

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    OffenseType, SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry,
    ValidatorView, verify_evidence,
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

// ── Attestation construction ────────────────────────────────────────────

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_key(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn make_data(target_epoch: u64, head_vote_byte: u8) -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([head_vote_byte; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: target_epoch,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}

fn signed_attestation(indices: Vec<u32>, data: AttestationData) -> (IndexedAttestation, MapView) {
    let nid = network_id();
    let signing_root = data.signing_root(&nid);
    let mut sigs: Vec<Signature> = Vec::new();
    let mut map: HashMap<u32, TestValidator> = HashMap::new();
    for idx in &indices {
        let sk = make_key(*idx as u8);
        let pk = sk.public_key();
        sigs.push(chia_bls::sign(&sk, signing_root.as_ref()));
        map.insert(*idx, TestValidator { pk });
    }
    let agg = chia_bls::aggregate(&sigs);
    let att = IndexedAttestation {
        attesting_indices: indices,
        data,
        signature: agg.to_bytes().to_vec(),
    };
    (att, MapView(map))
}

fn merge(a: MapView, b: MapView) -> MapView {
    let mut merged = a.0;
    for (k, v) in b.0 {
        merged.insert(k, v);
    }
    MapView(merged)
}

/// Build a double-vote envelope with explicit disjoint/overlap
/// control. Same target epoch + different head byte → predicate
/// holds; intersection is caller-chosen.
fn envelope(indices_a: Vec<u32>, indices_b: Vec<u32>) -> (SlashingEvidence, MapView) {
    let data_a = make_data(3, 0xA1);
    let data_b = make_data(3, 0xB2);
    let (att_a, view_a) = signed_attestation(indices_a, data_a);
    let (att_b, view_b) = signed_attestation(indices_b, data_b);
    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 999,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 3,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att_a,
            attestation_b: att_b,
        }),
    };
    (ev, merge(view_a, view_b))
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-016 row 1: disjoint indices + valid predicate (double-vote) →
/// `EmptySlashableIntersection`.
#[test]
fn test_dsl_016_disjoint_rejected() {
    let (ev, view) = envelope(vec![1, 2, 3], vec![4, 5, 6]);
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("disjoint committees must reject");
    assert_eq!(err, SlashingError::EmptySlashableIntersection);
}

/// DSL-016 row 2: non-empty intersection + valid predicate passes
/// through the check (and the rest of the pipeline, on valid fixtures).
#[test]
fn test_dsl_016_non_empty_passes() {
    let (ev, view) = envelope(vec![1, 2, 3], vec![2, 3, 4]);
    let verified =
        verify_evidence(&ev, &view, &network_id(), 3).expect("non-empty intersection must pass");
    assert_eq!(verified.slashable_validator_indices, vec![2, 3]);
}

/// DSL-016 row 3: disjoint indices + deliberately bad signatures →
/// `EmptySlashableIntersection` wins because intersection check runs
/// BEFORE BLS verify. Proves honest nodes don't pay pairing cost on
/// adversarial disjoint-committee evidence.
#[test]
fn test_dsl_016_runs_before_bls_verify() {
    let (mut ev, view) = envelope(vec![1, 2, 3], vec![4, 5, 6]);
    if let SlashingEvidencePayload::Attester(p) = &mut ev.payload {
        // Corrupt BOTH signatures — if BLS ran first, we'd get
        // BlsVerifyFailed; if intersection ran first, we get
        // EmptySlashableIntersection.
        p.attestation_a.signature = vec![0xFFu8; BLS_SIGNATURE_SIZE];
        p.attestation_b.signature = vec![0xFFu8; BLS_SIGNATURE_SIZE];
    }
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("disjoint must reject before BLS");
    assert_eq!(
        err,
        SlashingError::EmptySlashableIntersection,
        "intersection check MUST run before BLS verify",
    );
}

/// DSL-016 row 4: single-element intersection — boundary between empty
/// and non-empty — passes the check.
#[test]
fn test_dsl_016_single_element_intersection_passes() {
    let (ev, view) = envelope(vec![1, 2, 3], vec![3, 4, 5]);
    let verified = verify_evidence(&ev, &view, &network_id(), 3).expect("single-overlap must pass");
    assert_eq!(verified.slashable_validator_indices, vec![3]);
}

/// DSL-016 row 5: when BOTH the predicate fails AND the intersection
/// is empty, `AttesterSlashingNotSlashable` surfaces first (predicate
/// decision precedes intersection check in the verifier order). Locks
/// the ordering invariant from the other direction.
#[test]
fn test_dsl_016_runs_after_predicate_decision() {
    // Different target epochs + sources preventing surround → neither
    // predicate holds; committees also disjoint.
    let data_a = make_data(3, 0xA1);
    let data_b = make_data(4, 0xB2); // different target, no surround (sources identical at 2)
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![10, 11, 12], data_b);
    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 999,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 4,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att_a,
            attestation_b: att_b,
        }),
    };
    let view = merge(view_a, view_b);
    let err = verify_evidence(&ev, &view, &network_id(), 4).expect_err("non-slashable must reject");
    assert_eq!(
        err,
        SlashingError::AttesterSlashingNotSlashable,
        "predicate failure MUST surface before intersection check",
    );
}
