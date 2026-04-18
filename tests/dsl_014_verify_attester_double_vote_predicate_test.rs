//! Requirement DSL-014: `verify_attester_slashing` accepts evidence
//! where the two `AttestationData`s share the same `target.epoch` but
//! differ in content — the Ethereum-parity double-vote predicate.
//!
//! Traces to: docs/resources/SPEC.md §5.3, §22.2.
//!
//! # Role
//!
//! One of the two slashable attester predicates (the other is
//! surround-vote, DSL-015). A validator who signs two distinct
//! attestations for the same target epoch has equivocated at the FFG
//! finality layer — an unrecoverable consensus violation.
//!
//! # Predicate
//!
//! ```text
//! double_vote ⟺ a.data.target.epoch == b.data.target.epoch AND a.data != b.data
//! ```
//!
//! # Verifier scope (also enforced but not targeted by this suite)
//!
//! The underlying `verify_attester_slashing` function lands the full
//! attester-verification pipeline:
//!
//!   - structure validation (DSL-005 via `validate_structure`)
//!   - byte-identical rejection
//!   - **predicate decision (this DSL + DSL-015)**
//!   - empty-intersection rejection (DSL-016)
//!   - BLS aggregate verify both sides (DSL-006)
//!
//! Tests for DSL-015, DSL-016, DSL-017 cover the sibling paths in
//! subsequent commits.
//!
//! # Test matrix (maps to DSL-014 Test Plan)
//!
//!   1. `test_dsl_014_double_vote_accepted`
//!   2. `test_dsl_014_different_targets_not_double_vote_path`
//!   3. `test_dsl_014_identical_attestations_rejected`
//!   4. `test_dsl_014_bls_parity`
//!   5. `test_dsl_014_slashable_set_matches_intersection`
//!   6. `test_dsl_014_direct_call_parity`

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation,
    OffenseType, SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry,
    ValidatorView, verify_attester_slashing, verify_evidence,
};

// ── Validator fixtures ──────────────────────────────────────────────────

/// Minimal `ValidatorEntry` impl: always active, never slashed.
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

/// `HashMap`-backed view wiring `index → TestValidator`.
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

/// Build an attestation data with explicit target epoch + distinguishing
/// byte mixed into `beacon_block_root` so otherwise-identical target
/// epochs yield byte-different attestations (double-vote precondition).
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

/// Build a BLS-aggregate-signed `IndexedAttestation` across the given
/// committee indices. Each seed_byte offset is derived from
/// `(index, suffix)` so a single validator index in BOTH attestations
/// uses the SAME underlying secret key in both aggregates.
fn signed_attestation(indices: Vec<u32>, data: AttestationData) -> (IndexedAttestation, MapView) {
    let nid = network_id();
    let signing_root = data.signing_root(&nid);

    let mut sigs: Vec<Signature> = Vec::new();
    let mut map: HashMap<u32, TestValidator> = HashMap::new();
    for idx in &indices {
        // Seed byte derived ONLY from validator index → stable across
        // both attestations in a double-vote pair.
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

/// Build a FULL double-vote evidence pair. Both attestations share
/// `target.epoch` but differ in `beacon_block_root` (head vote). The
/// committee overlaps — any index appearing in both uses the SAME key
/// in both aggregates so the BLS verify passes on both sides.
fn double_vote_pair(
    reporter: u32,
    indices_a: Vec<u32>,
    indices_b: Vec<u32>,
    target_epoch: u64,
) -> (SlashingEvidence, MapView) {
    let data_a = make_data(target_epoch, 0xA1);
    let data_b = make_data(target_epoch, 0xB2);
    let (att_a, view_a) = signed_attestation(indices_a, data_a);
    let (att_b, view_b) = signed_attestation(indices_b, data_b);

    // Merge views — shared indices have the same key, so overwriting is
    // safe (idempotent).
    let mut merged = view_a.0;
    for (k, v) in view_b.0 {
        merged.insert(k, v);
    }

    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: target_epoch,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att_a,
            attestation_b: att_b,
        }),
    };
    (ev, MapView(merged))
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-014 row 1: valid double-vote evidence verifies.
///
/// Committee `{1, 3, 5, 7}` vs `{3, 5, 7, 9}`, same target epoch,
/// different head votes. Intersection `{3, 5, 7}` is slashable.
#[test]
fn test_dsl_014_double_vote_accepted() {
    let (ev, view) = double_vote_pair(99, vec![1, 3, 5, 7], vec![3, 5, 7, 9], 3);
    let verified =
        verify_evidence(&ev, &view, &network_id(), 3).expect("valid double-vote must verify");
    assert_eq!(verified.offense_type, OffenseType::AttesterDoubleVote);
    assert_eq!(verified.slashable_validator_indices, vec![3, 5, 7]);
}

/// DSL-014 row 2: different target epochs → NOT accepted via DSL-014
/// path. May still be accepted via DSL-015 surround-vote iff the
/// surround predicate holds; here we use non-surrounding windows so
/// the verifier rejects as `AttesterSlashingNotSlashable` (DSL-017).
#[test]
fn test_dsl_014_different_targets_not_double_vote_path() {
    // target_a = 3, target_b = 4, sources identical — no surround.
    let data_a = make_data(3, 0xA1);
    let data_b = make_data(4, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);
    let mut merged = view_a.0;
    for (k, v) in view_b.0 {
        merged.insert(k, v);
    }
    let view = MapView(merged);

    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 4,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att_a,
            attestation_b: att_b,
        }),
    };
    let err = verify_evidence(&ev, &view, &network_id(), 4)
        .expect_err("different targets + no surround must not use DSL-014 path");
    assert_eq!(err, SlashingError::AttesterSlashingNotSlashable);
}

/// DSL-014 row 3: byte-identical attestations rejected as
/// `InvalidAttesterSlashing("identical")`. Not a slashable offense —
/// mirrors DSL-041 appeal ground `AttestationsIdentical`.
#[test]
fn test_dsl_014_identical_attestations_rejected() {
    let data = make_data(3, 0xA1);
    let (att, view) = signed_attestation(vec![1, 3, 5], data);
    // Byte-identical second attestation: Clone the first.
    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 3,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att.clone(),
            attestation_b: att,
        }),
    };
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("byte-identical must reject");
    assert!(
        matches!(err, SlashingError::InvalidAttesterSlashing(ref s) if s.contains("identical")),
        "got {err:?}",
    );
}

/// DSL-014 row 4: verdict matches a direct `chia_bls::aggregate_verify`
/// reconstruction. Guards against a divergence where the verifier uses
/// a different augmentation scheme than DSL-006.
#[test]
fn test_dsl_014_bls_parity() {
    let (ev, view) = double_vote_pair(99, vec![1, 3, 5], vec![3, 5, 7], 3);
    let nid = network_id();

    // Verifier verdict.
    let verified_result = verify_evidence(&ev, &view, &nid, 3);

    // Direct reconstruction against attestation_a only (mirror for b).
    let SlashingEvidencePayload::Attester(att_pair) = &ev.payload else {
        panic!("sample is attester")
    };
    let signing_root_a = att_pair.attestation_a.data.signing_root(&nid);
    let pubkeys_a: Vec<PublicKey> = att_pair
        .attestation_a
        .attesting_indices
        .iter()
        .map(|i| *view.get(*i).expect("present").public_key())
        .collect();
    let sig_bytes_a: [u8; BLS_SIGNATURE_SIZE] = att_pair
        .attestation_a
        .signature
        .as_slice()
        .try_into()
        .unwrap();
    let sig_a = Signature::from_bytes(&sig_bytes_a).unwrap();
    let msg_a: &[u8] = signing_root_a.as_ref();
    let direct_a = chia_bls::aggregate_verify(&sig_a, pubkeys_a.iter().map(|pk| (pk, msg_a)));
    assert!(direct_a, "direct BLS verify on a must succeed");

    // Verifier verdict aligns with aggregate_verify verdicts on BOTH sides.
    assert!(
        verified_result.is_ok(),
        "verify_evidence must accept when direct BLS verifies on both sides: {verified_result:?}",
    );
}

/// DSL-014 row 5: `VerifiedEvidence.slashable_validator_indices` equals
/// the intersection computed by `AttesterSlashing::slashable_indices`
/// (DSL-007). Sorted + deduped.
#[test]
fn test_dsl_014_slashable_set_matches_intersection() {
    let (ev, view) = double_vote_pair(99, vec![1, 3, 5, 7, 9], vec![2, 3, 5, 7, 11], 3);
    let verified = verify_evidence(&ev, &view, &network_id(), 3).expect("valid must verify");

    let SlashingEvidencePayload::Attester(att_pair) = &ev.payload else {
        panic!("sample is attester");
    };
    let direct_intersection = att_pair.slashable_indices();
    assert_eq!(verified.slashable_validator_indices, direct_intersection);
    assert_eq!(verified.slashable_validator_indices, vec![3, 5, 7]);
}

/// DSL-014 row 6: `verify_attester_slashing` direct call returns the
/// same verdict as the `verify_evidence` dispatcher path. Guards
/// against an accidental dispatcher regression that bypasses this
/// verifier.
#[test]
fn test_dsl_014_direct_call_parity() {
    let (ev, view) = double_vote_pair(99, vec![1, 3, 5], vec![3, 5, 7], 3);
    let SlashingEvidencePayload::Attester(att) = &ev.payload else {
        panic!("sample is attester");
    };
    let direct = verify_attester_slashing(&ev, att, &view, &network_id()).expect("valid direct");
    let dispatch = verify_evidence(&ev, &view, &network_id(), 3).expect("valid dispatch");
    assert_eq!(direct, dispatch);
}
