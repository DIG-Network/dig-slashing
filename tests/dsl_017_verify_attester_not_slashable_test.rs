//! Requirement DSL-017: `verify_attester_slashing` rejects with
//! `SlashingError::AttesterSlashingNotSlashable` when NEITHER the
//! double-vote (DSL-014) NOR the surround-vote (DSL-015) predicate
//! holds on the two `AttestationData`s.
//!
//! Traces to: docs/resources/SPEC.md §5.3, §22.2.
//!
//! # Role
//!
//! Third-stage filter in the attester pipeline. An envelope may be
//! structurally valid and byte-different yet still describe a pair of
//! attestations that are NOT slashable — e.g. two attestations of the
//! same validator at different target epochs with non-overlapping FFG
//! windows. Reject before paying BLS pairing cost.
//!
//! # Combined coverage with DSL-014 + DSL-015
//!
//! The two predicates cover all slashable cases per Ethereum/DIG
//! consensus:
//!   - same target + different data → DSL-014 double-vote
//!   - strict surround → DSL-015 surround-vote
//!
//! This suite verifies the COMPLEMENT: every case where neither holds
//! yields `AttesterSlashingNotSlashable`.
//!
//! # Mirrors
//!
//! Appeal ground `AttesterAppealGround::NotSlashableByPredicate`
//! (DSL-042) inverts this — appellant proves neither predicate holds
//! even though the slasher claimed one did.
//!
//! # Test matrix (maps to DSL-017 Test Plan)
//!
//!   1. `test_dsl_017_non_overlapping_epochs_rejected`
//!   2. `test_dsl_017_same_target_same_data_not_this_error`
//!   3. `test_dsl_017_double_vote_not_this_error`
//!   4. `test_dsl_017_surround_vote_not_this_error`
//!   5. `test_dsl_017_equal_source_nonequal_target_rejected`
//!   6. `test_dsl_017_nested_but_not_strict_rejected`

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, Checkpoint, IndexedAttestation, OffenseType, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, ValidatorEntry, ValidatorView, verify_evidence,
};

// ── Validator fixtures (consistent with DSL-014/015/016) ────────────────

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

fn make_key(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn make_data(source_epoch: u64, target_epoch: u64, head_vote_byte: u8) -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([head_vote_byte; 32]),
        source: Checkpoint {
            epoch: source_epoch,
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

fn envelope(att_a: IndexedAttestation, att_b: IndexedAttestation) -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: 999,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 10,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att_a,
            attestation_b: att_b,
        }),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-017 row 1: non-overlapping epoch windows — disjoint FFG votes
/// with no surround either direction → `AttesterSlashingNotSlashable`.
///
/// `a`: src=1, tgt=2. `b`: src=3, tgt=4. Neither target equal nor
/// surround relation → not slashable.
#[test]
fn test_dsl_017_non_overlapping_epochs_rejected() {
    let data_a = make_data(1, 2, 0xA1);
    let data_b = make_data(3, 4, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);
    let view = merge(view_a, view_b);

    let err = verify_evidence(&envelope(att_a, att_b), &view, &network_id(), 4)
        .expect_err("non-overlapping must reject");
    assert_eq!(err, SlashingError::AttesterSlashingNotSlashable);
}

/// DSL-017 row 2: byte-identical attestations surface earlier as
/// `InvalidAttesterSlashing("identical")`, NOT `AttesterSlashingNotSlashable`.
/// Locks the ordering: identical-check runs BEFORE predicate decision.
#[test]
fn test_dsl_017_same_target_same_data_not_this_error() {
    let data = make_data(2, 5, 0xA1);
    let (att, view) = signed_attestation(vec![1, 2, 3], data);

    let err = verify_evidence(&envelope(att.clone(), att), &view, &network_id(), 5)
        .expect_err("byte-identical must reject");
    assert!(
        matches!(err, SlashingError::InvalidAttesterSlashing(ref s) if s.contains("identical")),
        "got {err:?}; identical check MUST run before predicate",
    );
    // Explicit negative: MUST NOT be the DSL-017 variant.
    assert_ne!(err, SlashingError::AttesterSlashingNotSlashable);
}

/// DSL-017 row 3: genuine double-vote → passes the DSL-017 check
/// (accepted by the verifier).
#[test]
fn test_dsl_017_double_vote_not_this_error() {
    let data_a = make_data(2, 5, 0xA1);
    let data_b = make_data(2, 5, 0xB2); // same tgt, different head → double-vote
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);
    let view = merge(view_a, view_b);

    let verified = verify_evidence(&envelope(att_a, att_b), &view, &network_id(), 5)
        .expect("double-vote must accept");
    assert_eq!(verified.slashable_validator_indices, vec![1, 2, 3]);
}

/// DSL-017 row 4: genuine surround-vote → passes the DSL-017 check.
#[test]
fn test_dsl_017_surround_vote_not_this_error() {
    let data_a = make_data(1, 10, 0xA1); // a surrounds b
    let data_b = make_data(3, 7, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);
    let view = merge(view_a, view_b);

    let verified = verify_evidence(&envelope(att_a, att_b), &view, &network_id(), 10)
        .expect("surround must accept");
    assert_eq!(verified.slashable_validator_indices, vec![1, 2, 3]);
}

/// DSL-017 row 5: equal source + different target (non-surround,
/// different targets → not double-vote) → `AttesterSlashingNotSlashable`.
///
/// `a`: src=5, tgt=10. `b`: src=5, tgt=8. No strict surround (sources
/// equal), different targets (not double-vote).
#[test]
fn test_dsl_017_equal_source_nonequal_target_rejected() {
    let data_a = make_data(5, 10, 0xA1);
    let data_b = make_data(5, 8, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);
    let view = merge(view_a, view_b);

    let err = verify_evidence(&envelope(att_a, att_b), &view, &network_id(), 10)
        .expect_err("equal-source non-surround non-double-vote must reject");
    assert_eq!(err, SlashingError::AttesterSlashingNotSlashable);
}

/// DSL-017 row 6: nested-but-not-strict — one window is contained in
/// the other but shares a boundary. `a`: src=3, tgt=10. `b`: src=3,
/// tgt=10. Wait — byte-equal test. Use `src=3, tgt=10` vs `src=3,
/// tgt=7` — b "inside" a on source but equal source prevents surround;
/// different target prevents double-vote.
///
/// Documents that nesting ALONE is not slashable — the surround
/// predicate requires both source AND target to be strictly inside.
#[test]
fn test_dsl_017_nested_but_not_strict_rejected() {
    let data_a = make_data(3, 10, 0xA1);
    let data_b = make_data(3, 7, 0xB2); // same source, smaller target
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);
    let view = merge(view_a, view_b);

    let err = verify_evidence(&envelope(att_a, att_b), &view, &network_id(), 10)
        .expect_err("same source + smaller target must not be slashable");
    assert_eq!(err, SlashingError::AttesterSlashingNotSlashable);
}
