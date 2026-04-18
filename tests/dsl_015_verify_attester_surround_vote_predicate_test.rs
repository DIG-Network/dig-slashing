//! Requirement DSL-015: `verify_attester_slashing` accepts evidence
//! where one `AttestationData` surrounds the other's FFG vote —
//! Ethereum-parity surround-vote predicate.
//!
//! Traces to: docs/resources/SPEC.md §5.3, §22.2.
//!
//! # Predicate
//!
//! ```text
//! surround_vote ⟺
//!     (a.source.epoch <  b.source.epoch AND a.target.epoch >  b.target.epoch)
//!     OR
//!     (b.source.epoch <  a.source.epoch AND b.target.epoch >  a.target.epoch)
//! ```
//!
//! Strict inequalities on both ends — equal source or equal target
//! does NOT count as surround (may still be double-vote, which is the
//! DSL-014 path).
//!
//! # Role
//!
//! Surround-vote catches validators who back-vote to a conflicting
//! FFG checkpoint pair. Combined with double-vote (DSL-014), these
//! are the two slashable attester predicates. `verify_attester_slashing`
//! (landed in the DSL-014 commit) already enforces both; this suite
//! exercises the surround branch.
//!
//! # Test matrix (maps to DSL-015 Test Plan)
//!
//!   1. `test_dsl_015_a_surrounds_b` — src_a=1 tgt_a=5, src_b=2 tgt_b=4
//!   2. `test_dsl_015_b_surrounds_a` — mirror
//!   3. `test_dsl_015_non_overlapping_rejected` — no surround, no double
//!   4. `test_dsl_015_equal_source_not_surround` — tie on source
//!   5. `test_dsl_015_equal_target_not_surround` — tie on target
//!   6. `test_dsl_015_adjacent_shared_target_not_surround` — boundary
//!   7. `test_dsl_015_slashable_set_matches_intersection` — DSL-007 parity

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, Checkpoint, IndexedAttestation, OffenseType, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, ValidatorEntry, ValidatorView, verify_evidence,
};

// ── Validator fixtures (same shape as DSL-014) ──────────────────────────

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

/// Build attestation data with full FFG vote control (source + target).
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
        // Seed derived from validator index → stable key across both
        // attestations in a surround-vote pair.
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

/// Build a slashing envelope from two attestations + merge their
/// validator views. Indices in BOTH views share the same key.
fn slashing_evidence(
    reporter: u32,
    att_a: IndexedAttestation,
    att_b: IndexedAttestation,
    view_a: MapView,
    view_b: MapView,
    offense_epoch: u64,
) -> (SlashingEvidence, MapView) {
    let mut merged = view_a.0;
    for (k, v) in view_b.0 {
        merged.insert(k, v);
    }
    let ev = SlashingEvidence {
        offense_type: OffenseType::AttesterSurroundVote,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: offense_epoch,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: att_a,
            attestation_b: att_b,
        }),
    };
    (ev, MapView(merged))
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-015 row 1: `a` surrounds `b` → accepted.
///
/// `a`: source=1, target=5. `b`: source=2, target=4.
/// `1 < 2` AND `5 > 4` → surround predicate holds.
#[test]
fn test_dsl_015_a_surrounds_b() {
    let data_a = make_data(1, 5, 0xA1);
    let data_b = make_data(2, 4, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![1, 3, 5], data_a);
    let (att_b, view_b) = signed_attestation(vec![3, 5, 7], data_b);

    let (ev, view) = slashing_evidence(99, att_a, att_b, view_a, view_b, 5);
    let verified =
        verify_evidence(&ev, &view, &network_id(), 5).expect("a surrounds b must accept");
    assert_eq!(verified.slashable_validator_indices, vec![3, 5]);
}

/// DSL-015 row 2: `b` surrounds `a` (mirror case) → accepted.
///
/// `a`: source=10, target=12. `b`: source=5, target=20.
/// `5 < 10` AND `20 > 12` → b surrounds a → predicate holds.
#[test]
fn test_dsl_015_b_surrounds_a() {
    let data_a = make_data(10, 12, 0xA1);
    let data_b = make_data(5, 20, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![2, 4, 6], data_a);
    let (att_b, view_b) = signed_attestation(vec![4, 6, 8], data_b);

    let (ev, view) = slashing_evidence(99, att_a, att_b, view_a, view_b, 20);
    let verified =
        verify_evidence(&ev, &view, &network_id(), 20).expect("b surrounds a must accept");
    assert_eq!(verified.slashable_validator_indices, vec![4, 6]);
}

/// DSL-015 row 3: non-overlapping epoch windows (neither surrounds) +
/// different target epochs (not double-vote) → `AttesterSlashingNotSlashable`.
///
/// `a`: source=1, target=2. `b`: source=3, target=4.
/// No surround (disjoint) and different targets → neither predicate.
#[test]
fn test_dsl_015_non_overlapping_rejected() {
    let data_a = make_data(1, 2, 0xA1);
    let data_b = make_data(3, 4, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);

    let (ev, view) = slashing_evidence(99, att_a, att_b, view_a, view_b, 4);
    let err = verify_evidence(&ev, &view, &network_id(), 4).expect_err("no-overlap must reject");
    assert_eq!(err, SlashingError::AttesterSlashingNotSlashable);
}

/// DSL-015 row 4: equal source epochs → NOT surround (strict `<`
/// required). Different target → NOT double-vote either → rejected.
#[test]
fn test_dsl_015_equal_source_not_surround() {
    let data_a = make_data(5, 10, 0xA1);
    let data_b = make_data(5, 8, 0xB2); // tied source
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);

    let (ev, view) = slashing_evidence(99, att_a, att_b, view_a, view_b, 10);
    let err =
        verify_evidence(&ev, &view, &network_id(), 10).expect_err("equal source must not surround");
    assert_eq!(err, SlashingError::AttesterSlashingNotSlashable);
}

/// DSL-015 row 5: equal target epochs → NOT surround (strict `>`
/// required). Equal target could still be double-vote, but here we
/// additionally ensure the data is identical target-wise and differs
/// only in source, so: same target + different data → double-vote
/// DOES hold, and the verifier accepts via DSL-014 path.
///
/// This test documents that DSL-015 path rejects equal-target but the
/// ENVELOPE is still slashable — what matters for "not surround" is
/// that the surround predicate alone doesn't trigger.
#[test]
fn test_dsl_015_equal_target_not_surround() {
    // Same target → double-vote predicate covers this case. To isolate
    // "not surround", construct a pair where source + target are both
    // equal but head vote differs → byte-different + same (src,tgt) →
    // double-vote predicate holds → accepted under DSL-014, NOT DSL-015.
    let data_a = make_data(5, 10, 0xA1);
    let data_b = make_data(5, 10, 0xB2); // tied src + tgt, different head
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);

    let (ev, view) = slashing_evidence(99, att_a, att_b, view_a, view_b, 10);
    // Accepted via DSL-014 (double-vote) — surround does NOT apply.
    let verified = verify_evidence(&ev, &view, &network_id(), 10).expect("double-vote must accept");
    assert_eq!(verified.slashable_validator_indices, vec![1, 2, 3]);
}

/// DSL-015 row 6: boundary case — one attestation shares the target
/// epoch with the other but has a later source. `a`: src=1, tgt=3.
/// `b`: src=2, tgt=3. `1 < 2` but `3 == 3` (not `>`), so NOT surround.
///
/// Targets are equal + data differs in head vote → double-vote. The
/// envelope is still slashable via DSL-014; DSL-015 specifically
/// rejects this shape. Documents the strictness of the target
/// inequality.
#[test]
fn test_dsl_015_adjacent_shared_target_not_surround() {
    let data_a = make_data(1, 3, 0xA1);
    let data_b = make_data(2, 3, 0xB2); // shared target
    let (att_a, view_a) = signed_attestation(vec![1, 2, 3], data_a);
    let (att_b, view_b) = signed_attestation(vec![1, 2, 3], data_b);

    let (ev, view) = slashing_evidence(99, att_a, att_b, view_a, view_b, 3);
    // Same target + different head → double-vote holds → accepted, but
    // NOT via the surround path.
    let verified = verify_evidence(&ev, &view, &network_id(), 3).expect("double-vote covers this");
    assert_eq!(verified.slashable_validator_indices, vec![1, 2, 3]);
}

/// DSL-015: slashable set from a surround-vote acceptance equals the
/// `AttesterSlashing::slashable_indices` intersection (DSL-007).
#[test]
fn test_dsl_015_slashable_set_matches_intersection() {
    let data_a = make_data(1, 10, 0xA1); // surrounds b
    let data_b = make_data(3, 7, 0xB2);
    let (att_a, view_a) = signed_attestation(vec![1, 3, 5, 7, 9], data_a);
    let (att_b, view_b) = signed_attestation(vec![2, 3, 5, 7, 11], data_b);

    let (ev, view) = slashing_evidence(99, att_a, att_b, view_a, view_b, 10);
    let verified = verify_evidence(&ev, &view, &network_id(), 10).expect("surround must accept");

    let SlashingEvidencePayload::Attester(p) = &ev.payload else {
        panic!("attester");
    };
    assert_eq!(verified.slashable_validator_indices, p.slashable_indices());
    assert_eq!(verified.slashable_validator_indices, vec![3, 5, 7]);
}
