//! Requirement DSL-048: An attester-slashing appeal whose ground does
//! NOT hold against a genuine attester slashing MUST be rejected.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! Mirror of DSL-040 for the attester side. Builds a single fixture
//! that represents a GENUINE slashable attester offense — a
//! double-vote with honest aggregate BLS sigs, well-formed structure,
//! non-empty intersection — then drives every attester-appeal
//! verifier through it and asserts each returns
//! `Rejected { GroundDoesNotHold }`. Any verifier that sustains here
//! would admit a false-positive appeal and allow a genuine attester
//! slasher to escape via DSL-071 bond forfeiture.
//!
//! # Fixture shape
//!
//!   - `data_a`: target.epoch = 3, beacon_block_root = 0x33
//!   - `data_b`: target.epoch = 3, beacon_block_root = 0x44
//!     → double-vote (same target.epoch, different data).
//!   - `attesting_indices_a = [1, 2, 3]`,
//!     `attesting_indices_b = [2, 3, 4]` → intersection {2, 3}.
//!   - Both aggregates produced by the SAME index→secret-key table,
//!     so the global `MapLookup` verifies sigs on both sides.
//!
//! # Test matrix (maps to DSL-048 Test Plan — one row per ground)
//!
//!   1. `test_dsl_048_double_vote_identical_claim_rejected`
//!      → AttestationsIdentical (DSL-041)
//!   2. `test_dsl_048_surround_not_slashable_claim_rejected`
//!      → NotSlashableByPredicate (DSL-042)
//!   3. `test_dsl_048_non_empty_empty_claim_rejected`
//!      → EmptyIntersection (DSL-043)
//!   4. `test_dsl_048_valid_sig_a_claim_rejected`
//!      → AttesterSignatureAInvalid (DSL-044)
//!   5. `test_dsl_048_valid_sig_b_claim_rejected`
//!      → AttesterSignatureBInvalid (DSL-045)
//!   6. `test_dsl_048_well_formed_structure_claim_rejected`
//!      → InvalidIndexedAttestationStructure (DSL-046)
//!   7. `test_dsl_048_index_in_intersection_claim_rejected`
//!      → ValidatorNotInIntersection (DSL-047)

use std::collections::BTreeMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealVerdict, AttestationData, AttesterSlashing, Checkpoint,
    IndexedAttestation, PublicKeyLookup, verify_attester_appeal_attestations_identical,
    verify_attester_appeal_empty_intersection,
    verify_attester_appeal_invalid_indexed_attestation_structure,
    verify_attester_appeal_not_slashable_by_predicate, verify_attester_appeal_signature_a_invalid,
    verify_attester_appeal_signature_b_invalid,
    verify_attester_appeal_validator_not_in_intersection,
};

/// Map-backed `PublicKeyLookup` shared across the suite. One
/// entry per global validator index; both side-A and side-B
/// aggregates are signed by the same (sk_i, pk_i) pair per index,
/// so verifying either side through this lookup succeeds.
struct MapLookup(BTreeMap<u32, PublicKey>);

impl PublicKeyLookup for MapLookup {
    fn pubkey_of(&self, index: u32) -> Option<&PublicKey> {
        self.0.get(&index)
    }
}

fn make_key(seed_byte: u8) -> (SecretKey, PublicKey) {
    let seed = [seed_byte; 32];
    let sk = SecretKey::from_seed(&seed);
    let pk = sk.public_key();
    (sk, pk)
}

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn data_a() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x33u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    }
}

/// Same target.epoch as `data_a` but distinct `target.root` and
/// `beacon_block_root` → genuine double-vote (DSL-014).
fn data_b() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x44u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x44u8; 32]),
        },
    }
}

/// Build one signed side of the evidence. Uses the global key
/// table (`keys: u32 → SecretKey`) so side-A and side-B sigs
/// verify under the SAME `PublicKeyLookup` — required for the
/// sig-path grounds (DSL-044/045) to reject.
fn signed_side(
    indices: &[u32],
    data: AttestationData,
    keys: &BTreeMap<u32, SecretKey>,
) -> IndexedAttestation {
    let nid = network_id();
    let signing_root = data.signing_root(&nid);

    let sigs: Vec<Signature> = indices
        .iter()
        .map(|idx| {
            let sk = keys.get(idx).expect("fixture: key must exist");
            chia_bls::sign(sk, signing_root.as_ref())
        })
        .collect();
    let agg = chia_bls::aggregate(&sigs);

    IndexedAttestation {
        attesting_indices: indices.to_vec(),
        data,
        signature: agg.to_bytes().to_vec(),
    }
}

/// Build the shared genuine-slashing fixture used by all 7 rows.
/// Returns (evidence, pubkey-lookup). Evidence: well-formed,
/// honestly-signed, double-vote, intersection = {2, 3}.
fn genuine() -> (AttesterSlashing, MapLookup) {
    // Key table covering every index that appears on either side.
    let mut sks: BTreeMap<u32, SecretKey> = BTreeMap::new();
    let mut pks: BTreeMap<u32, PublicKey> = BTreeMap::new();
    for (seed, idx) in [(0x01u8, 1u32), (0x02, 2), (0x03, 3), (0x04, 4)] {
        let (sk, pk) = make_key(seed);
        sks.insert(idx, sk);
        pks.insert(idx, pk);
    }

    let attestation_a = signed_side(&[1, 2, 3], data_a(), &sks);
    let attestation_b = signed_side(&[2, 3, 4], data_b(), &sks);

    (
        AttesterSlashing {
            attestation_a,
            attestation_b,
        },
        MapLookup(pks),
    )
}

fn rejected() -> AppealVerdict {
    AppealVerdict::Rejected {
        reason: AppealRejectReason::GroundDoesNotHold,
    }
}

/// DSL-048 row 1: genuine distinct attestations → `AttestationsIdentical`
/// ground does NOT hold → Rejected.
#[test]
fn test_dsl_048_double_vote_identical_claim_rejected() {
    let (evidence, _pks) = genuine();
    assert_eq!(
        verify_attester_appeal_attestations_identical(&evidence),
        rejected(),
    );
}

/// DSL-048 row 2: genuine double-vote → `NotSlashableByPredicate`
/// ground does NOT hold (double_vote is TRUE) → Rejected.
#[test]
fn test_dsl_048_surround_not_slashable_claim_rejected() {
    let (evidence, _pks) = genuine();
    assert_eq!(
        verify_attester_appeal_not_slashable_by_predicate(&evidence),
        rejected(),
    );
}

/// DSL-048 row 3: intersection = {2, 3} (non-empty) →
/// `EmptyIntersection` ground does NOT hold → Rejected.
#[test]
fn test_dsl_048_non_empty_empty_claim_rejected() {
    let (evidence, _pks) = genuine();
    assert_eq!(
        verify_attester_appeal_empty_intersection(&evidence),
        rejected(),
    );
}

/// DSL-048 row 4: honest sig_a under the canonical lookup →
/// `AttesterSignatureAInvalid` ground does NOT hold → Rejected.
#[test]
fn test_dsl_048_valid_sig_a_claim_rejected() {
    let (evidence, pks) = genuine();
    assert_eq!(
        verify_attester_appeal_signature_a_invalid(&evidence, &pks, &network_id()),
        rejected(),
    );
}

/// DSL-048 row 5: honest sig_b under the canonical lookup →
/// `AttesterSignatureBInvalid` ground does NOT hold → Rejected.
#[test]
fn test_dsl_048_valid_sig_b_claim_rejected() {
    let (evidence, pks) = genuine();
    assert_eq!(
        verify_attester_appeal_signature_b_invalid(&evidence, &pks, &network_id()),
        rejected(),
    );
}

/// DSL-048 row 6: both sides well-formed →
/// `InvalidIndexedAttestationStructure` ground does NOT hold →
/// Rejected.
#[test]
fn test_dsl_048_well_formed_structure_claim_rejected() {
    let (evidence, _pks) = genuine();
    assert_eq!(
        verify_attester_appeal_invalid_indexed_attestation_structure(&evidence),
        rejected(),
    );
}

/// DSL-048 row 7: index 3 IS in the intersection {2, 3} →
/// `ValidatorNotInIntersection { validator_index: 3 }` does NOT
/// hold → Rejected. Named index chosen to be a member of the
/// intersection specifically to exercise the "in" branch of
/// DSL-047's predicate.
#[test]
fn test_dsl_048_index_in_intersection_claim_rejected() {
    let (evidence, _pks) = genuine();
    assert_eq!(
        verify_attester_appeal_validator_not_in_intersection(&evidence, 3),
        rejected(),
    );
}
