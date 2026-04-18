//! Requirement DSL-045: `AttesterAppealGround::AttesterSignatureBInvalid`
//! sustains when `attestation_b.verify_signature(...)` returns `Err`.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! Mirror of DSL-044 applied to side B. Both grounds funnel through
//! the shared helper `verify_attester_appeal_signature_side` in
//! `src/appeal/verify.rs`, so this suite's primary job is *parity
//! evidence* — if the same fixture pattern produces the same verdict
//! shape on side B as on side A (modulo the sustain-reason tag),
//! the helper wiring is correct.
//!
//! # Test matrix (maps to DSL-045 Test Plan)
//!
//!   1. `test_dsl_045_corrupted_sustained` — bit flip on sig_b
//!   2. `test_dsl_045_valid_rejected` — honest aggregate on B → Rejected
//!   3. `test_dsl_045_parity_dsl_044` — sig_a corruption MUST NOT
//!      affect the B-path verdict; only sig_b drives the B-side
//!      verifier. This is the cross-leak guard: proves the side-A
//!      verifier and side-B verifier read the correct field.

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing,
    BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation, PublicKeyLookup,
    verify_attester_appeal_signature_b_invalid,
};

struct MapLookup(HashMap<u32, PublicKey>);

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

/// Side-A data — identical slot/indices but distinct
/// `beacon_block_root` vs side B so the envelope is a valid
/// double-vote shape.
fn data_a() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x11u8; 32]),
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

fn data_b() -> AttestationData {
    AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x99u8; 32]),
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

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

/// Build a structurally-valid, honestly-signed aggregate over
/// `attesting_indices` for `data`. Returns the attestation + lookup
/// that was used to generate the signatures.
fn honest(attesting_indices: Vec<u32>, data: AttestationData) -> (IndexedAttestation, MapLookup) {
    let nid = network_id();
    let signing_root = data.signing_root(&nid);

    let mut sigs: Vec<Signature> = Vec::new();
    let mut map: HashMap<u32, PublicKey> = HashMap::new();
    for (k, idx) in attesting_indices.iter().enumerate() {
        let seed_byte = (k as u8).wrapping_add(1);
        let (sk, pk) = make_key(seed_byte);
        sigs.push(chia_bls::sign(&sk, signing_root.as_ref()));
        map.insert(*idx, pk);
    }
    let agg = chia_bls::aggregate(&sigs);

    let att = IndexedAttestation {
        attesting_indices,
        data,
        signature: agg.to_bytes().to_vec(),
    };
    (att, MapLookup(map))
}

/// DSL-045 row 1: corrupted aggregate sig on side B → Sustained.
#[test]
fn test_dsl_045_corrupted_sustained() {
    let (mut att_b, pks) = honest(vec![1, 3, 5, 7], data_b());
    att_b.signature[0] ^= 0xFF;

    let evidence = AttesterSlashing {
        attestation_a: IndexedAttestation {
            attesting_indices: vec![1, 3, 5, 7],
            data: data_a(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        attestation_b: att_b,
    };

    assert_eq!(
        verify_attester_appeal_signature_b_invalid(&evidence, &pks, &network_id()),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::AttesterSignatureBInvalid,
        },
    );
}

/// DSL-045 row 2: honest sig_b → Rejected (determinism guard).
#[test]
fn test_dsl_045_valid_rejected() {
    let (att_b, pks) = honest(vec![1, 3, 5, 7], data_b());

    let evidence = AttesterSlashing {
        attestation_a: IndexedAttestation {
            attesting_indices: vec![1, 3, 5, 7],
            data: data_a(),
            signature: vec![0xABu8; BLS_SIGNATURE_SIZE],
        },
        attestation_b: att_b,
    };

    assert_eq!(
        verify_attester_appeal_signature_b_invalid(&evidence, &pks, &network_id()),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-045 row 3: sig_a corruption MUST NOT affect B-side verdict.
///
/// Build an honest sig_b, then plant a deliberately-wrong sig_a in
/// the envelope. The B-side verifier must still return `Rejected`
/// because sig_b genuinely verifies — if the shared helper ever
/// drifted to read the wrong field, this test fails.
#[test]
fn test_dsl_045_parity_dsl_044() {
    let (att_b, pks) = honest(vec![1, 3, 5, 7], data_b());
    // Sig_a is stuffed with the wrong bytes — irrelevant for the
    // B-side ground but proves the verifier does NOT bleed across.
    let evidence = AttesterSlashing {
        attestation_a: IndexedAttestation {
            attesting_indices: vec![1, 3, 5, 7],
            data: data_a(),
            signature: vec![0xDEu8; BLS_SIGNATURE_SIZE],
        },
        attestation_b: att_b,
    };

    assert_eq!(
        verify_attester_appeal_signature_b_invalid(&evidence, &pks, &network_id()),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}
