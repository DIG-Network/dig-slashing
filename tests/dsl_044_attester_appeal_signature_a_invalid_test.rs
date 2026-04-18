//! Requirement DSL-044: `AttesterAppealGround::AttesterSignatureAInvalid`
//! sustains when `attestation_a.verify_signature(...)` returns `Err`.
//!
//! Traces to: docs/resources/SPEC.md §6.3, §22.5.
//!
//! # Role
//!
//! DSL-006 aggregate-BLS verify inverted into an appeal ground. The
//! appellant re-runs the verifier over the stored `attestation_a`
//! against the current `PublicKeyLookup`; any failure (bad sig bytes,
//! bad G2 point, unknown attester index, cryptographic reject)
//! collapses to `Sustained{ AttesterSignatureAInvalid }` — same
//! coarse handling as DSL-036 on the proposer side (SPEC §15.2).
//!
//! # Test matrix (maps to DSL-044 Test Plan)
//!
//!   1. `test_dsl_044_corrupted_aggregate_sustained` — bit flip on sig_a
//!   2. `test_dsl_044_valid_aggregate_rejected` — honest aggregate → Rejected
//!   3. `test_dsl_044_wrong_pubkey_sustained` — substituted committee key
//!
//! The happy-path rejection in test (2) is the determinism guard: the
//! ground holds iff the stored sig genuinely fails to verify under
//! the current lookup, not because the verifier always sustains.

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AppealRejectReason, AppealSustainReason, AppealVerdict, AttestationData, AttesterSlashing,
    Checkpoint, IndexedAttestation, PublicKeyLookup, verify_attester_appeal_signature_a_invalid,
};

/// `HashMap`-backed `PublicKeyLookup` — mirrors DSL-006 tests so
/// the signature path is exercised on identical plumbing.
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

/// Different `AttestationData` for attestation_b — its signature does
/// not matter for DSL-044 (only side A is checked), but it must be
/// present in the evidence envelope.
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

/// Build a structurally-valid, honestly-signed aggregate for
/// `attesting_indices` over `data`.
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

/// DSL-044 row 1: corrupted aggregate sig on side A → Sustained.
///
/// Flips the first byte of the stored signature bytes. The BLS
/// decode may still succeed (producing a different G2 point) OR
/// fail; either way `verify_signature` returns `Err` and the appeal
/// sustains. Mirrors DSL-036 row 1 for the proposer side.
#[test]
fn test_dsl_044_corrupted_aggregate_sustained() {
    let (mut att_a, pks) = honest(vec![1, 3, 5, 7], data_a());
    att_a.signature[0] ^= 0xFF; // bit-flip the sig bytes

    let evidence = AttesterSlashing {
        attestation_a: att_a,
        attestation_b: IndexedAttestation {
            attesting_indices: vec![1, 3, 5, 7],
            data: data_b(),
            signature: vec![0xABu8; dig_slashing::BLS_SIGNATURE_SIZE],
        },
    };

    assert_eq!(
        verify_attester_appeal_signature_a_invalid(&evidence, &pks, &network_id()),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::AttesterSignatureAInvalid,
        },
    );
}

/// DSL-044 row 2: honest aggregate → Rejected.
///
/// Determinism guard. The same lookup that produced the aggregate
/// re-runs `verify_signature` successfully, so the ground does not
/// hold and the verifier MUST reject the appeal with
/// `GroundDoesNotHold`. Proves the verifier is not a constant
/// `Sustained`.
#[test]
fn test_dsl_044_valid_aggregate_rejected() {
    let (att_a, pks) = honest(vec![1, 3, 5, 7], data_a());

    let evidence = AttesterSlashing {
        attestation_a: att_a,
        attestation_b: IndexedAttestation {
            attesting_indices: vec![1, 3, 5, 7],
            data: data_b(),
            signature: vec![0xABu8; dig_slashing::BLS_SIGNATURE_SIZE],
        },
    };

    assert_eq!(
        verify_attester_appeal_signature_a_invalid(&evidence, &pks, &network_id()),
        AppealVerdict::Rejected {
            reason: AppealRejectReason::GroundDoesNotHold,
        },
    );
}

/// DSL-044 row 3: substituted committee key → Sustained.
///
/// Generate the aggregate under one set of keys, then serve a
/// different pubkey at `attesting_indices[0]`. The aggregate verify
/// fails because the augmented signing root used by that slot no
/// longer matches the signature — a classic key-substitution attack.
/// Covers the "unknown / wrong validator" leg of DSL-006's coarse
/// `BlsVerifyFailed`.
#[test]
fn test_dsl_044_wrong_pubkey_sustained() {
    let (att_a, mut pks) = honest(vec![1, 3, 5, 7], data_a());
    // Replace the key at index 1 with an unrelated key.
    let (_sk_other, pk_other) = make_key(0xEE);
    pks.0.insert(1, pk_other);

    let evidence = AttesterSlashing {
        attestation_a: att_a,
        attestation_b: IndexedAttestation {
            attesting_indices: vec![1, 3, 5, 7],
            data: data_b(),
            signature: vec![0xABu8; dig_slashing::BLS_SIGNATURE_SIZE],
        },
    };

    assert_eq!(
        verify_attester_appeal_signature_a_invalid(&evidence, &pks, &network_id()),
        AppealVerdict::Sustained {
            reason: AppealSustainReason::AttesterSignatureAInvalid,
        },
    );
}
