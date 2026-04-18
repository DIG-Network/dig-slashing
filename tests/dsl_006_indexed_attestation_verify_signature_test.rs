//! Requirement DSL-006: `IndexedAttestation::verify_signature` performs
//! aggregate BLS verify over every committee member's public key against
//! the shared `signing_root(network_id)` (DSL-004).
//!
//! Traces to: docs/resources/SPEC.md §3.3, §22.1.
//!
//! # Role
//!
//! The expensive half of the two-guard pattern on `IndexedAttestation`:
//!
//!   1. `validate_structure` (DSL-005) — cheap; rejects malformed input.
//!   2. `verify_signature`  (DSL-006) — aggregate BLS pairing verify.
//!
//! Consumers (`verify_attester_slashing`, DSL-014 / DSL-015) MUST call
//! `validate_structure` first and only run this on structurally-valid
//! input. A failed aggregate verify under a structurally-valid committee
//! is the strongest per-signer rejection we can produce — the evidence
//! reporter lied about who signed.
//!
//! # Test matrix (maps to DSL-006 Test Plan)
//!
//!   1. `test_dsl_006_valid_aggregate_accepted` — honest signing path
//!   2. `test_dsl_006_signature_mutation_rejected` — bit flip on aggregate
//!   3. `test_dsl_006_substituted_pubkey_rejected` — wrong pubkey in lookup
//!   4. `test_dsl_006_mutated_message_rejected` — change beacon_block_root
//!   5. `test_dsl_006_missing_pubkey_rejected` — lookup returns None
//!   6. `test_dsl_006_chia_bls_parity` — direct aggregate_verify agrees
//!   7. `test_dsl_006_bad_sig_width_rejected` — standalone safety (no prior
//!      validate_structure)
//!   8. `test_dsl_006_corrupt_sig_bytes_rejected` — 96-byte but invalid sig
//!
//! # BLS scheme
//!
//! `chia_bls::sign` and `chia_bls::aggregate_verify` both use the
//! augmented scheme (`pk || msg`) — augmentation is internal. Every
//! attester signs the SAME signing_root; verify augments per-pubkey.

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey, Signature};
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, BLS_SIGNATURE_SIZE, Checkpoint, IndexedAttestation, PublicKeyLookup,
    SlashingError,
};

/// Trivial `HashMap`-backed implementation of the lookup trait for tests.
/// Real runtimes will wire `PublicKeyLookup` onto their validator set.
struct MapLookup(HashMap<u32, PublicKey>);

impl PublicKeyLookup for MapLookup {
    fn pubkey_of(&self, index: u32) -> Option<&PublicKey> {
        self.0.get(&index)
    }
}

fn make_key(seed_byte: u8) -> (SecretKey, PublicKey) {
    // 32 bytes — chia_bls::SecretKey::from_seed requires len >= 32.
    let seed = [seed_byte; 32];
    let sk = SecretKey::from_seed(&seed);
    let pk = sk.public_key();
    (sk, pk)
}

fn sample_attestation_data() -> AttestationData {
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

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

/// Build a structurally-valid, honestly-signed `IndexedAttestation`
/// over `attesting_indices`. Returns the attestation + lookup.
fn honest(attesting_indices: Vec<u32>) -> (IndexedAttestation, MapLookup) {
    let data = sample_attestation_data();
    let nid = network_id();
    let signing_root = data.signing_root(&nid);

    let mut sigs: Vec<Signature> = Vec::new();
    let mut map: HashMap<u32, PublicKey> = HashMap::new();
    for (k, idx) in attesting_indices.iter().enumerate() {
        // Seed byte uniquely derived so no two attesters share a key.
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

/// DSL-006 row 1: honestly-signed committee aggregate verifies.
///
/// Constructs 4 signers, each `chia_bls::sign(sk_i, signing_root)`,
/// aggregates into a single G2 sig, and verifies. Happy-path lock.
#[test]
fn test_dsl_006_valid_aggregate_accepted() {
    let (att, pks) = honest(vec![1, 3, 5, 7]);
    let result = att.verify_signature(&pks, &network_id());
    assert!(result.is_ok(), "honest aggregate must verify: {result:?}");
}

/// DSL-006 row 2: a single-bit mutation on the aggregate signature
/// bytes must cause verify to fail.
///
/// Picks byte 0 and XORs with 0x01 — the G2 sig decoder still accepts
/// the bytes as a point (or rejects outright); either way the verify
/// MUST return `BlsVerifyFailed`.
#[test]
fn test_dsl_006_signature_mutation_rejected() {
    let (mut att, pks) = honest(vec![1, 3, 5, 7]);
    att.signature[0] ^= 0x01;
    let err = att
        .verify_signature(&pks, &network_id())
        .expect_err("mutated sig must fail");
    assert_eq!(err, SlashingError::BlsVerifyFailed);
}

/// DSL-006 row 3: replacing one pubkey in the lookup with a different
/// random pubkey breaks the aggregate verify.
///
/// The aggregate was computed over the original 4 secret keys; swapping
/// any one pubkey in the lookup makes the augmented-message derivation
/// mismatch and the pairing verify rejects.
#[test]
fn test_dsl_006_substituted_pubkey_rejected() {
    let (att, pks) = honest(vec![1, 3, 5, 7]);
    let MapLookup(mut map) = pks;

    // Substitute the pubkey at index 3 with a completely unrelated one.
    let (_, wrong_pk) = make_key(0xEE);
    map.insert(3, wrong_pk);
    let bad_pks = MapLookup(map);

    let err = att
        .verify_signature(&bad_pks, &network_id())
        .expect_err("substituted pubkey must fail");
    assert_eq!(err, SlashingError::BlsVerifyFailed);
}

/// DSL-006 row 4: tampering with the signed message — by shifting
/// `beacon_block_root` — yields a different signing root, so the
/// aggregate produced over the ORIGINAL root does not verify under
/// the tampered root.
///
/// The attack this defends against: a reporter submits a correctly-
/// signed aggregate but tweaks the `AttestationData` payload to misdirect
/// the slash target.
#[test]
fn test_dsl_006_mutated_message_rejected() {
    let (mut att, pks) = honest(vec![1, 3, 5, 7]);
    att.data.beacon_block_root = Bytes32::new([0x99u8; 32]);
    let err = att
        .verify_signature(&pks, &network_id())
        .expect_err("mutated payload must fail");
    assert_eq!(err, SlashingError::BlsVerifyFailed);
}

/// DSL-006 row 5: an attesting index with no registered pubkey in the
/// lookup collapses verify to failure. Matches SPEC §15.2 security
/// model: "unknown validator" and "bad signature" are indistinguishable
/// at this layer.
#[test]
fn test_dsl_006_missing_pubkey_rejected() {
    let (att, pks) = honest(vec![1, 3, 5, 7]);

    // Drop index 5 from the lookup entirely.
    let MapLookup(mut map) = pks;
    map.remove(&5);
    let partial = MapLookup(map);

    let err = att
        .verify_signature(&partial, &network_id())
        .expect_err("missing pubkey must fail");
    assert_eq!(err, SlashingError::BlsVerifyFailed);
}

/// DSL-006 row 6: verdict matches a direct `chia_bls::aggregate_verify`
/// call wired by hand. Guards against accidental divergence from the
/// upstream API (e.g. if a future refactor swaps augmentation schemes).
#[test]
fn test_dsl_006_chia_bls_parity() {
    let (att, pks) = honest(vec![2, 4, 6]);
    let nid = network_id();
    let signing_root = att.data.signing_root(&nid);

    // Rebuild the (pk, msg) pair list by hand against the same lookup.
    let pubkeys: Vec<PublicKey> = att
        .attesting_indices
        .iter()
        .map(|i| *pks.pubkey_of(*i).expect("present"))
        .collect();
    let msg: &[u8] = signing_root.as_ref();
    let pairs = pubkeys.iter().map(|pk| (pk, msg));

    let sig_bytes: [u8; BLS_SIGNATURE_SIZE] = att.signature.as_slice().try_into().unwrap();
    let sig = Signature::from_bytes(&sig_bytes).unwrap();
    let direct = chia_bls::aggregate_verify(&sig, pairs);

    let via_method = att.verify_signature(&pks, &nid).is_ok();
    assert_eq!(direct, via_method, "direct and method verdicts must agree");
    assert!(direct, "honest aggregate must verify");
}

/// DSL-006 row 7: `verify_signature` refuses to panic on signature
/// widths != 96. Even though structurally-invalid attestations are
/// caught by `validate_structure` upstream, this method MUST be safe
/// to call standalone.
#[test]
fn test_dsl_006_bad_sig_width_rejected() {
    // Build a valid committee, then truncate the signature post-hoc.
    let (mut att, pks) = honest(vec![1, 2, 3]);
    att.signature.truncate(BLS_SIGNATURE_SIZE - 1);
    assert_eq!(att.signature.len(), 95);
    let err = att
        .verify_signature(&pks, &network_id())
        .expect_err("95-byte sig must fail");
    assert_eq!(err, SlashingError::BlsVerifyFailed);

    // Oversize signature.
    let (mut att, pks) = honest(vec![1, 2, 3]);
    att.signature.push(0xFF);
    assert_eq!(att.signature.len(), BLS_SIGNATURE_SIZE + 1);
    let err = att
        .verify_signature(&pks, &network_id())
        .expect_err("97-byte sig must fail");
    assert_eq!(err, SlashingError::BlsVerifyFailed);
}

/// DSL-006 row 8: 96 bytes of junk is not a decodable BLS G2 signature.
/// `Signature::from_bytes` rejects at decode; method must propagate as
/// `BlsVerifyFailed`.
#[test]
fn test_dsl_006_corrupt_sig_bytes_rejected() {
    let (mut att, pks) = honest(vec![1, 2, 3]);
    // All-0xFF bytes do not decode to a valid G2 affine point.
    att.signature = vec![0xFFu8; BLS_SIGNATURE_SIZE];
    let err = att
        .verify_signature(&pks, &network_id())
        .expect_err("undecodable sig must fail");
    assert_eq!(err, SlashingError::BlsVerifyFailed);
}
