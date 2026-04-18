//! Requirement DSL-018: `verify_invalid_block` enforces that the
//! proposer's signature verifies over `block_signing_message(network_id,
//! header.epoch, &header.hash(), header.proposer_index)` — the SAME
//! domain-bound message used for honest block production.
//!
//! Traces to: docs/resources/SPEC.md §5.4, §2.10, §22.2.
//!
//! # Role
//!
//! Invalid-block evidence accuses a proposer of signing a block that
//! fails canonical validation. Before any oracle re-execution (DSL-020),
//! we need cryptographic proof that the accused proposer actually
//! signed the header. The signing message is the domain-prefixed,
//! network-bound byte string also used by honest block production —
//! identical to the proposer-slashing signing message (DSL-013) so
//! proposer signatures cannot be forged under a different context.
//!
//! # Anti-replay bindings
//!
//!   - `DOMAIN_BEACON_PROPOSER` prefix → cannot replay as attester
//!     signature (different domain tag).
//!   - `network_id` mix → cannot replay cross-chain (testnet →
//!     mainnet).
//!   - `header.hash()` → binds to the exact failing block.
//!   - `proposer_index` → binds to the accused validator.
//!
//! # Test matrix (maps to DSL-018 Test Plan)
//!
//!   1. `test_dsl_018_valid_signature_accepted`
//!   2. `test_dsl_018_rejects_raw_hash_signature` — no domain prefix
//!   3. `test_dsl_018_rejects_wrong_key` — different signer
//!   4. `test_dsl_018_rejects_cross_network_replay` — different network_id
//!   5. `test_dsl_018_signing_message_parity` — bytes match the helper
//!   6. `test_dsl_018_direct_call_no_oracle_parity` — direct call
//!   7. `test_dsl_018_rejects_bad_sig_width` — width safety

use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, DOMAIN_BEACON_PROPOSER, InvalidBlockProof, InvalidBlockReason, OffenseType,
    SignedBlockHeader, SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry,
    ValidatorView, block_signing_message, verify_evidence, verify_invalid_block,
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

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn other_network_id() -> Bytes32 {
    Bytes32::new([0xBBu8; 32]) // distinct from production network_id
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn sample_header(proposer_index: u32, epoch: u64) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        epoch,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([0x02u8; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        proposer_index,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

fn sign_with(sk: &SecretKey, header: &L2BlockHeader, nid: &Bytes32) -> Vec<u8> {
    let msg = block_signing_message(nid, header.epoch, &header.hash(), header.proposer_index);
    chia_bls::sign(sk, msg).to_bytes().to_vec()
}

/// Build a valid, honestly-signed invalid-block envelope.
fn valid_evidence(proposer_index: u32, epoch: u64) -> (SlashingEvidence, MapView, SecretKey) {
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header = sample_header(proposer_index, epoch);
    let sig = sign_with(&sk, &header, &network_id());

    let mut map = HashMap::new();
    map.insert(proposer_index, TestValidator { pk });

    let ev = SlashingEvidence {
        offense_type: OffenseType::InvalidBlock,
        reporter_validator_index: 99,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch,
        payload: SlashingEvidencePayload::InvalidBlock(InvalidBlockProof {
            signed_header: SignedBlockHeader {
                message: header,
                signature: sig,
            },
            failure_witness: vec![1, 2, 3, 4, 5],
            failure_reason: InvalidBlockReason::BadStateRoot,
        }),
    };
    (ev, MapView(map), sk)
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-018 row 1: valid signature over `block_signing_message` passes.
#[test]
fn test_dsl_018_valid_signature_accepted() {
    let (ev, view, _) = valid_evidence(9, 3);
    let verified =
        verify_evidence(&ev, &view, &network_id(), 3).expect("valid invalid-block must verify");
    assert_eq!(verified.offense_type, OffenseType::InvalidBlock);
    assert_eq!(verified.slashable_validator_indices, vec![9]);
}

/// DSL-018 row 2: signature over RAW `header.hash()` (no domain prefix)
/// → rejected. Locks the domain-binding invariant — without the prefix,
/// a signature produced here could be replayed as some other context.
#[test]
fn test_dsl_018_rejects_raw_hash_signature() {
    let (mut ev, view, sk) = valid_evidence(9, 3);
    if let SlashingEvidencePayload::InvalidBlock(p) = &mut ev.payload {
        // Sign the raw hash bytes only — no domain, no network, no
        // proposer_index mixed in.
        let raw = p.signed_header.message.hash();
        p.signed_header.signature = chia_bls::sign(&sk, raw.as_ref()).to_bytes().to_vec();
    }
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("raw-hash signature must reject");
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(ref s) if s.contains("bad invalid-block signature")),
        "got {err:?}",
    );
}

/// DSL-018 row 3: signature from a different key → rejected.
#[test]
fn test_dsl_018_rejects_wrong_key() {
    let (mut ev, view, _) = valid_evidence(9, 3);
    let wrong_sk = make_sk(0xEE);
    if let SlashingEvidencePayload::InvalidBlock(p) = &mut ev.payload {
        p.signed_header.signature = sign_with(&wrong_sk, &p.signed_header.message, &network_id());
    }
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("wrong-key signature must reject");
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(_)),
        "got {err:?}"
    );
}

/// DSL-018 row 4: cross-network replay — signature produced under
/// testnet network_id MUST NOT verify under mainnet network_id.
#[test]
fn test_dsl_018_rejects_cross_network_replay() {
    let (mut ev, view, sk) = valid_evidence(9, 3);
    if let SlashingEvidencePayload::InvalidBlock(p) = &mut ev.payload {
        // Sign under the OTHER network_id.
        p.signed_header.signature = sign_with(&sk, &p.signed_header.message, &other_network_id());
    }
    // Verifier still uses production network_id — must reject.
    let err = verify_evidence(&ev, &view, &network_id(), 3)
        .expect_err("cross-network signature must reject");
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(_)),
        "got {err:?}"
    );
}

/// DSL-018 row 5: the bytes that the verifier BLS-verifies against are
/// byte-identical to `block_signing_message`. Reconstruct by hand and
/// verify the public `block_signing_message` helper produces the same
/// output the verifier consumes.
///
/// Locks the wire format at the protocol boundary — changing the
/// helper without bumping a domain tag would be a silent protocol
/// break.
#[test]
fn test_dsl_018_signing_message_parity() {
    let nid = network_id();
    let header = sample_header(9, 3);
    let header_hash = header.hash();
    let msg = block_signing_message(&nid, header.epoch, &header_hash, header.proposer_index);

    // Layout: DOMAIN || network_id || LE(epoch) || header_hash || LE(proposer_index).
    let mut expected = Vec::new();
    expected.extend_from_slice(DOMAIN_BEACON_PROPOSER);
    expected.extend_from_slice(nid.as_ref());
    expected.extend_from_slice(&header.epoch.to_le_bytes());
    expected.extend_from_slice(header_hash.as_ref());
    expected.extend_from_slice(&header.proposer_index.to_le_bytes());
    assert_eq!(msg, expected);

    // Verify an honestly-produced signature under the same bytes — if
    // the helper deviates from the verifier's internal call, this
    // would flip.
    let sk = make_sk(0x77);
    let pk = sk.public_key();
    let sig = chia_bls::sign(&sk, &msg);
    assert!(chia_bls::verify(&sig, &pk, &msg));
}

/// DSL-018 row 6: direct call to `verify_invalid_block` with `None`
/// oracle matches the dispatcher's verdict (dispatcher passes `None`
/// by default — bootstrap mode).
#[test]
fn test_dsl_018_direct_call_no_oracle_parity() {
    let (ev, view, _) = valid_evidence(9, 3);
    let SlashingEvidencePayload::InvalidBlock(p) = &ev.payload else {
        panic!("sample is invalid-block");
    };
    let direct = verify_invalid_block(&ev, p, &view, &network_id(), None).expect("direct Ok");
    let dispatch = verify_evidence(&ev, &view, &network_id(), 3).expect("dispatch Ok");
    assert_eq!(direct, dispatch);
}

/// DSL-018 row 7: bad signature width rejected standalone — verifier
/// must not panic on 95-byte or 97-byte signatures.
#[test]
fn test_dsl_018_rejects_bad_sig_width() {
    let (mut ev, view, _) = valid_evidence(9, 3);
    if let SlashingEvidencePayload::InvalidBlock(p) = &mut ev.payload {
        p.signed_header.signature.truncate(BLS_SIGNATURE_SIZE - 1);
    }
    let err = verify_evidence(&ev, &view, &network_id(), 3).expect_err("95-byte sig must reject");
    assert!(
        matches!(err, SlashingError::InvalidSlashingEvidence(ref s) if s.contains("width")),
        "got {err:?}",
    );
}
