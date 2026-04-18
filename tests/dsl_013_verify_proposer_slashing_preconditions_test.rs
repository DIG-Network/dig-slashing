//! Requirement DSL-013: `verify_proposer_slashing` enforces six
//! preconditions for proposer-equivocation evidence.
//!
//! Traces to: docs/resources/SPEC.md §5.2, §22.2.
//!
//! # Preconditions (in order)
//!
//!   1. `header_a.height == header_b.height`   (same-slot)
//!   2. `header_a.proposer_index == header_b.proposer_index`
//!   3. `header_a.hash() != header_b.hash()`    (different content)
//!   4. Both signatures parse as 96-byte G2 elements
//!   5. Proposer exists, not slashed, active at `header.epoch`
//!   6. Both signatures BLS-verify under the proposer's pubkey against
//!      `block_signing_message(network_id, header.epoch, header.hash(),
//!      proposer_index)`
//!
//! # Why six in a fixed order
//!
//!   - Cheap byte compares (1, 2, 3) before width check (4) before any
//!     validator lookup (5) before any BLS pairing (6). Minimizes the
//!     cost an adversarial envelope can impose on the verifier.
//!   - Ordering also matches the appeal grounds (DSL-034..040) one-to-one
//!     so an adjudicator can invert the logic without rediscovering
//!     categories.
//!
//! # Test matrix (maps to DSL-013 Test Plan)
//!
//!   1. `test_dsl_013_valid_proposer_slashing`
//!   2. `test_dsl_013_rejects_different_slot`
//!   3. `test_dsl_013_rejects_different_proposer`
//!   4. `test_dsl_013_rejects_identical_headers`
//!   5. `test_dsl_013_rejects_bad_signature_bytes`
//!   6. `test_dsl_013_rejects_unregistered_validator`
//!   7. `test_dsl_013_rejects_already_slashed`
//!   8. `test_dsl_013_rejects_inactive_validator`
//!   9. `test_dsl_013_rejects_bls_verify_failure_on_sig_a`
//!  10. `test_dsl_013_rejects_bls_verify_failure_on_sig_b`
//!  11. `test_dsl_013_signing_message_layout`  (parity against SPEC wire)

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, DOMAIN_BEACON_PROPOSER, OffenseType, ProposerSlashing, SignedBlockHeader,
    SlashingError, SlashingEvidence, SlashingEvidencePayload, ValidatorEntry, ValidatorView,
    block_signing_message, verify_evidence, verify_proposer_slashing,
};

// ── Validator fixtures ──────────────────────────────────────────────────

/// Minimal `ValidatorEntry` impl for tests. Supports enough state to
/// exercise every DSL-013 branch (active/inactive/slashed).
struct TestValidator {
    pk: PublicKey,
    activation_epoch: u64,
    exit_epoch: u64,
    slashed: bool,
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
        self.slashed
    }
    fn activation_epoch(&self) -> u64 {
        self.activation_epoch
    }
    fn exit_epoch(&self) -> u64 {
        self.exit_epoch
    }
    fn is_active_at_epoch(&self, epoch: u64) -> bool {
        epoch >= self.activation_epoch && epoch < self.exit_epoch
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

/// Single-validator view with configurable state. Optional so tests can
/// simulate "not registered" cleanly.
struct SingleValidator {
    index: u32,
    validator: Option<TestValidator>,
}

impl ValidatorView for SingleValidator {
    fn get(&self, index: u32) -> Option<&dyn ValidatorEntry> {
        if index == self.index {
            self.validator.as_ref().map(|v| v as &dyn ValidatorEntry)
        } else {
            None
        }
    }
    fn get_mut(&mut self, index: u32) -> Option<&mut dyn ValidatorEntry> {
        if index == self.index {
            self.validator
                .as_mut()
                .map(|v| v as &mut dyn ValidatorEntry)
        } else {
            None
        }
    }
    fn len(&self) -> usize {
        usize::from(self.validator.is_some())
    }
}

// ── Header + evidence construction ──────────────────────────────────────

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

/// Build a header with configurable height + epoch + proposer_index.
/// Other fields default to stable, distinctive values so tests can
/// mutate ONE aspect and keep everything else constant.
fn make_header(height: u64, epoch: u64, proposer_index: u32, state_root_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        height,
        epoch,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_root_byte; 32]), // vary state_root to force distinct hashes
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

fn sign_header(sk: &SecretKey, header: &L2BlockHeader, nid: &Bytes32) -> Vec<u8> {
    let msg = block_signing_message(nid, header.epoch, &header.hash(), header.proposer_index);
    chia_bls::sign(sk, msg).to_bytes().to_vec()
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

/// Build valid, honestly-signed proposer-equivocation evidence.
///
/// Returns (evidence, single-validator view) so each test can mutate
/// one axis without rebuilding everything.
fn valid_evidence(
    proposer_index: u32,
    reporter: u32,
) -> (SlashingEvidence, SingleValidator, SecretKey) {
    let nid = network_id();
    let sk = make_sk(0x01);
    let pk = sk.public_key();
    let header_a = make_header(100, 3, proposer_index, 0xA1);
    let header_b = make_header(100, 3, proposer_index, 0xB2); // same slot, different state_root → different hash

    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let evidence = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch: 3,
        payload: SlashingEvidencePayload::Proposer(ProposerSlashing {
            signed_header_a: SignedBlockHeader {
                message: header_a,
                signature: sig_a,
            },
            signed_header_b: SignedBlockHeader {
                message: header_b,
                signature: sig_b,
            },
        }),
    };
    let view = SingleValidator {
        index: proposer_index,
        validator: Some(TestValidator {
            pk,
            activation_epoch: 0,
            exit_epoch: u64::MAX,
            slashed: false,
        }),
    };
    (evidence, view, sk)
}

// ── Tests ───────────────────────────────────────────────────────────────

/// DSL-013 row 1: happy path — valid equivocation evidence verifies.
#[test]
fn test_dsl_013_valid_proposer_slashing() {
    let (ev, view, _) = valid_evidence(9, 42);
    let verified = verify_evidence(&ev, &view, &network_id(), 3).expect("valid must verify");
    assert_eq!(verified.offense_type, OffenseType::ProposerEquivocation);
    assert_eq!(verified.slashable_validator_indices, vec![9]);
}

/// DSL-013 row 2: different heights (= slot mismatch) rejected.
#[test]
fn test_dsl_013_rejects_different_slot() {
    let (mut ev, view, sk) = valid_evidence(9, 42);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev.payload {
        p.signed_header_b.message = make_header(101, 3, 9, 0xB2); // different height
        p.signed_header_b.signature = sign_header(&sk, &p.signed_header_b.message, &network_id());
    }
    let err = verify_evidence(&ev, &view, &network_id(), 3).expect_err("slot mismatch must reject");
    assert!(
        matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("slot")),
        "got {err:?}",
    );
}

/// DSL-013 row 3: different proposer indices rejected.
#[test]
fn test_dsl_013_rejects_different_proposer() {
    let (mut ev, view, sk) = valid_evidence(9, 42);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev.payload {
        p.signed_header_b.message = make_header(100, 3, 10, 0xB2); // different proposer
        p.signed_header_b.signature = sign_header(&sk, &p.signed_header_b.message, &network_id());
    }
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("proposer mismatch must reject");
    assert!(matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("proposer")));
}

/// DSL-013 row 4: identical headers rejected (not equivocation).
#[test]
fn test_dsl_013_rejects_identical_headers() {
    let (mut ev, view, sk) = valid_evidence(9, 42);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev.payload {
        // Force both sides byte-equal.
        p.signed_header_b.message = p.signed_header_a.message.clone();
        p.signed_header_b.signature = sign_header(&sk, &p.signed_header_b.message, &network_id());
    }
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("identical headers must reject");
    assert!(
        matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("identical"))
    );
}

/// DSL-013 row 5: truncated signature bytes rejected.
#[test]
fn test_dsl_013_rejects_bad_signature_bytes() {
    let (mut ev, view, _) = valid_evidence(9, 42);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev.payload {
        p.signed_header_a.signature.truncate(BLS_SIGNATURE_SIZE - 1);
    }
    let err = verify_evidence(&ev, &view, &network_id(), 3).expect_err("95-byte sig must reject");
    assert!(
        matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("signature"))
    );
}

/// DSL-013 row 6: unregistered validator rejected.
#[test]
fn test_dsl_013_rejects_unregistered_validator() {
    let (ev, _, _) = valid_evidence(9, 42);
    let empty_view = SingleValidator {
        index: 999, // look up 9, find nothing
        validator: None,
    };
    let err = verify_evidence(&ev, &empty_view, &network_id(), 3)
        .expect_err("unregistered proposer must reject");
    assert_eq!(err, SlashingError::ValidatorNotRegistered(9));
}

/// DSL-013: already-slashed validator rejected.
#[test]
fn test_dsl_013_rejects_already_slashed() {
    let (ev, mut view, _) = valid_evidence(9, 42);
    if let Some(v) = &mut view.validator {
        v.slashed = true;
    }
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("already-slashed must reject");
    assert!(
        matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("already slashed"))
    );
}

/// DSL-013: inactive validator at header epoch rejected.
#[test]
fn test_dsl_013_rejects_inactive_validator() {
    let (ev, mut view, _) = valid_evidence(9, 42);
    if let Some(v) = &mut view.validator {
        v.activation_epoch = 100; // not yet active
    }
    let err =
        verify_evidence(&ev, &view, &network_id(), 3).expect_err("inactive validator must reject");
    assert!(
        matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("not active"))
    );
}

/// DSL-013 row 7a: signature A fails BLS verify (signed under wrong key).
#[test]
fn test_dsl_013_rejects_bls_verify_failure_on_sig_a() {
    let (mut ev, view, _) = valid_evidence(9, 42);
    let wrong_sk = make_sk(0xEE);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev.payload {
        p.signed_header_a.signature =
            sign_header(&wrong_sk, &p.signed_header_a.message, &network_id());
    }
    let err = verify_evidence(&ev, &view, &network_id(), 3).expect_err("bad sig A must reject");
    assert!(
        matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("signature A"))
    );
}

/// DSL-013 row 7b: signature B fails BLS verify.
#[test]
fn test_dsl_013_rejects_bls_verify_failure_on_sig_b() {
    let (mut ev, view, _) = valid_evidence(9, 42);
    let wrong_sk = make_sk(0xEE);
    if let SlashingEvidencePayload::Proposer(p) = &mut ev.payload {
        p.signed_header_b.signature =
            sign_header(&wrong_sk, &p.signed_header_b.message, &network_id());
    }
    let err = verify_evidence(&ev, &view, &network_id(), 3).expect_err("bad sig B must reject");
    assert!(
        matches!(err, SlashingError::InvalidProposerSlashing(ref s) if s.contains("signature B"))
    );
}

/// DSL-013 row 8: `block_signing_message` layout matches the spec wire
/// format — domain tag + network_id + LE(epoch) + header_hash +
/// LE(proposer_index). 98 bytes total.
#[test]
fn test_dsl_013_signing_message_layout() {
    let nid = Bytes32::new([0x11u8; 32]);
    let header_hash = Bytes32::new([0x22u8; 32]);
    let msg = block_signing_message(&nid, 0xABCD_1234, &header_hash, 0x0A0B_0C0D);

    assert_eq!(msg.len(), DOMAIN_BEACON_PROPOSER.len() + 32 + 8 + 32 + 4);

    // Reconstruct by hand.
    let mut expected = Vec::new();
    expected.extend_from_slice(DOMAIN_BEACON_PROPOSER);
    expected.extend_from_slice(&[0x11u8; 32]);
    expected.extend_from_slice(&0xABCD_1234u64.to_le_bytes());
    expected.extend_from_slice(&[0x22u8; 32]);
    expected.extend_from_slice(&0x0A0B_0C0Du32.to_le_bytes());
    assert_eq!(msg, expected);

    // Determinism: same inputs → same output.
    let msg2 = block_signing_message(&nid, 0xABCD_1234, &header_hash, 0x0A0B_0C0D);
    assert_eq!(msg, msg2);
}

/// DSL-013: also callable as `verify_proposer_slashing` directly (not
/// only via the verify_evidence dispatcher). Guards against a future
/// refactor that accidentally privatizes the inner verifier.
#[test]
fn test_dsl_013_direct_call_parity() {
    let (ev, view, _) = valid_evidence(9, 42);
    let SlashingEvidencePayload::Proposer(p) = &ev.payload else {
        panic!("sample is proposer")
    };
    let verified_direct =
        verify_proposer_slashing(&ev, p, &view, &network_id()).expect("valid direct");
    let verified_dispatch = verify_evidence(&ev, &view, &network_id(), 3).expect("valid dispatch");
    assert_eq!(verified_direct, verified_dispatch);
}
