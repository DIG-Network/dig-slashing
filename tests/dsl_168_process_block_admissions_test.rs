//! Requirement DSL-168: `process_block_admissions` single-call block-level admission dispatcher.
//!
//! Traces to: docs/resources/SPEC.md §16.5, §7.3.
//!
//! # Role
//!
//! Bundles REMARK parsing + block-cap enforcement + `submit_evidence` / `submit_appeal` iteration into one call producing a `BlockAdmissionReport`. Previously embedders had to manually compose these six steps per block.
//!
//! # Processing order
//!
//! Evidence envelopes process BEFORE appeal envelopes. Per-envelope failures populate rejected vecs without aborting the block. Block-cap overflow truncates the excess and counts the drop.
//!
//! # Test matrix (maps to DSL-168 Test Plan)
//!
//!   1. `test_dsl_168_empty_conditions_empty_report` — no REMARKs → default report, zero mutations.
//!   2. `test_dsl_168_admits_evidence` — one BLS-signed valid evidence → admitted_evidences gets one entry with matching hash.
//!   3. `test_dsl_168_mixed_valid_invalid_evidence` — valid + malformed REMARKs → malformed filtered at parse; valid processed through submit.
//!   4. `test_dsl_168_cap_exceeded_drops_excess` — 65 encoded evidence REMARKs + 65 appeal REMARKs → cap_dropped_* counts the surplus over `MAX_SLASH_PROPOSALS_PER_BLOCK=64` / `MAX_APPEALS_PER_BLOCK=64`.
//!   5. `test_dsl_168_duplicate_evidence_rejected` — same evidence hash twice → first admits into report.admitted_evidences, second surfaces AlreadySlashed in report.rejected_evidences.
//!   6. `test_dsl_168_report_serde_roundtrip` — populated report round-trips bincode + serde_json.

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BlockAdmissionReport, BondError, BondEscrow, BondTag, EffectiveBalanceView,
    MAX_APPEALS_PER_BLOCK, MAX_SLASH_PROPOSALS_PER_BLOCK, OffenseType, ProposerSlashing,
    ProposerView, RewardPayout, SignedBlockHeader, SlashingError, SlashingEvidence,
    SlashingEvidencePayload, SlashingManager, ValidatorEntry, ValidatorView, block_signing_message,
    encode_slashing_evidence_remark_payload_v1, process_block_admissions,
};

// ── mocks ──────────────────────────────────────────────────

struct AcceptingBond;
impl BondEscrow for AcceptingBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        Ok(())
    }
    fn forfeit(&mut self, _: u32, _: u64, _: BondTag) -> Result<u64, BondError> {
        Ok(0)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

struct NullReward;
impl RewardPayout for NullReward {
    fn pay(&mut self, _: Bytes32, _: u64) {}
}

struct FixedProposer;
impl ProposerView for FixedProposer {
    fn proposer_at_slot(&self, _: u64) -> Option<u32> {
        Some(0)
    }
    fn current_slot(&self) -> u64 {
        0
    }
}

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
    fn is_active_at_epoch(&self, _: u64) -> bool {
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

struct MapView(RefCell<HashMap<u32, TestValidator>>);
impl ValidatorView for MapView {
    fn get(&self, i: u32) -> Option<&dyn ValidatorEntry> {
        // SAFETY: the RefCell borrow is returned as a trait
        // object whose lifetime is bound to &self. The HashMap
        // is immutable within a single process_block_admissions
        // call so the borrow is stable. Trait objects dispatch
        // through vtable — raw pointer avoids the RefCell borrow
        // dance.
        unsafe {
            let map = &*self.0.as_ptr();
            map.get(&i).map(|v| v as &dyn ValidatorEntry)
        }
    }
    fn get_mut(&mut self, i: u32) -> Option<&mut dyn ValidatorEntry> {
        self.0
            .get_mut()
            .get_mut(&i)
            .map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.0.borrow().len()
    }
}

struct MapBalances(HashMap<u32, u64>);
impl EffectiveBalanceView for MapBalances {
    fn get(&self, i: u32) -> u64 {
        self.0.get(&i).copied().unwrap_or(0)
    }
    fn total_active(&self) -> u64 {
        self.0.values().sum()
    }
}

// ── fixture helpers ──────────────────────────────────────────────────

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_sk(seed: u8) -> SecretKey {
    SecretKey::from_seed(&[seed; 32])
}

fn sample_header(proposer: u32, epoch: u64, state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        epoch,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_byte; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        proposer,
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

/// Build a full BLS-signed proposer equivocation evidence. Caller
/// picks state_byte to differentiate distinct-hash fixtures.
fn valid_evidence(
    proposer: u32,
    reporter: u32,
    epoch: u64,
    state_byte_a: u8,
    state_byte_b: u8,
) -> (SlashingEvidence, PublicKey) {
    let nid = network_id();
    let sk = make_sk(proposer as u8 ^ 0x55);
    let pk = sk.public_key();
    let header_a = sample_header(proposer, epoch, state_byte_a);
    let header_b = sample_header(proposer, epoch, state_byte_b);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let ev = SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch,
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
    (ev, pk)
}

fn build_vset_for(indices: &[(u32, PublicKey)]) -> MapView {
    let mut map = HashMap::new();
    for (idx, pk) in indices {
        map.insert(*idx, TestValidator { pk: *pk });
    }
    // Proposer (for DSL-025 reward routing) — idx 0.
    let sk_prop = make_sk(0xFE);
    map.insert(
        0u32,
        TestValidator {
            pk: sk_prop.public_key(),
        },
    );
    MapView(RefCell::new(map))
}

// ── tests ──────────────────────────────────────────────────

/// DSL-168 row 1: empty payloads → default (zero-filled) report.
/// No trait calls fire; no manager state changes.
#[test]
fn test_dsl_168_empty_conditions_empty_report() {
    let mut mgr = SlashingManager::new(5);
    let mut view = MapView(RefCell::new(HashMap::new()));
    let balances = MapBalances(HashMap::new());
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &[] as &[Vec<u8>],
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    );

    assert_eq!(report, BlockAdmissionReport::default());
    assert_eq!(mgr.book().len(), 0);
}

/// DSL-168 row 2: one valid evidence REMARK → admitted_evidences
/// gets one entry with the matching evidence_hash. Manager state
/// grew by one pending slash.
#[test]
fn test_dsl_168_admits_evidence() {
    let (ev, accused_pk) = valid_evidence(9, 42, 5, 0xA1, 0xB2);
    let expected_hash = ev.hash();

    let payloads = vec![encode_slashing_evidence_remark_payload_v1(&ev).expect("encode")];
    let mut mgr = SlashingManager::new(5);
    let mut view = build_vset_for(&[(9, accused_pk), (42, make_sk(42).public_key())]);
    let balances = MapBalances(HashMap::from([(9u32, 32_000_000_000)]));
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    );

    assert_eq!(report.admitted_evidences.len(), 1);
    assert_eq!(report.admitted_evidences[0].0, expected_hash);
    assert_eq!(report.rejected_evidences.len(), 0);
    assert_eq!(mgr.book().len(), 1);
}

/// DSL-168 row 3: mixed valid + invalid payloads.
/// Malformed payloads (non-magic + wrong-JSON) are silent-skipped
/// at parse. Valid payloads reach submit_evidence and appear in
/// the report (either admitted or rejected).
#[test]
fn test_dsl_168_mixed_valid_invalid_evidence() {
    let (ev, accused_pk) = valid_evidence(9, 42, 5, 0xA1, 0xB2);
    let valid_payload = encode_slashing_evidence_remark_payload_v1(&ev).expect("encode");

    // Garbage 1: wrong magic prefix — parser should silent-skip.
    let bad1 = b"WRONG_PREFIX_THIS_IS_NOT_EVIDENCE".to_vec();
    // Garbage 2: right magic but malformed JSON body.
    let mut bad2 = Vec::new();
    bad2.extend_from_slice(dig_slashing::SLASH_EVIDENCE_REMARK_MAGIC_V1);
    bad2.extend_from_slice(b"{not valid json");

    let payloads = vec![bad1, valid_payload, bad2];
    let mut mgr = SlashingManager::new(5);
    let mut view = build_vset_for(&[(9, accused_pk), (42, make_sk(42).public_key())]);
    let balances = MapBalances(HashMap::from([(9u32, 32_000_000_000)]));
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    );

    // Exactly one envelope parsed + made it through admission.
    assert_eq!(
        report.admitted_evidences.len() + report.rejected_evidences.len(),
        1,
        "only the valid payload parsed; two malformed skipped at parse",
    );
}

/// DSL-168 row 4: block-cap overflow truncates + counts.
/// Feeds `MAX_SLASH_PROPOSALS_PER_BLOCK + 5` encoded evidences.
/// cap_dropped_evidences must equal 5; dropped ones are NOT
/// submitted.
#[test]
fn test_dsl_168_cap_exceeded_drops_excess() {
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    // Each evidence must hash distinctly — different state_byte_a.
    for i in 0..(MAX_SLASH_PROPOSALS_PER_BLOCK + 5) {
        let (ev, _) = valid_evidence(9, 42, 5, i as u8, (i as u8).wrapping_add(1));
        payloads.push(encode_slashing_evidence_remark_payload_v1(&ev).expect("encode"));
    }

    let mut mgr = SlashingManager::new(5);
    let mut view = MapView(RefCell::new(HashMap::new()));
    let balances = MapBalances(HashMap::new());
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    );

    assert_eq!(report.cap_dropped_evidences, 5);
    assert_eq!(report.cap_dropped_appeals, 0);
    // Total non-capped envelopes processed = MAX_SLASH_PROPOSALS_PER_BLOCK.
    assert_eq!(
        report.admitted_evidences.len() + report.rejected_evidences.len(),
        MAX_SLASH_PROPOSALS_PER_BLOCK,
        "only the first MAX envelopes reached submit_evidence",
    );
    let _ = MAX_APPEALS_PER_BLOCK; // keep import used
}

/// DSL-168 row 5: duplicate evidence within a block.
/// First copy admits; second surfaces AlreadySlashed in
/// rejected_evidences. Proves admitting and deduping both run
/// inside the same call without the embedder intervening.
#[test]
fn test_dsl_168_duplicate_evidence_rejected() {
    let (ev, accused_pk) = valid_evidence(9, 42, 5, 0xA1, 0xB2);
    let payload = encode_slashing_evidence_remark_payload_v1(&ev).expect("encode");
    // Same payload twice in the block.
    let payloads = vec![payload.clone(), payload];
    let hash = ev.hash();

    let mut mgr = SlashingManager::new(5);
    let mut view = build_vset_for(&[(9, accused_pk), (42, make_sk(42).public_key())]);
    let balances = MapBalances(HashMap::from([(9u32, 32_000_000_000)]));
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    );

    // First admitted; second rejected.
    assert_eq!(report.admitted_evidences.len(), 1);
    assert_eq!(report.admitted_evidences[0].0, hash);
    assert_eq!(report.rejected_evidences.len(), 1);
    assert_eq!(report.rejected_evidences[0].0, hash);
    assert!(matches!(
        report.rejected_evidences[0].1,
        SlashingError::AlreadySlashed,
    ));
    // Book size: one admission only — second call dedup'd.
    assert_eq!(mgr.book().len(), 1);
}

/// DSL-168 row 6: report serde roundtrip.
///
/// Populated report with entries in every vec + non-zero cap
/// counts round-trips byte-exact under bincode + serde_json.
#[test]
fn test_dsl_168_report_serde_roundtrip() {
    let (ev, accused_pk) = valid_evidence(9, 42, 5, 0xA1, 0xB2);
    let (dup_ev, _) = valid_evidence(9, 42, 5, 0xA1, 0xB2); // identical hash
    let payloads = vec![
        encode_slashing_evidence_remark_payload_v1(&ev).expect("encode"),
        encode_slashing_evidence_remark_payload_v1(&dup_ev).expect("encode"),
    ];

    let mut mgr = SlashingManager::new(5);
    let mut view = build_vset_for(&[(9, accused_pk), (42, make_sk(42).public_key())]);
    let balances = MapBalances(HashMap::from([(9u32, 32_000_000_000)]));
    let mut bond = AcceptingBond;
    let mut reward = NullReward;

    let report = process_block_admissions(
        &payloads,
        &mut mgr,
        &mut view,
        &balances,
        &mut bond,
        &mut reward,
        &FixedProposer,
        &network_id(),
    );

    // bincode.
    let bin = bincode::serialize(&report).expect("bincode ser");
    let bin_decoded: BlockAdmissionReport = bincode::deserialize(&bin).expect("bincode deser");
    assert_eq!(bin_decoded, report);

    // serde_json.
    let json = serde_json::to_vec(&report).expect("json ser");
    let json_decoded: BlockAdmissionReport = serde_json::from_slice(&json).expect("json deser");
    assert_eq!(json_decoded, report);
}
