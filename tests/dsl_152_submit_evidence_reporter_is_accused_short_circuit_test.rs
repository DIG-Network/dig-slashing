//! Requirement DSL-152: `SlashingManager::submit_evidence` must
//! short-circuit on `ReporterIsAccused` BEFORE any state mutation.
//!
//! Traces to: docs/resources/SPEC.md §5.1, §7.3.
//!
//! # Role
//!
//! DSL-012 pinned the `verify_evidence` branch that rejects
//! self-accuse envelopes. DSL-152 is the manager-level invariant:
//! `submit_evidence` calls `verify_evidence` BEFORE touching any
//! bond escrow, reward payout, validator set, pending book, or
//! processed dedup map. The error MUST propagate identically and
//! no side-effect may leak on the rejection path.
//!
//! Placement matters for attack resistance: a malicious reporter
//! submitting `ReporterIsAccused` evidence MUST NOT be able to
//! push state changes — not even a `processed` entry that would
//! grief future honest admissions of the same hash.
//!
//! # Test matrix (maps to DSL-152 Test Plan)
//!
//!   1. `test_dsl_152_self_accuse_proposer` — Proposer slashing
//!      where reporter == proposer index → ReporterIsAccused.
//!   2. `test_dsl_152_self_accuse_attester` — AttesterSlashing
//!      where the sorted intersection of both attestations
//!      CONTAINS the reporter index → ReporterIsAccused.
//!   3. `test_dsl_152_no_state_mutation` — rejection produces
//!      zero bond-lock calls, zero reward-pay calls, empty
//!      pending book, `is_processed(hash)` false → retry
//!      permitted once reporter stops self-accusing.
//!   4. `test_dsl_152_distinct_reporter_ok` — control case:
//!      reporter disjoint from slashable set → admission
//!      succeeds, proving the self-accuse check does not
//!      false-positive.

use std::cell::RefCell;
use std::collections::HashMap;

use chia_bls::{PublicKey, SecretKey};
use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    AttestationData, AttesterSlashing, BLS_SIGNATURE_SIZE, BondError, BondEscrow, BondTag,
    Checkpoint, EffectiveBalanceView, IndexedAttestation, MIN_EFFECTIVE_BALANCE, OffenseType,
    ProposerSlashing, ProposerView, RewardPayout, SignedBlockHeader, SlashingError,
    SlashingEvidence, SlashingEvidencePayload, SlashingManager, ValidatorEntry, ValidatorView,
    block_signing_message,
};

// ─────────────── recording mocks ────────────────────────────────

#[derive(Default)]
struct RecordingBond {
    lock_calls: RefCell<u32>,
    release_calls: RefCell<u32>,
}
impl BondEscrow for RecordingBond {
    fn lock(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        *self.lock_calls.borrow_mut() += 1;
        Ok(())
    }
    fn release(&mut self, _: u32, _: u64, _: BondTag) -> Result<(), BondError> {
        *self.release_calls.borrow_mut() += 1;
        Ok(())
    }
    fn forfeit(&mut self, _: u32, _: u64, _: BondTag) -> Result<u64, BondError> {
        Ok(0)
    }
    fn escrowed(&self, _: u32, _: BondTag) -> u64 {
        0
    }
}

#[derive(Default)]
struct RecordingReward {
    pay_calls: RefCell<u32>,
}
impl RewardPayout for RecordingReward {
    fn pay(&mut self, _: Bytes32, _: u64) {
        *self.pay_calls.borrow_mut() += 1;
    }
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
        MIN_EFFECTIVE_BALANCE
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

struct MapView(HashMap<u32, TestValidator>);
impl ValidatorView for MapView {
    fn get(&self, i: u32) -> Option<&dyn ValidatorEntry> {
        self.0.get(&i).map(|v| v as &dyn ValidatorEntry)
    }
    fn get_mut(&mut self, i: u32) -> Option<&mut dyn ValidatorEntry> {
        self.0.get_mut(&i).map(|v| v as &mut dyn ValidatorEntry)
    }
    fn len(&self) -> usize {
        self.0.len()
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

// ─────────────── fixtures ────────────────────────────────

fn network_id() -> Bytes32 {
    Bytes32::new([0xAAu8; 32])
}

fn make_sk(seed_byte: u8) -> SecretKey {
    SecretKey::from_seed(&[seed_byte; 32])
}

fn sample_header(proposer_index: u32, epoch: u64, state_byte: u8) -> L2BlockHeader {
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

/// Build a signed proposer-equivocation envelope + a view whose
/// validator at `proposer_index` carries the matching BLS pubkey
/// so the downstream signature check would succeed if we reached
/// it. DSL-152 scope is the short-circuit BEFORE that check; we
/// still want the fixtures realistic so control tests can proceed
/// all the way through admission.
fn proposer_evidence(reporter: u32, proposer: u32, epoch: u64) -> (SlashingEvidence, MapView) {
    let nid = network_id();
    let sk = make_sk(0x11);
    let pk = sk.public_key();
    let header_a = sample_header(proposer, epoch, 0xA1);
    let header_b = sample_header(proposer, epoch, 0xB2);
    let sig_a = sign_header(&sk, &header_a, &nid);
    let sig_b = sign_header(&sk, &header_b, &nid);

    let mut map = HashMap::new();
    map.insert(proposer, TestValidator { pk });
    // Reporter validator (so BondEscrow::lock would have a target
    // if we ever reached that step on the distinct-reporter path).
    let sk_r = make_sk(0xFE);
    map.insert(
        reporter,
        TestValidator {
            pk: sk_r.public_key(),
        },
    );

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
    (ev, MapView(map))
}

/// AttesterSlashing envelope — two IndexedAttestations, the
/// intersection of whose `attesting_indices` sets is the slashable
/// cohort. Signatures are placeholder zero bytes; DSL-152 short-
/// circuit fires BEFORE BLS aggregate verify so the envelope need
/// not be cryptographically valid past the self-accuse gate.
fn attester_evidence(
    reporter: u32,
    indices_a: Vec<u32>,
    indices_b: Vec<u32>,
    epoch: u64,
) -> SlashingEvidence {
    let data_a = AttestationData {
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
    };
    let data_b = AttestationData {
        slot: 100,
        index: 0,
        beacon_block_root: Bytes32::new([0x44u8; 32]),
        source: Checkpoint {
            epoch: 2,
            root: Bytes32::new([0x22u8; 32]),
        },
        target: Checkpoint {
            epoch: 3,
            root: Bytes32::new([0x33u8; 32]),
        },
    };

    SlashingEvidence {
        offense_type: OffenseType::AttesterDoubleVote,
        reporter_validator_index: reporter,
        reporter_puzzle_hash: Bytes32::new([0xCCu8; 32]),
        epoch,
        payload: SlashingEvidencePayload::Attester(AttesterSlashing {
            attestation_a: IndexedAttestation {
                attesting_indices: indices_a,
                data: data_a,
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
            attestation_b: IndexedAttestation {
                attesting_indices: indices_b,
                data: data_b,
                signature: vec![0u8; BLS_SIGNATURE_SIZE],
            },
        }),
    }
}

// ─────────────── tests ────────────────────────────────

/// DSL-152 row 1: Proposer slashing where reporter == proposer index.
/// `submit_evidence` must surface `ReporterIsAccused(9)` exactly —
/// identical variant to the `verify_evidence` rejection so callers
/// can dedup error-handling across both entry points.
#[test]
fn test_dsl_152_self_accuse_proposer() {
    let (ev, mut view) = proposer_evidence(9, 9, 50);
    let mut mgr = SlashingManager::new(50);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();

    let err = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &FixedProposer,
            &network_id(),
        )
        .expect_err("self-accuse proposer must reject");

    assert_eq!(err, SlashingError::ReporterIsAccused(9));
}

/// DSL-152 row 2: AttesterSlashing where the sorted intersection of
/// both attestations contains the reporter index → rejected at the
/// verify stage, surfaced through submit_evidence unchanged.
///
/// Intersection of `{1, 3, 5, 7}` and `{3, 5, 7, 9}` is `{3, 5, 7}`.
/// Reporter = 5 ∈ intersection → ReporterIsAccused(5).
#[test]
fn test_dsl_152_self_accuse_attester() {
    let ev = attester_evidence(5, vec![1, 3, 5, 7], vec![3, 5, 7, 9], 50);
    // View population is irrelevant — verify_evidence's
    // `slashable_validators()` computes the cohort from the
    // payload directly, not from validator_set.
    let mut view = MapView(HashMap::new());
    let mut mgr = SlashingManager::new(50);
    let balances = MapBalances(HashMap::new());
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();

    let err = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &FixedProposer,
            &network_id(),
        )
        .expect_err("reporter in intersection must reject");

    assert_eq!(err, SlashingError::ReporterIsAccused(5));
}

/// DSL-152 row 3: rejection path leaves state pristine.
///
/// After a self-accuse rejection:
///   - `RecordingBond::lock_calls == 0` (bond was NEVER escrowed).
///   - `RecordingReward::pay_calls == 0` (no whistleblower reward).
///   - `book.len() == 0` (no PendingSlash inserted).
///   - `is_processed(hash) == false` — retry is permitted once the
///     reporter stops self-accusing (critical: otherwise a griefer
///     could burn an evidence hash by filing a self-accuse envelope
///     and poisoning the `processed` dedup map).
#[test]
fn test_dsl_152_no_state_mutation() {
    let (ev, mut view) = proposer_evidence(9, 9, 50);
    let hash = ev.hash();
    let mut mgr = SlashingManager::new(50);
    let balances = MapBalances(HashMap::from([(9u32, MIN_EFFECTIVE_BALANCE)]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();

    let err = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &FixedProposer,
            &network_id(),
        )
        .expect_err("self-accuse must reject");
    assert!(matches!(err, SlashingError::ReporterIsAccused(_)));

    // No bond lock attempted.
    assert_eq!(
        *bond.lock_calls.borrow(),
        0,
        "bond.lock must NOT be called on ReporterIsAccused rejection",
    );
    // No reward payout.
    assert_eq!(
        *reward.pay_calls.borrow(),
        0,
        "reward.pay must NOT be called on rejection",
    );
    // No pending insert.
    assert_eq!(mgr.book().len(), 0, "book must remain empty");
    // No processed entry — griefer cannot poison the dedup map.
    assert!(
        !mgr.is_processed(&hash),
        "processed map must remain clean so a non-self-accusing \
         reporter can resubmit the identical hash later",
    );
}

/// DSL-152 row 4: distinct reporter admission proceeds normally.
///
/// Proves the short-circuit does not false-positive — reporter = 42,
/// proposer = 9; slashable set is `{9}`; reporter ∉ {9} so
/// ReporterIsAccused does NOT fire and the pipeline runs to
/// completion.
#[test]
fn test_dsl_152_distinct_reporter_ok() {
    let (ev, mut view) = proposer_evidence(42, 9, 50);
    // Add validator at idx=0 — DSL-025 reward routing looks up the
    // block proposer via `proposer_at_slot(current_slot()) == 0`.
    // Without a live entry at idx=0, submit_evidence surfaces
    // `ValidatorNotRegistered(0)` before the pending book is
    // written, masking the DSL-152 control path.
    view.0.insert(
        0,
        TestValidator {
            pk: make_sk(0x22).public_key(),
        },
    );
    let mut mgr = SlashingManager::new(50);
    // Balances for both reporter + accused so DSL-025 reward math
    // has data to work with.
    let balances = MapBalances(HashMap::from([
        (9u32, MIN_EFFECTIVE_BALANCE),
        (42u32, MIN_EFFECTIVE_BALANCE),
    ]));
    let mut bond = RecordingBond::default();
    let mut reward = RecordingReward::default();

    let out = mgr
        .submit_evidence(
            ev,
            &mut view,
            &balances,
            &mut bond,
            &mut reward,
            &FixedProposer,
            &network_id(),
        )
        .expect("distinct reporter must admit");

    // Admission side-effects visible: bond locked, at least one
    // reward paid, book grew by one.
    assert_eq!(*bond.lock_calls.borrow(), 1, "reporter bond escrowed");
    assert!(
        *reward.pay_calls.borrow() >= 1,
        "whistleblower + proposer rewards routed",
    );
    assert_eq!(mgr.book().len(), 1, "pending slash inserted");
    assert!(
        mgr.is_processed(&out.pending_slash_hash),
        "processed map records successful admission",
    );
}
