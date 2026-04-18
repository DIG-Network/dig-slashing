# dig-slashing

Validator slashing, Ethereum-parity attestation participation accounting, continuous inactivity accounting, and optimistic fraud-proof appeals for the DIG Network L2.

- **Crate:** `dig-slashing` v0.1.0
- **Edition:** 2024
- **Spec:** [docs/resources/SPEC.md](docs/resources/SPEC.md) (normative; every public symbol traces to a `DSL-NNN` requirement)
- **Scope:** Validator slashing only. Four offenses (ProposerEquivocation, InvalidBlock, AttesterDoubleVote, AttesterSurroundVote). DFSP / storage-provider slashing is out of scope.

---

## Table of Contents

1. [Design Overview](#design-overview)
2. [Integration at a Glance](#integration-at-a-glance)
3. [Top-Level Entry Points](#top-level-entry-points)
4. [Embedder-Implemented Traits](#embedder-implemented-traits)
5. [Data Types](#data-types)
6. [Report Types (Outputs)](#report-types-outputs)
7. [Error Surface](#error-surface)
8. [Wire Format (REMARK)](#wire-format-remark)
9. [Validator-Local Slashing Protection](#validator-local-slashing-protection)
10. [Constants](#constants)
11. [Determinism & Serde Guarantees](#determinism--serde-guarantees)
12. [Full Symbol Index](#full-symbol-index)

---

## Design Overview

The crate is **state-owning but IO-agnostic**. It holds three long-lived trackers (`SlashingManager`, `ParticipationTracker`, `InactivityScoreTracker`) bundled in `SlashingSystem`. Every interaction with validator stake, bond escrow, reward payouts, collateral, and justification state goes through **trait objects** (`&dyn`, `&mut dyn`) that the embedder implements.

Three processing modes:

| Mode | Entry point | Trigger |
|------|-------------|---------|
| **Genesis** | `SlashingSystem::genesis` | Chain birth |
| **Block admission** | `process_block_admissions` | Per block, after executing REMARK conditions |
| **Epoch boundary** | `run_epoch_boundary` | Per epoch, at block N where `N % BLOCKS_PER_EPOCH == 0` |
| **Reorg** | `rewind_all_on_reorg` | Fork-choice moves tip backward |
| **Appeal verdict** | `adjudicate_appeal` | After verifier emits `AppealVerdict` |

Optimistic slashing with **8-epoch appeal window** (`SLASH_APPEAL_WINDOW_EPOCHS`). Evidence admits immediately; finalisation is deferred. Appeals filed during the window may revert the slash.

---

## Integration at a Glance

```rust
use dig_slashing::{
    GenesisParameters, SlashingSystem,
    process_block_admissions, run_epoch_boundary, rewind_all_on_reorg,
    adjudicate_appeal,
};

// 1. Bootstrap at chain genesis.
let mut sys = SlashingSystem::genesis(&GenesisParameters {
    genesis_epoch: 0,
    initial_validator_count: 1_024,
    network_id: network_id,
});

// 2. Per block — ingest REMARK-carried evidence + appeals.
let block_report = process_block_admissions(
    &remark_payloads,
    &mut sys.manager,
    &mut my_validator_set,      // impl ValidatorView
    &my_balances,                // impl EffectiveBalanceView
    &mut my_bond_escrow,         // impl BondEscrow
    &mut my_reward_payout,       // impl RewardPayout
    &my_proposer_view,           // impl ProposerView
    sys.network_id(),
);

// 3. Per epoch boundary.
let epoch_report = run_epoch_boundary(
    &mut sys.manager,
    &mut sys.participation,
    &mut sys.inactivity,
    &mut my_validator_set,
    &my_balances,
    &mut my_bond_escrow,
    &mut my_reward_payout,
    &my_justification_view,      // impl JustificationView
    current_epoch_ending,
    validator_count,
    total_active_balance,
);

// 4. On fork-choice reorg.
let reorg_report = rewind_all_on_reorg(
    &mut sys.manager,
    &mut sys.participation,
    &mut sys.inactivity,
    &mut my_slashing_protection,
    &mut my_validator_set,
    &mut my_collateral,          // impl CollateralSlasher
    &mut my_bond_escrow,
    new_tip_epoch,
    new_tip_slot,
    validator_count,
)?;

// 5. After appeal verifier produces a verdict.
let adj_report = adjudicate_appeal(
    verdict,
    &mut pending,
    &appeal,
    &mut my_validator_set,
    &my_balances,
    Some(&mut my_collateral),
    &mut my_bond_escrow,
    &mut my_reward_payout,
    &mut my_reward_clawback,     // impl RewardClawback
    &mut my_slashed_in_window,   // BTreeMap<(u64, u32), u64>
    proposer_puzzle_hash,
    reason_hash,
    current_epoch,
)?;
```

---

## Top-Level Entry Points

All single-call. Inputs are typed state + trait-object handles. Outputs are typed reports with `Serialize + Deserialize + PartialEq + Eq`.

### `SlashingSystem::genesis`

Bootstrap at chain birth (DSL-128 / DSL-170).

```rust
pub fn genesis(params: &GenesisParameters) -> SlashingSystem;
pub fn network_id(&self) -> &Bytes32;
```

**Input:** `&GenesisParameters { genesis_epoch: u64, initial_validator_count: usize, network_id: Bytes32 }`.
**Output:** `SlashingSystem { manager, participation, inactivity, network_id }`.

### `process_block_admissions`

Single-call block-level REMARK admission dispatcher (DSL-168).

```rust
pub fn process_block_admissions<P: AsRef<[u8]>>(
    payloads: &[P],                          // raw REMARK condition bodies
    manager: &mut SlashingManager,
    validator_set: &mut dyn ValidatorView,
    effective_balances: &dyn EffectiveBalanceView,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
    proposer: &dyn ProposerView,
    network_id: &Bytes32,
) -> BlockAdmissionReport;
```

Evidence REMARKs process before appeal REMARKs so a same-block appeal can reference a same-block evidence admission. Per-envelope failures populate rejected vecs; block-cap overflow truncates + counts. Never aborts the block outright.

### `run_epoch_boundary`

Fixed 8-step per-epoch pipeline (DSL-127 / DSL-169). Order is normative: flag deltas → inactivity score update → inactivity penalties → finalise expired slashes → rotate participation → advance manager epoch → resize trackers → prune old state. Rewards are routed through `RewardPayout::pay`; inactivity penalties debit validator stake via `ValidatorEntry::slash_absolute`.

```rust
pub fn run_epoch_boundary(
    manager: &mut SlashingManager,
    participation: &mut ParticipationTracker,
    inactivity: &mut InactivityScoreTracker,
    validator_set: &mut dyn ValidatorView,
    effective_balances: &dyn EffectiveBalanceView,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
    justification: &dyn JustificationView,
    current_epoch_ending: u64,
    validator_count: usize,
    total_active_balance: u64,
) -> EpochBoundaryReport;
```

### `rewind_all_on_reorg`

Global fork-choice reorg (DSL-130). Rewinds manager → participation → inactivity → slashing protection in fixed order. Returns `Err(ReorgTooDeep)` when `current_epoch - new_tip_epoch > CORRELATION_WINDOW_EPOCHS` (36).

```rust
pub fn rewind_all_on_reorg(
    manager: &mut SlashingManager,
    participation: &mut ParticipationTracker,
    inactivity: &mut InactivityScoreTracker,
    protection: &mut SlashingProtection,
    validator_set: &mut dyn ValidatorView,
    collateral: &mut dyn CollateralSlasher,
    bond_escrow: &mut dyn BondEscrow,
    new_tip_epoch: u64,
    new_tip_slot: u64,
    validator_count: usize,
) -> Result<ReorgReport, SlashingError>;
```

### `adjudicate_appeal`

Appeal adjudication dispatcher (DSL-167). Composes DSL-064..073 slice functions into one end-to-end pass. Sustained branch: revert base slash → revert collateral → restore status → clawback rewards → forfeit reporter bond → absorb shortfall → reporter penalty → status-reverted. Rejected branch: forfeit appellant bond → challenge-open.

```rust
pub fn adjudicate_appeal(
    verdict: AppealVerdict,
    pending: &mut PendingSlash,
    appeal: &SlashAppeal,
    validator_set: &mut dyn ValidatorView,
    effective_balances: &dyn EffectiveBalanceView,
    collateral: Option<&mut dyn CollateralSlasher>,
    bond_escrow: &mut dyn BondEscrow,
    reward_payout: &mut dyn RewardPayout,
    reward_clawback: &mut dyn RewardClawback,
    slashed_in_window: &mut BTreeMap<(u64, u32), u64>,
    proposer_puzzle_hash: Bytes32,
    reason_hash: Bytes32,
    current_epoch: u64,
) -> Result<AppealAdjudicationResult, BondError>;
```

### `SlashingManager` single-envelope methods

```rust
impl SlashingManager {
    pub fn new(current_epoch: u64) -> Self;
    pub fn current_epoch(&self) -> u64;
    pub fn set_epoch(&mut self, epoch: u64);

    // Admission.
    pub fn submit_evidence(
        &mut self,
        evidence: SlashingEvidence,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        bond_escrow: &mut dyn BondEscrow,
        reward_payout: &mut dyn RewardPayout,
        proposer: &dyn ProposerView,
        network_id: &Bytes32,
    ) -> Result<SlashingResult, SlashingError>;

    pub fn submit_appeal(
        &mut self,
        appeal: &SlashAppeal,
        bond_escrow: &mut dyn BondEscrow,
    ) -> Result<(), SlashingError>;

    // Lifecycle.
    pub fn finalise_expired_slashes(
        &mut self,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        bond_escrow: &mut dyn BondEscrow,
        total_active_balance: u64,
    ) -> Vec<FinalisationResult>;

    pub fn rewind_on_reorg(
        &mut self,
        new_tip_epoch: u64,
        validator_set: &mut dyn ValidatorView,
        collateral: Option<&mut dyn CollateralSlasher>,
        bond_escrow: &mut dyn BondEscrow,
    ) -> Vec<Bytes32>;

    // Query.
    pub fn is_processed(&self, hash: &Bytes32) -> bool;
    pub fn is_slashed(&self, idx: u32, vs: &dyn ValidatorView) -> bool;
    pub fn is_slashed_in_window(&self, epoch: u64, idx: u32) -> bool;
    pub fn pending(&self, hash: &Bytes32) -> Option<&PendingSlash>;
    pub fn book(&self) -> &PendingSlashBook;
    pub fn book_mut(&mut self) -> &mut PendingSlashBook;
    pub fn processed_epoch(&self, hash: &Bytes32) -> Option<u64>;

    // Maintenance.
    pub fn prune(&mut self, before_epoch: u64) -> usize;
    pub fn prune_processed_older_than(&mut self, cutoff_epoch: u64) -> usize;
    pub fn mark_processed(&mut self, hash: Bytes32, epoch: u64);
    pub fn mark_slashed_in_window(&mut self, epoch: u64, idx: u32, effective_balance: u64);
}
```

---

## Embedder-Implemented Traits

The embedder supplies concrete types implementing these traits. All are consumed via `&dyn` / `&mut dyn` so generics never leak.

### `ValidatorView` + `ValidatorEntry`

Active validator set + per-validator state accessors.

```rust
pub trait ValidatorView {
    fn get(&self, index: u32) -> Option<&dyn ValidatorEntry>;
    fn get_mut(&mut self, index: u32) -> Option<&mut dyn ValidatorEntry>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool { self.len() == 0 }
}

pub trait ValidatorEntry {
    fn public_key(&self) -> &chia_bls::PublicKey;
    fn puzzle_hash(&self) -> Bytes32;
    fn effective_balance(&self) -> u64;
    fn is_slashed(&self) -> bool;
    fn activation_epoch(&self) -> u64;
    fn exit_epoch(&self) -> u64;
    fn is_active_at_epoch(&self, epoch: u64) -> bool;
    fn slash_absolute(&mut self, amount_mojos: u64, epoch: u64) -> u64;
    fn credit_stake(&mut self, amount_mojos: u64) -> u64;
    fn restore_status(&mut self) -> bool;
    fn schedule_exit(&mut self, epoch: u64);
}
```

### `EffectiveBalanceView`

```rust
pub trait EffectiveBalanceView {
    fn get(&self, index: u32) -> u64;
    fn total_active(&self) -> u64;
}
```

### `BondEscrow` + `BondTag` + `BondError`

Reporter + appellant bond accounting.

```rust
pub enum BondTag {
    Reporter(Bytes32),     // evidence_hash
    Appellant(Bytes32),    // appeal_hash
}

pub trait BondEscrow {
    fn lock(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError>;
    fn release(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError>;
    fn forfeit(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<u64, BondError>;
    fn escrowed(&self, principal_idx: u32, tag: BondTag) -> u64;
}
```

### `RewardPayout` + `RewardClawback`

```rust
pub trait RewardPayout {
    fn pay(&mut self, principal_ph: Bytes32, amount_mojos: u64);
}

pub trait RewardClawback {
    fn claw_back(&mut self, principal_ph: Bytes32, amount: u64) -> u64;  // returns actual
}
```

### `CollateralSlasher` + `CollateralError`

Optional (light-client embedders pass `None` where the signature allows).

```rust
pub trait CollateralSlasher {
    fn credit(&mut self, validator_idx: u32, amount_mojos: u64);
    fn slash(&mut self, _: u32, _: u64, _: u64) -> Result<(u64, u64), CollateralError> {
        Err(CollateralError::NoCollateral)
    }
}
```

### `ProposerView`

```rust
pub trait ProposerView {
    fn proposer_at_slot(&self, slot: u64) -> Option<u32>;
    fn current_slot(&self) -> u64;
}
```

### `JustificationView`

```rust
pub trait JustificationView {
    fn latest_finalized_epoch(&self) -> u64;

    // Default-impl methods for DSL-143 forward-compatibility.
    fn current_justified_checkpoint(&self) -> Checkpoint { ... }
    fn previous_justified_checkpoint(&self) -> Checkpoint { ... }
    fn finalized_checkpoint(&self) -> Checkpoint { ... }
    fn canonical_block_root_at_slot(&self, _: u64) -> Option<Bytes32> { None }
    fn canonical_target_root_for_epoch(&self, _: u64) -> Option<Bytes32> { None }
}
```

### `InvalidBlockOracle` + `ExecutionOutcome`

Deterministic re-execution for invalid-block evidence + appeals.

```rust
pub enum ExecutionOutcome {
    Valid,
    Invalid(InvalidBlockReason),
}

pub trait InvalidBlockOracle {
    fn re_execute(&self, header: &SignedBlockHeader, witness: &[u8]) -> ExecutionOutcome;
    fn verify_failure(
        &self,
        _: &SignedBlockHeader,
        _: InvalidBlockReason,
        _: &[u8],
    ) -> Result<(), ()> { Ok(()) }
}
```

### `PublicKeyLookup`

Blanket impl over `T: ValidatorView + ?Sized` — any `ValidatorView` is automatically a `PublicKeyLookup`. Consumers: DSL-006/013 verifiers.

---

## Data Types

### Evidence envelopes (admission-side)

```rust
pub struct SlashingEvidence {
    pub offense_type: OffenseType,
    pub reporter_validator_index: u32,
    pub reporter_puzzle_hash: Bytes32,
    pub epoch: u64,
    pub payload: SlashingEvidencePayload,
}

pub enum SlashingEvidencePayload {
    Proposer(ProposerSlashing),
    Attester(AttesterSlashing),
    InvalidBlock(InvalidBlockProof),
}

pub enum OffenseType {
    ProposerEquivocation,
    InvalidBlock,
    AttesterDoubleVote,
    AttesterSurroundVote,
}

pub enum InvalidBlockReason {
    BadStateRoot, BadTxRoot, BadReceiptRoot, BadGasUsed,
    BadBloom, BadDifficulty, BadExtraData, BadTimestamp,
}

impl SlashingEvidence {
    pub fn hash(&self) -> Bytes32;                  // DSL-002 content-address
    pub fn slashable_validators(&self) -> Vec<u32>; // DSL-010
}
```

Per-payload:

```rust
pub struct ProposerSlashing {
    pub signed_header_a: SignedBlockHeader,
    pub signed_header_b: SignedBlockHeader,
}

pub struct AttesterSlashing {
    pub attestation_a: IndexedAttestation,
    pub attestation_b: IndexedAttestation,
}

pub struct InvalidBlockProof {
    pub signed_header: SignedBlockHeader,
    #[serde(with = "serde_bytes")] pub failure_witness: Vec<u8>,
    pub failure_reason: InvalidBlockReason,
}

pub struct SignedBlockHeader {
    pub message: dig_block::L2BlockHeader,
    #[serde(with = "serde_bytes")] pub signature: Vec<u8>,  // 96-byte BLS
}

pub struct IndexedAttestation {
    pub attesting_indices: Vec<u32>,   // strict-ascending
    pub data: AttestationData,
    #[serde(with = "serde_bytes")] pub signature: Vec<u8>,
}

pub struct AttestationData {
    pub slot: u64,
    pub index: u32,
    pub beacon_block_root: Bytes32,
    pub source: Checkpoint,
    pub target: Checkpoint,
}

pub struct Checkpoint {
    pub epoch: u64,
    pub root: Bytes32,
}

pub struct VerifiedEvidence {
    pub offense_type: OffenseType,
    pub slashable_validator_indices: Vec<u32>,
}
```

### Appeal envelopes

```rust
pub struct SlashAppeal {
    pub evidence_hash: Bytes32,
    pub appellant_index: u32,
    pub appellant_puzzle_hash: Bytes32,
    pub filed_epoch: u64,
    pub payload: SlashAppealPayload,
}

pub enum SlashAppealPayload {
    Proposer(ProposerSlashingAppeal),
    Attester(AttesterSlashingAppeal),
    InvalidBlock(InvalidBlockAppeal),
}

pub struct ProposerSlashingAppeal {
    pub ground: ProposerAppealGround,
    #[serde(with = "serde_bytes")] pub witness: Vec<u8>,
}

pub struct AttesterSlashingAppeal {
    pub ground: AttesterAppealGround,
    #[serde(with = "serde_bytes")] pub witness: Vec<u8>,
}

pub struct InvalidBlockAppeal {
    pub ground: InvalidBlockAppealGround,
    #[serde(with = "serde_bytes")] pub witness: Vec<u8>,
}

pub enum ProposerAppealGround {
    HeadersIdentical,
    ProposerIndexMismatch,
    SignatureAInvalid,
    SignatureBInvalid,
    SlotMismatch,
    ValidatorNotActiveAtEpoch,
}

pub enum AttesterAppealGround {
    AttestationsIdentical,
    NotSlashableByPredicate,
    EmptyIntersection,
    SignatureAInvalid,
    SignatureBInvalid,
    InvalidIndexedAttestationStructure,
    ValidatorNotInIntersection { validator_index: u32 },
}

pub enum InvalidBlockAppealGround {
    BlockActuallyValid,
    ProposerSignatureInvalid,
    FailureReasonMismatch,
    EvidenceEpochMismatch,
}

impl SlashAppeal {
    pub fn hash(&self) -> Bytes32;     // DSL-159 content-address
}

pub enum AppealVerdict {
    Sustained { reason: AppealSustainReason },
    Rejected { reason: AppealRejectReason },
}

impl AppealVerdict {
    pub fn to_appeal_outcome(&self) -> AppealOutcome;  // DSL-171
}
```

### Pending slash + lifecycle

```rust
pub struct PendingSlash {
    pub evidence_hash: Bytes32,
    pub evidence: SlashingEvidence,
    pub verified: VerifiedEvidence,
    pub status: PendingSlashStatus,
    pub submitted_at_epoch: u64,
    pub window_expires_at_epoch: u64,
    pub base_slash_per_validator: Vec<PerValidatorSlash>,
    pub reporter_bond_mojos: u64,
    pub appeal_history: Vec<AppealAttempt>,
}

pub enum PendingSlashStatus {
    Accepted,
    ChallengeOpen { first_appeal_filed_epoch: u64, appeal_count: u8 },
    Reverted    { winning_appeal_hash: Bytes32, reverted_at_epoch: u64 },
    Finalised   { finalised_at_epoch: u64 },
}

pub struct AppealAttempt {
    pub appeal_hash: Bytes32,
    pub appellant_index: u32,
    pub filed_epoch: u64,
    pub outcome: AppealOutcome,
    pub bond_mojos: u64,
}

pub enum AppealOutcome {
    Won,
    Lost { reason_hash: Bytes32 },
    Pending,
}

pub struct PendingSlashBook { /* keyed store */ }
impl PendingSlashBook {
    pub fn new(capacity: usize) -> Self;
    pub fn insert(&mut self, record: PendingSlash) -> Result<(), SlashingError>;
    pub fn get(&self, hash: &Bytes32) -> Option<&PendingSlash>;
    pub fn get_mut(&mut self, hash: &Bytes32) -> Option<&mut PendingSlash>;
    pub fn remove(&mut self, hash: &Bytes32) -> Option<PendingSlash>;
    pub fn expired_by(&self, current_epoch: u64) -> Vec<Bytes32>;
    pub fn submitted_after(&self, new_tip_epoch: u64) -> Vec<Bytes32>;
    pub fn len(&self) -> usize;
    pub fn capacity(&self) -> usize;
}
```

### Participation / Inactivity

```rust
pub struct ParticipationFlags(pub u8);  // 3-bit mask: TIMELY_SOURCE | TIMELY_TARGET | TIMELY_HEAD

pub struct ParticipationTracker { /* two-epoch ring */ }
impl ParticipationTracker {
    pub fn new(validator_count: usize, initial_epoch: u64) -> Self;
    pub fn current_epoch_number(&self) -> u64;
    pub fn current_flags(&self, idx: u32) -> Option<ParticipationFlags>;
    pub fn previous_flags(&self, idx: u32) -> Option<ParticipationFlags>;
    pub fn validator_count(&self) -> usize;
    pub fn rotate_epoch(&mut self, new_epoch: u64, validator_count: usize);
    pub fn rewind_on_reorg(&mut self, new_tip_epoch: u64, validator_count: usize) -> u64;
    pub fn record_attestation(
        &mut self,
        data: &AttestationData,
        attesting_indices: &[u32],
        flags: ParticipationFlags,
    ) -> Result<(), ParticipationError>;
}

pub struct InactivityScoreTracker { /* u64 per validator */ }
impl InactivityScoreTracker {
    pub fn new(validator_count: usize) -> Self;
    pub fn score(&self, idx: u32) -> Option<u64>;
    pub fn set_score(&mut self, idx: u32, score: u64) -> bool;
    pub fn validator_count(&self) -> usize;
    pub fn update_for_epoch(&mut self, participation: &ParticipationTracker, in_finality_stall: bool);
    pub fn epoch_penalties(
        &self,
        effective_balances: &dyn EffectiveBalanceView,
        in_finality_stall: bool,
    ) -> Vec<(u32, u64)>;
    pub fn resize_for(&mut self, validator_count: usize);
    pub fn rewind_on_reorg(&mut self, depth: u64) -> u64;
}

pub struct FlagDelta {
    pub validator_index: u32,
    pub reward: u64,
    pub penalty: u64,
}

// Free functions.
pub fn compute_flag_deltas(
    participation: &ParticipationTracker,
    effective_balances: &dyn EffectiveBalanceView,
    total_active_balance: u64,
    in_finality_stall: bool,
) -> Vec<FlagDelta>;

pub fn base_reward(effective_balance: u64, total_active_balance: u64) -> u64;
pub fn classify_timeliness(inclusion_delay: u64, source_epoch_distance: u64) -> ParticipationFlags;
pub fn proposer_inclusion_reward(attester_base_reward: u64) -> u64;
pub fn in_finality_stall(current_epoch: u64, latest_finalized_epoch: u64) -> bool;
```

---

## Report Types (Outputs)

All reports `derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)`; most also `Default`. Every field serde-roundtrips byte-exact via bincode + serde_json (DSL-163/164/165/167/168).

### `SlashingResult` — output of `submit_evidence`

```rust
pub struct SlashingResult {
    pub per_validator: Vec<PerValidatorSlash>,
    pub whistleblower_reward: u64,
    pub proposer_reward: u64,
    pub burn_amount: u64,
    pub reporter_bond_escrowed: u64,
    pub pending_slash_hash: Bytes32,
}

pub struct PerValidatorSlash {
    pub validator_index: u32,
    pub base_slash_amount: u64,
    pub effective_balance_at_slash: u64,
    pub collateral_slashed: u64,
}
```

### `FinalisationResult` — output of `finalise_expired_slashes` (one per finalised pending slash)

```rust
pub struct FinalisationResult {
    pub evidence_hash: Bytes32,
    pub per_validator_correlation_penalty: Vec<(u32, u64)>,
    pub reporter_bond_returned: u64,
    pub exit_lock_until_epoch: u64,
}
```

### `EpochBoundaryReport` — output of `run_epoch_boundary`

```rust
pub struct EpochBoundaryReport {
    pub flag_deltas: Vec<FlagDelta>,
    pub inactivity_penalties: Vec<(u32, u64)>,
    pub finalisations: Vec<FinalisationResult>,
    pub in_finality_stall: bool,
    pub pruned_entries: usize,
}
```

### `ReorgReport` — output of `rewind_all_on_reorg`

```rust
pub struct ReorgReport {
    pub rewound_pending_slashes: Vec<Bytes32>,
    pub participation_epochs_dropped: u64,
    pub inactivity_epochs_dropped: u64,
    pub protection_rewound: bool,
}
```

### `BlockAdmissionReport` — output of `process_block_admissions`

```rust
pub struct BlockAdmissionReport {
    pub admitted_evidences: Vec<(Bytes32, SlashingResult)>,
    pub rejected_evidences: Vec<(Bytes32, SlashingError)>,
    pub admitted_appeals: Vec<Bytes32>,
    pub rejected_appeals: Vec<(Bytes32, SlashingError)>,
    pub cap_dropped_evidences: usize,
    pub cap_dropped_appeals: usize,
}
```

### `AppealAdjudicationResult` — output of `adjudicate_appeal`

```rust
pub struct AppealAdjudicationResult {
    pub appeal_hash: Bytes32,
    pub evidence_hash: Bytes32,
    pub outcome: AppealOutcome,

    // Sustained-branch fields (zero/empty on Rejected).
    pub reverted_stake_mojos: Vec<(u32, u64)>,
    pub reverted_collateral_mojos: Vec<(u32, u64)>,
    pub clawback_shortfall: u64,
    pub reporter_bond_forfeited: u64,
    pub appellant_award_mojos: u64,
    pub reporter_penalty_mojos: u64,

    // Rejected-branch fields (zero on Sustained).
    pub appellant_bond_forfeited: u64,
    pub reporter_award_mojos: u64,

    // Both branches.
    pub burn_amount: u64,
}
```

### Adjudicator intermediate structs (exposed for consumers of the slice functions)

```rust
pub struct ClawbackResult { pub wb_amount: u64, pub prop_amount: u64, pub wb_clawed: u64, pub prop_clawed: u64, pub shortfall: u64 }
pub struct BondSplitResult { pub forfeited: u64, pub winner_award: u64, pub burn: u64 }
pub struct ShortfallAbsorption { pub clawback_shortfall: u64, pub original_burn: u64, pub final_burn: u64, pub residue: u64 }
pub struct ReporterPenalty { pub reporter_index: u32, pub effective_balance_at_slash: u64, pub penalty_mojos: u64 }
```

---

## Error Surface

One enum, flat match exhaustive. Variants derive `Debug + Clone + PartialEq + Eq + Error + Serialize + Deserialize`.

```rust
pub enum SlashingError {
    // Verification.
    OffenseTooOld { offense_epoch: u64, current_epoch: u64 },
    ReporterIsAccused(u32),
    InvalidProposerSlashing(String),
    InvalidAttesterSlashing(String),
    InvalidBlockProofRejected(String),
    InvalidIndexedAttestation(String),
    InvalidBlockPredicateFailed(String),
    ValidatorNotRegistered(u32),
    BlsVerificationFailed,

    // Admission.
    AlreadySlashed,
    DuplicateEvidence,
    DuplicateAppeal,
    PendingBookFull,
    BondLockFailed,
    BlockCapExceeded { actual: usize, limit: usize },
    EvidencePayloadTooLarge { actual: usize, limit: usize },
    AppealPayloadTooLarge { actual: usize, limit: usize },

    // Appeal.
    UnknownEvidence(String),
    AppealWindowExpired { submitted_at: u64, window: u64, current: u64 },
    SlashAlreadyReverted,
    SlashAlreadyFinalised,
    VariantMismatch,
    MaxAppealAttemptsExceeded,

    // REMARK.
    AdmissionPuzzleHashMismatch,

    // Orchestration.
    ReorgTooDeep { depth: u64, limit: u64 },
}
```

`BondError` is separate, propagated from `BondEscrow` trait operations:

```rust
pub enum BondError {
    InsufficientBalance { have: u64, need: u64 },
    TagNotFound { tag: BondTag },
    DoubleLock   { tag: BondTag },
}
```

---

## Wire Format (REMARK)

Evidence + appeals travel on-chain as `REMARK` conditions. Each payload = magic prefix || `serde_json(envelope)`.

```rust
pub const SLASH_EVIDENCE_REMARK_MAGIC_V1: &[u8] = b"DIG_SLASH_EVIDENCE_V1\0";
pub const SLASH_APPEAL_REMARK_MAGIC_V1:   &[u8] = b"DIG_SLASH_APPEAL_V1\0";

// Encode / parse.
pub fn encode_slashing_evidence_remark_payload_v1(ev: &SlashingEvidence) -> serde_json::Result<Vec<u8>>;
pub fn encode_slash_appeal_remark_payload_v1(ap: &SlashAppeal) -> serde_json::Result<Vec<u8>>;
pub fn parse_slashing_evidence_from_conditions<P: AsRef<[u8]>>(payloads: &[P]) -> Vec<SlashingEvidence>;
pub fn parse_slash_appeals_from_conditions<P: AsRef<[u8]>>(payloads: &[P]) -> Vec<SlashAppeal>;

// Puzzle reveal / puzzle hash.
pub fn slashing_evidence_remark_puzzle_reveal_v1(ev: &SlashingEvidence) -> Vec<u8>;
pub fn slashing_evidence_remark_puzzle_hash_v1(ev: &SlashingEvidence) -> Bytes32;
pub fn slash_appeal_remark_puzzle_reveal_v1(ap: &SlashAppeal) -> Vec<u8>;
pub fn slash_appeal_remark_puzzle_hash_v1(ap: &SlashAppeal) -> Bytes32;

// Admission policy enforcers.
pub fn enforce_slashing_evidence_remark_admission(...) -> Result<(), SlashingError>;
pub fn enforce_slash_appeal_remark_admission(...) -> Result<(), SlashingError>;

// Mempool policy (per-envelope).
pub fn enforce_slashing_evidence_mempool_policy(...) -> Result<(), SlashingError>;
pub fn enforce_slashing_evidence_mempool_dedup_policy(pending: &[SlashingEvidence], incoming: &[SlashingEvidence]) -> Result<(), SlashingError>;
pub fn enforce_slashing_evidence_payload_cap(ev: &SlashingEvidence) -> Result<(), SlashingError>;
pub fn enforce_slash_appeal_mempool_policy(...) -> Result<(), SlashingError>;
pub fn enforce_slash_appeal_mempool_dedup_policy(pending: &[SlashAppeal], incoming: &[SlashAppeal]) -> Result<(), SlashingError>;
pub fn enforce_slash_appeal_payload_cap(ap: &SlashAppeal) -> Result<(), SlashingError>;
pub fn enforce_slash_appeal_window_policy(...) -> Result<(), SlashingError>;
pub fn enforce_slash_appeal_terminal_status_policy(...) -> Result<(), SlashingError>;
pub fn enforce_slash_appeal_variant_policy(...) -> Result<(), SlashingError>;

// Block-level caps.
pub fn enforce_block_level_slashing_caps(evidences: &[SlashingEvidence]) -> Result<(), SlashingError>;
pub fn enforce_block_level_appeal_caps(appeals: &[SlashAppeal]) -> Result<(), SlashingError>;
```

---

## Validator-Local Slashing Protection

Prevents a validator's OWN keys from producing slashable evidence (double-propose, double-vote, surround-vote). Persisted independently of consensus state.

```rust
pub struct SlashingProtection { /* private fields */ }

impl SlashingProtection {
    pub fn new() -> Self;

    // Proposal guard (DSL-094).
    pub fn check_proposal_slot(&self, slot: u64) -> bool;
    pub fn record_proposal(&mut self, slot: u64);
    pub fn last_proposed_slot(&self) -> u64;

    // Attestation guards (DSL-095/096).
    pub fn check_attestation(
        &self,
        source_epoch: u64,
        target_epoch: u64,
        block_hash: &Bytes32,
    ) -> bool;
    pub fn record_attestation(&mut self, source_epoch: u64, target_epoch: u64, block_hash: Bytes32);
    pub fn last_attested_source_epoch(&self) -> u64;
    pub fn last_attested_target_epoch(&self) -> u64;
    pub fn last_attested_block_hash(&self) -> Option<&str>;

    // Reorg rewind.
    pub fn rewind_proposal_to_slot(&mut self, new_tip_slot: u64);
    pub fn rewind_attestation_to_epoch(&mut self, new_tip_epoch: u64);
    pub fn reconcile_with_chain_tip(&mut self, tip_slot: u64, tip_epoch: u64);

    // Persistence (JSON, `#[serde(default)]` for forward-compat).
    pub fn save(&self, path: &Path) -> std::io::Result<()>;
    pub fn load(path: &Path) -> std::io::Result<Self>;
}
```

---

## Constants

Re-exported from `dig_slashing::constants`:

| Constant | Value | Role |
|----------|-------|------|
| `MIN_EFFECTIVE_BALANCE` | 32_000_000_000 | Baseline stake (mojos) |
| `BPS_DENOMINATOR` | 10_000 | Basis-point scale |
| `EQUIVOCATION_BASE_BPS` | 500 | Proposer eq. base rate (5%) |
| `INVALID_BLOCK_BASE_BPS` | 300 | Invalid-block + reporter-penalty rate (3%) |
| `ATTESTATION_BASE_BPS` | 100 | Attester double/surround rate (1%) |
| `MAX_PENALTY_BPS` | 10_000 | 100% cap |
| `MIN_SLASHING_PENALTY_QUOTIENT` | 32 | Floor divisor (eff / 32) |
| `PROPORTIONAL_SLASHING_MULTIPLIER` | 3 | Correlation penalty multiplier |
| `SLASH_APPEAL_WINDOW_EPOCHS` | 8 | Appeal window |
| `SLASH_LOCK_EPOCHS` | 100 | Exit lock after finalisation |
| `MAX_APPEAL_ATTEMPTS_PER_SLASH` | 8 | Per-pending cap |
| `MAX_PENDING_SLASHES` | 4_096 | Book capacity |
| `MAX_SLASH_PROPOSALS_PER_BLOCK` | 64 | Per-block evidence cap |
| `MAX_APPEALS_PER_BLOCK` | 64 | Per-block appeal cap |
| `MAX_SLASH_PROPOSAL_PAYLOAD_BYTES` | 65_536 | Evidence payload cap |
| `MAX_APPEAL_PAYLOAD_BYTES` | 131_072 | Appeal payload cap (2× evidence) |
| `REPORTER_BOND_MOJOS` | `MIN_EFFECTIVE_BALANCE / 64` | Reporter bond |
| `APPELLANT_BOND_MOJOS` | `MIN_EFFECTIVE_BALANCE / 64` | Appellant bond |
| `BOND_AWARD_TO_WINNER_BPS` | 5_000 | 50% of forfeited bond |
| `WHISTLEBLOWER_REWARD_QUOTIENT` | 512 | `total_eff / 512` |
| `PROPOSER_REWARD_QUOTIENT` | 8 | `wb / 8` |
| `WEIGHT_DENOMINATOR` | 64 | Participation weight scale |
| `TIMELY_SOURCE_WEIGHT` | 14 | source-hit share |
| `TIMELY_TARGET_WEIGHT` | 26 | target-hit share |
| `TIMELY_HEAD_WEIGHT` | 14 | head-hit share |
| `PROPOSER_WEIGHT` | 8 | proposer-inclusion share |
| `TIMELY_SOURCE_FLAG_INDEX` | 0 | bit position |
| `TIMELY_TARGET_FLAG_INDEX` | 1 | bit position |
| `TIMELY_HEAD_FLAG_INDEX` | 2 | bit position |
| `BASE_REWARD_FACTOR` | 64 | reward scaling |
| `INACTIVITY_PENALTY_QUOTIENT` | 16_777_216 | `eff × score / quot` |
| `INACTIVITY_SCORE_BIAS` | 4 | miss-in-stall increment |
| `INACTIVITY_SCORE_RECOVERY_RATE` | 16 | out-of-stall decrement |
| `MIN_EPOCHS_TO_INACTIVITY_PENALTY` | 4 | stall threshold |
| `MIN_ATTESTATION_INCLUSION_DELAY` | 1 | earliest-include delay |
| `TIMELY_SOURCE_MAX_DELAY_SLOTS` | 5 | source deadline |
| `TIMELY_TARGET_MAX_DELAY_SLOTS` | 32 | target deadline |
| `MAX_VALIDATORS_PER_COMMITTEE` | 2_048 | per-committee cap |
| `BLS_SIGNATURE_SIZE` | 96 | BLS sig wire bytes |
| `BLS_PUBLIC_KEY_SIZE` | 48 | BLS pubkey wire bytes |
| `DOMAIN_BEACON_PROPOSER` | `b"..."` | Proposer signing-message domain |
| `DOMAIN_BEACON_ATTESTER` | `b"..."` | Attester signing-message domain |
| `DOMAIN_SLASHING_EVIDENCE` | `b"DIG_SLASH_EVIDENCE_V1\0"` | Evidence hash domain |
| `DOMAIN_SLASH_APPEAL` | `b"DIG_SLASH_APPEAL_V1"` | Appeal hash domain |
| `SLASH_EVIDENCE_REMARK_MAGIC_V1` | `b"DIG_SLASH_EVIDENCE_V1\0"` | REMARK magic prefix |
| `SLASH_APPEAL_REMARK_MAGIC_V1` | `b"DIG_SLASH_APPEAL_V1\0"` | REMARK magic prefix |
| `SLASH_LOOKBACK_EPOCHS` | re-exported from `dig_epoch` | Max offense age |

---

## Determinism & Serde Guarantees

- **Content addressing** — `SlashingEvidence::hash()` (DSL-002) + `SlashAppeal::hash()` (DSL-159) are `SHA-256(DOMAIN || bincode(envelope))`. Deterministic across runs; any one-bit field mutation shifts the digest.
- **Byte-exact serde** — every `Serialize + Deserialize` type round-trips byte-exact via `bincode` + `serde_json`. Witness/signature fields use `#[serde(with = "serde_bytes")]` for binary-tight encoding under bincode.
- **Fixed step order** — `run_epoch_boundary` (8 steps, DSL-127) + `rewind_all_on_reorg` (4 steps, DSL-130) + `adjudicate_appeal` sustained branch (8 steps) all execute in normative order pinned by per-DSL tests.
- **Saturating arithmetic** — correlation penalty (DSL-030/151), inactivity penalty (DSL-092), clawback (DSL-142), slash_absolute (DSL-131) all saturate rather than wrap.
- **No custom crypto** — BLS via `chia_bls`, SHA-256 via `chia_sha2`, Merkle via `chia_sdk_types`, canonical bytes via `dig_block::block_signing_message` + `AttestationData::signing_root`.

---

## Full Symbol Index

171 `DSL-NNN` requirements, each with a dedicated `tests/dsl_NNN_<name>_test.rs` file. See:

- [docs/requirements/IMPLEMENTATION_ORDER.md](docs/requirements/IMPLEMENTATION_ORDER.md) — phase + status table
- [docs/requirements/domains/](docs/requirements/domains/) — per-domain NORMATIVE + VERIFICATION + TRACKING
- [docs/resources/SPEC.md](docs/resources/SPEC.md) — master spec

Phase breakdown:

| Phase | DSL range | Domain | Status |
|-------|-----------|--------|--------|
| 0 | 001..021 | Evidence | ✅ |
| 1 | 022..033 | Lifecycle (admission + finalise) | ✅ |
| 2 | 034..073 | Appeal (grounds + adjudication) | ✅ |
| 3 | 074..086 | Participation (Altair) | ✅ |
| 4 | 087..093 | Inactivity (Bellatrix) | ✅ |
| 5 | 094..101 | Slashing protection | ✅ |
| 6 | 102..120 | REMARK wire + policy | ✅ |
| 7 | 121..126 | Bond accounting | ✅ |
| 8 | 127..130 | Orchestration | ✅ |
| 9 | 131..145 | Embedder trait contracts | ✅ |
| 10 | 146..156 | Gap fills 1 (defensive ops) | ✅ |
| 11 | 157..166 | Gap fills 2 (serde + BondTag) | ✅ |
| 12 | 167..171 | Integration closures (dispatchers) | ✅ |
| **Total** | **171** | | **171 ✅** |

---

## Upstream Dependencies (must-use)

| Purpose | Crate |
|---------|-------|
| BLS signatures | `chia-bls` 0.26 |
| SHA-256 | `chia-sha2` 0.26 |
| Merkle + run_puzzle (dev) | `chia-sdk-types` 0.30 |
| CLVM tree hash | `clvm-utils` 0.26 |
| Block types + signing message | `dig-block` 0.1 |
| Epoch arithmetic | `dig-epoch` 0.1 |
| Network constants | `dig-constants` 0.1 |

The crate NEVER reimplements primitives available upstream. Never use custom BLS / SHA / Merkle / epoch math — only the above.
