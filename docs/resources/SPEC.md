# dig-slashing Specification

**Version:** 0.4.0
**Status:** Draft
**Date:** 2026-04-16

## 1. Overview

`dig-slashing` is a self-contained Rust crate for the DIG Network L2 blockchain. It owns **validator slashing**, **optimistic slash lifecycle with fraud-proof appeal**, **Ethereum-parity attestation participation accounting with rewards and missed-attestation penalties**, **Ethereum-parity inactivity accounting**, **validator-local slashing protection**, and **slashing-evidence + slash-appeal mempool/block admission**.

**Scope:** consensus-level validator concerns only. DFSP / storage-provider slashing is out of scope.

The crate **does** own:

- **Offense catalogue** (`OffenseType`): `ProposerEquivocation`, `InvalidBlock`, `AttesterDoubleVote`, `AttesterSurroundVote`. Four discrete, cryptographically-provable offenses.
- **Evidence envelopes + payloads**: `SlashingEvidence` wrapper over `ProposerSlashing`, `AttesterSlashing`, `InvalidBlockProof`. Ethereum-parity shapes (`Checkpoint`, `AttestationData`, `IndexedAttestation`, `SignedBlockHeader`).
- **Per-offense deterministic verifiers**.
- **Optimistic slashing lifecycle** — base slash applied immediately on evidence inclusion; challenge window opens; `SlashingManager` tracks slash state through `Submitted → Accepted → ChallengeOpen → (Reverted | Finalised)`.
- **Fraud-proof appeal system** — `SlashAppeal` with payload variants mirroring each offense; `verify_appeal` adjudicates the fraud proof; `AppealAdjudicator` applies reversal or upholds the slash, routing reporter and appellant bonds.
- **Pending-slash book** — `PendingSlashBook` keyed by evidence hash, tracks lifecycle status, timers, bond escrow tags, and appeal history.
- **Attestation participation accounting** — `ParticipationFlags` bitmask (`TIMELY_SOURCE`, `TIMELY_TARGET`, `TIMELY_HEAD`), `ParticipationTracker` (previous-epoch + current-epoch arrays), Ethereum-parity base reward formula, per-flag rewards/penalties, proposer inclusion reward.
- **Inactivity accounting** — `InactivityScoreTracker` per-validator score, `in_finality_stall` detection, per-epoch inactivity penalty formula. Continuous accounting; **not** event-driven slashing — matches Ethereum.
- **Epoch-boundary orchestration** — single deterministic sequence that rotates participation, computes flag deltas, updates inactivity scores, applies correlation penalties, and finalises expired slashes.
- **Genesis / initialisation policy** — explicit initial state + parameters.
- **Reward routing** — pay-to-puzzle-hash for whistleblower + proposer + appellant awards.
- **Bond escrow** — `BondEscrow` trait; escrowed mojos held against reporter/appellant validator stake, released or forfeited per adjudication.
- **Reorg handling** — `rewind_on_reorg(depth)` for participation + pending slashes + slashing protection.
- **Slashing protection** — `SlashingProtection` validator-local JSON watermarks with surround-vote self-check.
- **REMARK wires + admission + mempool policy** for evidence and appeal.
- **Constants, error types, serialization.**

The crate does **not** own:

- **Block format** — `dig-block`. Consumed.
- **Validator set + stake + effective-balance math + activation/exit queues** — `dig-consensus`. Consumed via `ValidatorView` / `EffectiveBalanceView`.
- **Bond escrow storage** — `dig-collateral` (or `dig-bond-escrow`). Consumed via `BondEscrow`.
- **Collateral manager** — `dig-collateral`. Consumed via `CollateralSlasher`.
- **Fork choice / justification / finalisation** — `dig-consensus`. Consumed via `JustificationView` / `ProposerView`.
- **Block re-execution engine** (used by invalid-block appeal oracle) — `dig-block` / `dig-clvm`. Consumed via `InvalidBlockOracle`.
- **Epoch arithmetic + lookback constants** — `dig-epoch`. Re-exported.
- **Network id** — `dig-constants`. Injected.
- **Attestation gossip + aggregation + inclusion** — `dig-gossip` / `dig-consensus`. Tracker is told when an attestation is included; it does not observe gossip.
- **Mempool storage** — `dig-mempool`.
- **Reward account storage** — `dig-consensus` (or reward-distribution crate). Consumed via `RewardClawback` + `RewardPayout` traits.
- **CLVM execution** — `dig-clvm`. `run_puzzle` dev-dep only.
- **DFSP / storage-provider slashing** — out of scope.

**Hard boundary:** every external input (pubkeys, balances, current epoch, network id, justification view, proposer view, bond escrow) is injected through traits/parameters. No database, no network, no CLVM in production. Policy is protocol law — constants, not configuration.

### 1.1 Design Principles

- **Validator-only scope.**
- **Four discrete slashable offenses.** All cryptographically provable. Inactivity is continuous accounting, not a slashable offense — matches Ethereum.
- **Ethereum-parity economics + shapes; DIG mechanics.** Weights, quotients, inactivity math match Ethereum Altair/Bellatrix. Block times and epoch sizes follow DIG (`BLOCKS_PER_EPOCH = 32` at 3 s/block → 96 s/epoch).
- **Optimistic slashing with fraud-proof appeal.** Slash is debited at evidence inclusion but reversible during an 8-epoch challenge window. If no winning appeal, slash finalises + correlation penalty applies + exit lock starts.
- **Appeals are deterministic fraud proofs.** They prove that the original evidence fails a verifier precondition — not that slashing policy was wrong.
- **Symmetric bonds.** Reporter escrows `REPORTER_BOND_MOJOS`; appellant escrows `APPELLANT_BOND_MOJOS`. Losing party forfeits; winning party receives 50%, 50% burned.
- **Single base-reward formula drives all participation economics.** `base_reward = effective_balance * BASE_REWARD_FACTOR / isqrt(total_active_balance)`.
- **Deterministic and pure.** Every verifier is a function of inputs. No I/O, no wall-clock, no RNG.
- **One source of truth per constant.** Lookback from `dig-epoch`. Block format from `dig-block`. BLS from `chia-bls`. No re-derivations.
- **Validator-local vs consensus-global are separate.** `SlashingProtection` is per-validator JSON; `SlashingManager` is consensus-global.

### 1.2 Crate Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `dig-block` | 0.1 | `L2BlockHeader`, `block_signing_message`, `beacon_block_header_signing_root`, `attestation_data_signing_root`. |
| `dig-epoch` | 0.1 | `SLASH_LOOKBACK_EPOCHS`, `CORRELATION_WINDOW_EPOCHS`, `BLOCKS_PER_EPOCH`, `L2_BLOCK_TIME_MS`, height↔epoch helpers. |
| `dig-constants` | 0.1 | `NetworkConstants`. |
| `chia-protocol` | 0.26 | `Bytes32`, `Coin`, `CoinSpend`. |
| `chia-bls` | 0.26 | `Signature`, `PublicKey`, `verify`, `aggregate`, `aggregate_verify`. |
| `chia-sha2` | 0.26 | `Sha256`. |
| `chia-sdk-types` | 0.30 | `MerkleTree` + `MerkleProof` for participation witness (reorg + appeal). `run_puzzle` dev-dep. |
| `clvm-utils` | 0.26 | `tree_hash` for REMARK puzzle-hash derivation. |
| `clvmr` | 0.11 | Dev-dep. |
| `serde`, `serde_json`, `serde_bytes`, `bincode` | — | Serialization. |
| `thiserror`, `hex`, `tracing` | — | Utility. |
| `parking_lot` | — | Optional `threadsafe`. |
| `num-integer` | — | `Roots::sqrt` for base-reward. |

### 1.3 Design Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Four discrete offenses (Proposer/Invalid-Block/Attester-Double-Vote/Attester-Surround-Vote) | Fully covered by cryptographic evidence. Matches Ethereum except sync-committee-slashing (no sync committee in DIG). |
| 2 | Inactivity is NOT an offense | Continuous per-epoch accounting. Penalties debited each epoch from `InactivityScoreTracker`, not via `SlashingManager`. Matches Ethereum's treatment of inactivity leak. Simplifies appeal system (no fraud proof for continuous accounting). |
| 3 | No sync committee | DIG does not ship sync committees. `WEIGHT_DENOMINATOR = 64` retained for Ethereum parity; 2 units unassigned. Attester max = 54/64 × base_reward. |
| 4 | Optimistic slashing with 8-epoch appeal window | Balances finality (~12.8 min at 32×3 s/epoch) against operator-mistake / evidence-forgery risk. |
| 5 | Appeals are fraud proofs | Deterministic, cannot be overturned by governance. |
| 6 | `BondEscrow` trait abstracts coin movement | `dig-slashing` does not own escrow storage; escrow lives in `dig-collateral` or a dedicated crate. |
| 7 | `RewardPayout` + `RewardClawback` traits abstract reward routing | Per-principal pay-to-puzzle-hash coins created by the consensus layer; clawback on sustained appeal debits that account before falling back to reporter bond. |
| 8 | `ProposerView` trait identifies block proposer at slot | Needed to route proposer-inclusion rewards and, at evidence-inclusion time, identify the block proposer for the whistleblower-proposer-reward leg. |
| 9 | `reporter_index ≠ accused_index` enforced at admission | Prevents self-slashing-for-profit (validator reports self → collects wb reward). |
| 10 | Explicit epoch-boundary ordering | (a) rotate participation, (b) compute flag deltas, (c) update inactivity scores, (d) inactivity penalties, (e) finalise expired slashes (incl. correlation). Fixed sequence; deterministic; testable. |
| 11 | Reorg handling in main body | Participation flags and pending slashes both sensitive to fork-choice reorgs. Explicit `rewind_on_reorg(depth)` on every stateful component. |
| 12 | `slash_absolute(mojos)` is the canonical API; legacy `slash(percentage)` deprecated | Historical l2_driver code uses percentages; Ethereum-parity math uses absolute mojos. `slash_absolute` is primary; `slash(pct)` shim retained for migration only. |
| 13 | Genesis initialisation fully specified | Prevents surprise during bootstrap. Empty `processed`, empty `PendingSlashBook`, zero inactivity scores, zero participation flags, `current_epoch = 0`. |
| 14 | Maximal reuse of Chia + DIG crates | No reimplementations of BLS, SHA-256, Merkle, signing messages, epoch constants. |

## 2. Constants

### 2.1 Penalty Base Rates (BPS)

```rust
pub const EQUIVOCATION_BASE_BPS: u16 = 500;
pub const INVALID_BLOCK_BASE_BPS: u16 = 300;
pub const ATTESTATION_BASE_BPS: u16 = 100;
pub const MAX_PENALTY_BPS: u16 = 1_000;
pub const BPS_DENOMINATOR: u64 = 10_000;
```

### 2.2 Ethereum-Parity Slashing Quotients

```rust
pub const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 32;
pub const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 3;
pub use dig_epoch::CORRELATION_WINDOW_EPOCHS;
pub const SLASH_LOCK_EPOCHS: u64 = 100;
```

### 2.3 Reward Economics

```rust
pub const BASE_REWARD_FACTOR: u64 = 64;

/// WEIGHT_DENOMINATOR = 64, Ethereum-parity. 2 units are reserved (no sync committee
/// in DIG). Assigned weights sum to 62; max attester reward = 54/64 × base_reward.
pub const TIMELY_SOURCE_WEIGHT: u64 = 14;
pub const TIMELY_TARGET_WEIGHT: u64 = 26;
pub const TIMELY_HEAD_WEIGHT:   u64 = 14;
pub const PROPOSER_WEIGHT:      u64 = 8;
pub const WEIGHT_DENOMINATOR:   u64 = 64;

pub const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 512;
pub const PROPOSER_REWARD_QUOTIENT: u64 = 8;
```

### 2.4 Inactivity

```rust
pub const MIN_EPOCHS_TO_INACTIVITY_PENALTY: u64 = 4;
pub const INACTIVITY_SCORE_BIAS: u64 = 4;
pub const INACTIVITY_SCORE_RECOVERY_RATE: u64 = 16;
pub const INACTIVITY_PENALTY_QUOTIENT: u64 = 16_777_216;
```

### 2.5 Attestation Timeliness

```rust
pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;
pub const TIMELY_SOURCE_MAX_DELAY_SLOTS: u64 = 5;   // integer_sqrt(32)
pub const TIMELY_TARGET_MAX_DELAY_SLOTS: u64 = 32;  // SLOTS_PER_EPOCH
pub const TIMELY_HEAD_MAX_DELAY_SLOTS: u64 = 1;
```

### 2.6 Appeal System

```rust
pub const SLASH_APPEAL_WINDOW_EPOCHS: u64 = 8;
pub const REPORTER_BOND_MOJOS: u64 = MIN_EFFECTIVE_BALANCE / 64;
pub const APPELLANT_BOND_MOJOS: u64 = MIN_EFFECTIVE_BALANCE / 64;
pub const BOND_AWARD_TO_WINNER_BPS: u16 = 5_000;  // 50%
pub const MAX_PENDING_SLASHES: usize = 4_096;
pub const MAX_APPEAL_ATTEMPTS_PER_SLASH: usize = 4;
pub const MAX_APPEAL_PAYLOAD_BYTES: usize = 131_072;  // 128 KiB
```

### 2.7 Lookback & Validator Parameters

```rust
pub use dig_epoch::SLASH_LOOKBACK_EPOCHS;
pub use dig_consensus::MIN_VALIDATOR_COLLATERAL as MIN_EFFECTIVE_BALANCE;
```

### 2.8 Block Admission

```rust
pub const MAX_SLASH_PROPOSALS_PER_BLOCK: usize = 64;
pub const MAX_SLASH_PROPOSAL_PAYLOAD_BYTES: usize = 65_536;
pub const MAX_APPEALS_PER_BLOCK: usize = 64;
pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2_048;
pub const MAX_ATTESTATIONS_PER_BLOCK: usize = 128;
```

### 2.9 Flag Bit Indices

```rust
pub const TIMELY_SOURCE_FLAG_INDEX: u8 = 0;
pub const TIMELY_TARGET_FLAG_INDEX: u8 = 1;
pub const TIMELY_HEAD_FLAG_INDEX:   u8 = 2;
```

### 2.10 Domain Separation Tags + BLS Widths

```rust
pub const DOMAIN_SLASHING_EVIDENCE:       &[u8] = b"DIG_SLASHING_EVIDENCE_V1";
pub const DOMAIN_SLASH_APPEAL:            &[u8] = b"DIG_SLASH_APPEAL_V1";
pub const DOMAIN_BEACON_PROPOSER:         &[u8] = b"DIG_BEACON_PROPOSER_V1";
pub const DOMAIN_BEACON_ATTESTER:         &[u8] = b"DIG_BEACON_ATTESTER_V1";
pub const DOMAIN_AGGREGATE_AND_PROOF:     &[u8] = b"DIG_AGGREGATE_AND_PROOF_V1";
pub const SLASH_EVIDENCE_REMARK_MAGIC_V1: &[u8] = b"DIG_SLASH_EVIDENCE_V1\0";
pub const SLASH_APPEAL_REMARK_MAGIC_V1:   &[u8] = b"DIG_SLASH_APPEAL_V1\0";

pub const BLS_SIGNATURE_SIZE:  usize = 96;
pub const BLS_PUBLIC_KEY_SIZE: usize = 48;
```

## 3. Data Model

### 3.1 Primitive Types

| Type | Source | Usage |
|------|--------|-------|
| `Bytes32` | `chia-protocol` | Every 32-byte hash. |
| `Signature` | `chia-bls` | Proposer/attester sigs. |
| `PublicKey` | `chia-bls` | Validator pubkeys. |
| `L2BlockHeader` | `dig-block` | Decoded from `ProposerSlashing` / `InvalidBlockProof`. |

### 3.2 OffenseType

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OffenseType {
    ProposerEquivocation,
    InvalidBlock,
    AttesterDoubleVote,
    AttesterSurroundVote,
}

impl OffenseType {
    pub fn base_penalty_bps(&self) -> u16;
    pub fn name(&self) -> &'static str;
    pub fn description(&self) -> &'static str;
}
```

| Variant | `base_penalty_bps()` |
|---------|---------------------|
| `ProposerEquivocation` | `EQUIVOCATION_BASE_BPS` (500) |
| `InvalidBlock` | `INVALID_BLOCK_BASE_BPS` (300) |
| `AttesterDoubleVote` | `ATTESTATION_BASE_BPS` (100) |
| `AttesterSurroundVote` | `ATTESTATION_BASE_BPS` (100) |

### 3.3 Checkpoint / AttestationData / IndexedAttestation

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Checkpoint { pub epoch: u64, pub root: Bytes32 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AttestationData {
    pub slot: u64,
    pub index: u64,                  // committee index
    pub beacon_block_root: Bytes32,  // head vote
    pub source: Checkpoint,          // FFG source
    pub target: Checkpoint,          // FFG target
}
impl AttestationData {
    pub fn signing_root(&self, network_id: &Bytes32) -> Bytes32;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedAttestation {
    pub attesting_indices: Vec<u32>,  // strictly ascending, no duplicates
    pub data: AttestationData,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,           // 96 bytes G2 aggregate
}
impl IndexedAttestation {
    pub fn validate_structure(&self) -> Result<(), SlashingError>;
    pub fn verify_signature(&self, pks: &dyn PublicKeyLookup, nid: &Bytes32) -> Result<(), SlashingError>;
}
```

Double-vote predicate: `a.target.epoch == b.target.epoch && a.data != b.data`.
Surround-vote predicate: `a.source.epoch < b.source.epoch && a.target.epoch > b.target.epoch` (or mirror).

### 3.4 Evidence Payloads

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedBlockHeader {
    pub message: L2BlockHeader,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposerSlashing {
    pub signed_header_a: SignedBlockHeader,
    pub signed_header_b: SignedBlockHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttesterSlashing {
    pub attestation_a: IndexedAttestation,
    pub attestation_b: IndexedAttestation,
}
impl AttesterSlashing {
    pub fn slashable_indices(&self) -> Vec<u32>;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum InvalidBlockReason {
    BadStateRoot, BadParentRoot, BadTimestamp, BadProposerIndex,
    TransactionExecutionFailure, OverweightBlock, DuplicateTransaction, Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvalidBlockProof {
    pub signed_header: SignedBlockHeader,
    #[serde(with = "serde_bytes")]
    pub failure_witness: Vec<u8>,
    pub failure_reason: InvalidBlockReason,
}
```

### 3.5 SlashingEvidence (envelope)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingEvidence {
    pub offense_type: OffenseType,
    pub reporter_validator_index: u32,
    pub reporter_puzzle_hash: Bytes32,
    pub epoch: u64,
    pub payload: SlashingEvidencePayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashingEvidencePayload {
    Proposer(ProposerSlashing),
    Attester(AttesterSlashing),
    InvalidBlock(InvalidBlockProof),
}

impl SlashingEvidence {
    pub fn hash(&self) -> Bytes32;
    pub fn slashable_validators(&self) -> Vec<u32>;
}
```

### 3.6 Appeal Payloads (Fraud Proofs)

#### ProposerSlashingAppeal

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposerSlashingAppeal {
    pub ground: ProposerAppealGround,
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProposerAppealGround {
    HeadersIdentical,
    ProposerIndexMismatch,
    SignatureAInvalid,
    SignatureBInvalid,
    SlotMismatch,
    ValidatorNotActiveAtEpoch,
}
```

#### AttesterSlashingAppeal

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttesterSlashingAppeal {
    pub ground: AttesterAppealGround,
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AttesterAppealGround {
    AttestationsIdentical,
    NotSlashableByPredicate,
    EmptyIntersection,
    SignatureAInvalid,
    SignatureBInvalid,
    InvalidIndexedAttestationStructure,
    ValidatorNotInIntersection { validator_index: u32 },
}
```

#### InvalidBlockAppeal

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvalidBlockAppeal {
    pub ground: InvalidBlockAppealGround,
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,   // block body + pre-state + parent witness
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum InvalidBlockAppealGround {
    BlockActuallyValid,
    ProposerSignatureInvalid,
    FailureReasonMismatch,
    EvidenceEpochMismatch,
}
```

### 3.7 SlashAppeal (envelope)

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashAppeal {
    pub evidence_hash: Bytes32,
    pub appellant_index: u32,
    pub appellant_puzzle_hash: Bytes32,
    pub filed_epoch: u64,
    pub payload: SlashAppealPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlashAppealPayload {
    Proposer(ProposerSlashingAppeal),
    Attester(AttesterSlashingAppeal),
    InvalidBlock(InvalidBlockAppeal),
}

impl SlashAppeal {
    pub fn hash(&self) -> Bytes32;
}
```

### 3.8 Pending Slash Lifecycle

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PendingSlashStatus {
    Accepted,
    ChallengeOpen { first_appeal_filed_epoch: u64, appeal_count: u8 },
    Reverted  { winning_appeal_hash: Bytes32, reverted_at_epoch: u64 },
    Finalised { finalised_at_epoch: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingSlash {
    pub evidence_hash: Bytes32,
    pub evidence: SlashingEvidence,
    pub verified: VerifiedEvidence,
    pub status: PendingSlashStatus,
    pub submitted_at_epoch: u64,
    pub window_expires_at_epoch: u64,  // submitted_at + SLASH_APPEAL_WINDOW_EPOCHS
    pub base_slash_per_validator: Vec<PerValidatorSlash>,
    pub reporter_bond_mojos: u64,
    pub appeal_history: Vec<AppealAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppealAttempt {
    pub appeal_hash: Bytes32,
    pub appellant_index: u32,
    pub filed_epoch: u64,
    pub outcome: AppealOutcome,
    pub bond_mojos: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AppealOutcome {
    Won,
    Lost { reason_hash: Bytes32 },
    Pending,
}
```

### 3.9 Results

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerifiedEvidence {
    pub offense_type: OffenseType,
    pub slashable_validator_indices: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingResult {
    pub per_validator: Vec<PerValidatorSlash>,
    pub whistleblower_reward: u64,
    pub proposer_reward: u64,
    pub burn_amount: u64,
    pub reporter_bond_escrowed: u64,
    pub pending_slash_hash: Bytes32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PerValidatorSlash {
    pub validator_index: u32,
    pub base_slash_amount: u64,
    pub collateral_slashed: u64,
    pub effective_balance_at_slash: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppealVerdict {
    Sustained { reason: AppealSustainReason },
    Rejected  { reason: AppealRejectReason },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppealAdjudicationResult {
    pub appeal_hash: Bytes32,
    pub evidence_hash: Bytes32,
    pub outcome: AppealOutcome,
    pub reverted_stake_mojos: Vec<(u32, u64)>,
    pub reverted_collateral_mojos: Vec<(u32, u64)>,
    pub clawback_shortfall: u64,
    pub reporter_bond_forfeited: u64,
    pub appellant_award_mojos: u64,
    pub reporter_penalty_mojos: u64,
    pub appellant_bond_forfeited: u64,
    pub reporter_award_mojos: u64,
    pub burn_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalisationResult {
    pub evidence_hash: Bytes32,
    pub per_validator_correlation_penalty: Vec<(u32, u64)>,
    pub reporter_bond_returned: u64,
    pub exit_lock_until_epoch: u64,
}
```

### 3.10 Participation + Inactivity + Protection

```rust
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct ParticipationFlags(pub u8);
impl ParticipationFlags {
    pub fn is_source_timely(&self) -> bool;
    pub fn is_target_timely(&self) -> bool;
    pub fn is_head_timely(&self) -> bool;
    pub fn set(&mut self, flag_index: u8);
    pub fn has(&self, flag_index: u8) -> bool;
}

pub struct ParticipationTracker { /* see §8 */ }
pub struct InactivityScoreTracker { /* see §9 */ }

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlashingProtection {
    pub last_proposed_slot: u64,
    pub last_attested_source_epoch: u64,
    pub last_attested_target_epoch: u64,
    #[serde(default)]
    pub last_attested_block_hash: Option<String>,
    pub last_attested_height: u64,
    pub last_attested_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlagDelta {
    pub validator_index: u32,
    pub reward: u64,
    pub penalty: u64,
}
```

## 4. Slashing Geometry & Economics

```
─── Discrete Slashable Offenses ────────────────────────────────────────────
Offense               | Base BPS | Ethereum quotient       | Appeal window
----------------------+----------+------------------------+------------------
ProposerEquivocation  |   500    | eff_bal / 32            | 8 epochs
InvalidBlock          |   300    | eff_bal / 32            | 8 epochs
AttesterDoubleVote    |   100    | eff_bal / 32            | 8 epochs
AttesterSurroundVote  |   100    | eff_bal / 32            | 8 epochs

base_slash = max(
    eff_bal * base_bps / 10_000,
    eff_bal / MIN_SLASHING_PENALTY_QUOTIENT
)

At finalisation (not on admission):
    correlation_penalty = eff_bal
        * min(total_slashed_in_window * 3, total_active_balance)
        / total_active_balance

On admission (reversible):
    wb_reward  = eff_bal / 512
    prop_reward= wb_reward / 8
    burn       = base_slash - wb_reward - prop_reward
    reporter_bond escrowed (eff_bal / 64)
    base slash applied to validator

─── Participation (per validator per epoch, Ethereum Altair minus sync) ────
base_reward = effective_balance * 64 / integer_sqrt(total_active_balance)

TIMELY_SOURCE (14/64): reward on hit,   penalty on miss
TIMELY_TARGET (26/64): reward on hit,   penalty on miss
TIMELY_HEAD   (14/64): reward on hit,   NO penalty on miss
Proposer inclusion  : base_reward * 8 / (64 - 8)

In finality stall: rewards = 0, penalties still debit.

─── Inactivity Accounting (continuous, not a slashing event) ───────────────
On target miss + stall: score += 4
Otherwise (in stall)  : score -= min(1, score)
Out of stall          : score -= min(16, score) (global recovery)
Per-epoch penalty     : eff_bal * score / 16_777_216  (ONLY during stall)

─── Appeal Economics ───────────────────────────────────────────────────────
Reporter bond  : eff_bal / 64   escrowed at evidence admission
Appellant bond : eff_bal / 64   escrowed at appeal admission

On appeal WIN:
    Revert   : base slash + collateral slash (per slashed validator)
    Clawback : wb_reward + prop_reward from their reward accounts
    Forfeit  : reporter bond
    Award    : appellant_award = forfeited * 5_000 / 10_000
    Burn     : forfeited - appellant_award + clawback_shortfall
    Penalise : reporter slashed (InvalidBlock base) for filing false evidence

On appeal LOSS:
    Forfeit  : appellant bond
    Award    : reporter_award = forfeited * 5_000 / 10_000
    Burn     : forfeited - reporter_award
    Slash persists; further appeals accepted up to MAX_APPEAL_ATTEMPTS_PER_SLASH.

On window EXPIRY (no winning appeal):
    Status -> Finalised
    Correlation penalty applied
    Exit lock starts (SLASH_LOCK_EPOCHS)
    Reporter bond returned in full
```

## 5. Evidence Verification

### 5.1 Dispatcher

```rust
pub fn verify_evidence(
    evidence: &SlashingEvidence,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
    current_epoch: u64,
) -> Result<VerifiedEvidence, SlashingError>;
```

Preconditions before dispatch:

1. `evidence.epoch + SLASH_LOOKBACK_EPOCHS >= current_epoch` — else `OffenseTooOld`.
2. `evidence.reporter_validator_index` is live and active — else `ReporterNotRegistered`.
3. `evidence.reporter_validator_index` ∉ `evidence.slashable_validators()` — else `ReporterIsAccused`.

Then dispatch per payload.

### 5.2 Proposer Slashing

1. `signed_header_a.message.slot == signed_header_b.message.slot`.
2. `signed_header_a.message.proposer_index == signed_header_b.message.proposer_index`.
3. `signed_header_a.message.hash() != signed_header_b.message.hash()`.
4. Both signatures parse (96 bytes G2).
5. Accused validator exists, is not already slashed, is active at `header.epoch`.
6. Both sigs verify via `chia_bls::verify(sig, pk, block_signing_message(network_id, header.epoch, &header.hash(), header.proposer_index))`.

### 5.3 Attester Slashing

1. Both `IndexedAttestation::validate_structure()` succeed (ascending indices, no dup, len in [1, `MAX_VALIDATORS_PER_COMMITTEE`], sig 96 bytes).
2. `attestation_a != attestation_b`.
3. **Double-vote** OR **surround-vote** predicate holds.
4. Both `IndexedAttestation::verify_signature` succeed via `chia_bls::aggregate_verify`.
5. `slashable_indices = a.attesting_indices ∩ b.attesting_indices` non-empty.
6. Every slashable index is a live validator, not already slashed.

### 5.4 Invalid-Block

1. Signature verifies over `block_signing_message(...)`.
2. `header.epoch == evidence.epoch`.
3. `header.proposer_index` identifies a live validator.
4. `failure_witness.len()` ∈ `[1, MAX_SLASH_PROPOSAL_PAYLOAD_BYTES]`.
5. Optional `InvalidBlockOracle::verify_failure(header, witness, reason)` — if oracle is supplied, it must return `Ok`. Bootstrap path: no oracle required; caller defers to the challenge window for correctness.

### 5.5 Mempool-Admission Verification

```rust
pub fn verify_evidence_for_inclusion(
    evidence: &SlashingEvidence,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
    current_epoch: u64,
) -> Result<VerifiedEvidence, SlashingError>;
```

Identical to §5.1 minus state mutation; called by mempool + block-admission pipelines.

## 6. Appeal Verification

### 6.1 Dispatcher

```rust
pub fn verify_appeal(
    appeal: &SlashAppeal,
    pending: &PendingSlash,
    validator_view: &dyn ValidatorView,
    network_id: &Bytes32,
    current_epoch: u64,
    justification: &dyn JustificationView,
    invalid_block_oracle: Option<&dyn InvalidBlockOracle>,
) -> Result<AppealVerdict, AppealError>;
```

Preconditions (any failure → `AppealError`):

1. `appeal.evidence_hash == pending.evidence_hash`.
2. `pending.status ∈ { Accepted, ChallengeOpen }` — not `Reverted` / `Finalised`.
3. `pending.submitted_at_epoch <= appeal.filed_epoch <= pending.window_expires_at_epoch`.
4. `appeal.filed_epoch <= current_epoch`.
5. Appellant is a live, active validator.
6. `appeal.payload` variant matches `pending.evidence.payload` variant.
7. Serialized payload ≤ `MAX_APPEAL_PAYLOAD_BYTES`.
8. Not a byte-duplicate of any prior `AppealAttempt`.
9. `pending.appeal_history.len() < MAX_APPEAL_ATTEMPTS_PER_SLASH`.

### 6.2 Proposer Appeal Grounds

Per `ProposerAppealGround`:

- **HeadersIdentical** — assert `signed_header_a.message == signed_header_b.message` bytewise. Sustained iff true.
- **ProposerIndexMismatch** — `header_a.proposer_index != header_b.proposer_index`. Sustained iff true.
- **SignatureAInvalid** — BLS verify of sig_a over `block_signing_message`. Sustained iff verify returns false.
- **SignatureBInvalid** — same for sig_b.
- **SlotMismatch** — `header_a.slot != header_b.slot`. Sustained iff true.
- **ValidatorNotActiveAtEpoch** — `validator.is_active_at_epoch(header.epoch)` is false. Witness carries `ActivationRange { activation_epoch, exit_epoch }` + proof root; verifier consults `validator_view`. Sustained iff not active.

### 6.3 Attester Appeal Grounds

- **AttestationsIdentical** — byte-equal.
- **NotSlashableByPredicate** — neither double-vote nor surround-vote predicate holds.
- **EmptyIntersection** — intersection empty.
- **SignatureAInvalid / SignatureBInvalid** — aggregate verify fails.
- **InvalidIndexedAttestationStructure** — `validate_structure` errors on either side.
- **ValidatorNotInIntersection { validator_index }** — specified index not in intersection.

### 6.4 Invalid-Block Appeal Grounds

- **BlockActuallyValid** — requires `InvalidBlockOracle`. Witness carries block body + pre-state + parent witness. Oracle `re_execute` returns `ExecutionOutcome::Valid`. Sustained iff so. Without oracle: `MissingOracle` error (cannot adjudicate).
- **ProposerSignatureInvalid** — BLS verify over `block_signing_message` returns false.
- **FailureReasonMismatch** — oracle `re_execute` returns `Invalid(actual_reason)` where `actual_reason != evidence.failure_reason`.
- **EvidenceEpochMismatch** — `header.epoch != evidence.epoch`.

### 6.5 Adjudicator

```rust
pub struct AppealAdjudicator;

impl AppealAdjudicator {
    pub fn adjudicate(
        &mut self,
        appeal: &SlashAppeal,
        verdict: &AppealVerdict,
        pending: &mut PendingSlash,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        collateral: Option<&mut dyn CollateralSlasher>,
        bond_escrow: &mut dyn BondEscrow,
        reward_payout: &mut dyn RewardPayout,
        reward_clawback: &mut dyn RewardClawback,
        current_epoch: u64,
    ) -> AppealAdjudicationResult;
}
```

On **Sustained**:

1. For each `PerValidatorSlash` in `pending.base_slash_per_validator`:
   - `validator.credit_stake(base_slash_amount)`.
   - If collateral present: `collateral.credit(idx, collateral_slashed)`.
   - `validator.restore_status()`.
2. `reward_clawback.claw_back(reporter_ph, wb_reward)` and `claw_back(proposer_ph, prop_reward)`.
3. `shortfall = (wb_reward + prop_reward) - total_clawed_back`.
4. `bond_escrow.forfeit(reporter_idx, REPORTER_BOND_MOJOS, BondTag::Reporter(evidence_hash))` → forfeited.
5. `appellant_award = forfeited * BOND_AWARD_TO_WINNER_BPS / BPS_DENOMINATOR`.
6. `burn = forfeited - appellant_award + shortfall`. (Shortfall absorbed by burning from forfeited bond; no protocol debt unless shortfall > forfeited, which is flagged in telemetry.)
7. `reward_payout.pay(appellant_ph, appellant_award)`.
8. Reporter penalty: `base = max(eff_bal * INVALID_BLOCK_BASE_BPS / 10_000, eff_bal / 32)`. `validator.slash_absolute(base, current_epoch)`. Record into `slashed_in_window`.
9. `pending.status = Reverted { winning_appeal_hash, reverted_at_epoch: current_epoch }`.
10. Append `AppealAttempt { outcome: Won }`.

On **Rejected**:

1. `bond_escrow.forfeit(appellant_idx, APPELLANT_BOND_MOJOS, BondTag::Appellant(appeal_hash))` → forfeited.
2. `reporter_award = forfeited * BOND_AWARD_TO_WINNER_BPS / BPS_DENOMINATOR`.
3. `burn = forfeited - reporter_award`.
4. `reward_payout.pay(reporter_ph, reporter_award)`.
5. `pending.status = ChallengeOpen { first_appeal_filed_epoch: min(existing, filed), appeal_count: n + 1 }`.
6. Append `AppealAttempt { outcome: Lost { reason_hash } }`.

## 7. Slashing State Machine

### 7.1 PendingSlashBook

```rust
pub struct PendingSlashBook {
    pending: HashMap<Bytes32, PendingSlash>,
    by_window_expiry: BTreeMap<u64, Vec<Bytes32>>,
    capacity: usize,
}

impl PendingSlashBook {
    pub fn new(capacity: usize) -> Self;
    pub fn insert(&mut self, record: PendingSlash) -> Result<(), SlashingError>;
    pub fn get(&self, h: &Bytes32) -> Option<&PendingSlash>;
    pub fn get_mut(&mut self, h: &Bytes32) -> Option<&mut PendingSlash>;
    pub fn remove(&mut self, h: &Bytes32) -> Option<PendingSlash>;
    pub fn expired_by(&self, current_epoch: u64) -> Vec<Bytes32>;
    pub fn len(&self) -> usize;
}
```

### 7.2 SlashingManager

```rust
pub struct SlashingManager {
    book: PendingSlashBook,
    processed: HashMap<Bytes32, u64>,
    slashed_in_window: BTreeMap<(u64, u32), u64>,  // (epoch, idx) → eff_bal_at_slash
    current_epoch: u64,
}

impl SlashingManager {
    /// Genesis initialisation: empty book, empty processed, empty window, epoch=0.
    pub fn new(current_epoch: u64) -> Self;

    pub fn set_epoch(&mut self, epoch: u64);

    pub fn submit_evidence(
        &mut self,
        evidence: SlashingEvidence,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        collateral: Option<&mut dyn CollateralSlasher>,
        bond_escrow: &mut dyn BondEscrow,
        reward_payout: &mut dyn RewardPayout,
        proposer: &dyn ProposerView,
        network_id: &Bytes32,
    ) -> Result<SlashingResult, SlashingError>;

    pub fn submit_appeal(
        &mut self,
        appeal: SlashAppeal,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        collateral: Option<&mut dyn CollateralSlasher>,
        bond_escrow: &mut dyn BondEscrow,
        reward_payout: &mut dyn RewardPayout,
        reward_clawback: &mut dyn RewardClawback,
        network_id: &Bytes32,
        justification: &dyn JustificationView,
        invalid_block_oracle: Option<&dyn InvalidBlockOracle>,
    ) -> Result<AppealAdjudicationResult, AppealError>;

    /// Called once at each epoch boundary, AFTER participation rotation and
    /// BEFORE new-epoch block production. Transitions all expired PendingSlashes
    /// to Finalised; applies correlation penalty; returns reporter bonds;
    /// starts exit locks.
    pub fn finalise_expired_slashes(
        &mut self,
        validator_set: &mut dyn ValidatorView,
        effective_balances: &dyn EffectiveBalanceView,
        bond_escrow: &mut dyn BondEscrow,
        reward_payout: &mut dyn RewardPayout,
        total_active_balance: u64,
    ) -> Vec<FinalisationResult>;

    pub fn is_slashed(&self, idx: u32, vs: &dyn ValidatorView) -> bool;
    pub fn is_processed(&self, h: &Bytes32) -> bool;
    pub fn pending(&self, h: &Bytes32) -> Option<&PendingSlash>;
    pub fn prune(&mut self, before_epoch: u64);

    /// Reorg: roll back all pending slashes submitted at epochs > new_tip_epoch.
    /// Caller (consensus) handles restoring validator stake via the same path
    /// as a Sustained appeal (minus reporter penalty).
    pub fn rewind_on_reorg(
        &mut self,
        new_tip_epoch: u64,
        validator_set: &mut dyn ValidatorView,
        collateral: Option<&mut dyn CollateralSlasher>,
        bond_escrow: &mut dyn BondEscrow,
    ) -> Vec<Bytes32>;
}
```

### 7.3 submit_evidence Pipeline

1. `hash = evidence.hash()`. If in `processed` → `AlreadySlashed`.
2. `verified = verify_evidence(...)`.
3. Book at capacity? → `PendingBookFull`.
4. `bond_escrow.lock(reporter_idx, REPORTER_BOND_MOJOS, BondTag::Reporter(hash))`. If fails → `BondLockFailed`.
5. For each `idx` in `verified.slashable_validator_indices`:
   - Skip if validator missing or already slashed.
   - `eff_bal = effective_balances.get(idx)`.
   - `base_slash = max(eff_bal * base_bps / 10_000, eff_bal / 32)`.
   - `validator.slash_absolute(base_slash, current_epoch)`.
   - If collateral present: `collateral.slash(idx, base_slash, current_epoch)` → `coll_slashed`.
   - `slashed_in_window.insert((current_epoch, idx), eff_bal)`.
   - Push `PerValidatorSlash { base_slash_amount, collateral_slashed: coll_slashed, effective_balance_at_slash: eff_bal }`.
6. `total_base = Σ base_slash`. `total_eff = Σ eff_bal`.
7. `wb_reward = total_eff / WHISTLEBLOWER_REWARD_QUOTIENT`.
8. `prop_reward = wb_reward / PROPOSER_REWARD_QUOTIENT`.
9. `burn = total_base - wb_reward - prop_reward`.
10. `reward_payout.pay(reporter_puzzle_hash, wb_reward)`.
11. `block_proposer_idx = proposer.proposer_at_slot(current_slot)?`. `block_proposer_ph = validator_set.get(block_proposer_idx).puzzle_hash()`. `reward_payout.pay(block_proposer_ph, prop_reward)`.
12. `book.insert(PendingSlash { status: Accepted, submitted_at_epoch, window_expires_at_epoch: current_epoch + 8, ... })`.
13. `processed.insert(hash, current_epoch)`.
14. Return `SlashingResult`.

### 7.4 finalise_expired_slashes Pipeline

For each expired `evidence_hash` in `book.expired_by(current_epoch)`:

1. `pending = book.get_mut(hash)`.
2. If `pending.status == Reverted` or `Finalised` → skip (defensive).
3. Compute `cohort_sum = Σ eff_bal over slashed_in_window entries in [current_epoch - CORRELATION_WINDOW_EPOCHS, current_epoch]`.
4. For each `idx` in `pending.base_slash_per_validator`:
   - `eff_bal = effective_balances.get(idx)`.
   - `corr = eff_bal * min(cohort_sum * 3, total_active_balance) / total_active_balance`.
   - `validator.slash_absolute(corr, current_epoch)`.
   - Set `exit_eligible_epoch = current_epoch + SLASH_LOCK_EPOCHS` (handled by validator_set via `schedule_exit`).
5. `bond_escrow.release(reporter_idx, REPORTER_BOND_MOJOS, BondTag::Reporter(hash))` → return in full.
6. `pending.status = Finalised { finalised_at_epoch: current_epoch }`.
7. Emit `FinalisationResult`.

## 8. Attestation Participation & Rewards

### 8.1 Timeliness Classification

```rust
/// Given an attestation included at `inclusion_slot`, classify timeliness
/// against the canonical fork-choice view.
pub fn classify_timeliness(
    data: &AttestationData,
    inclusion_slot: u64,
    source_is_justified: bool,
    target_is_canonical: bool,
    head_is_canonical: bool,
) -> ParticipationFlags;
```

Rules:

- `delay = inclusion_slot - data.slot`.
- `TIMELY_SOURCE` set iff `delay ∈ [1, 5] && source_is_justified`.
- `TIMELY_TARGET` set iff `delay ∈ [1, 32] && target_is_canonical`.
- `TIMELY_HEAD` set iff `delay == 1 && head_is_canonical`.

### 8.2 ParticipationTracker

```rust
pub struct ParticipationTracker {
    previous_epoch: Vec<ParticipationFlags>,
    current_epoch:  Vec<ParticipationFlags>,
    current_epoch_number: u64,
}

impl ParticipationTracker {
    pub fn new(validator_count: usize, current_epoch: u64) -> Self;

    pub fn record_attestation(
        &mut self,
        data: &AttestationData,
        attesting_indices: &[u32],
        flags_for_all: ParticipationFlags,
    ) -> Result<(), ParticipationError>;

    pub fn rotate_epoch(&mut self, new_epoch: u64, validator_count: usize);

    pub fn previous_epoch_flags(&self, idx: u32) -> ParticipationFlags;
    pub fn current_epoch_flags(&self, idx: u32) -> ParticipationFlags;
    pub fn previous_epoch_all(&self) -> &[ParticipationFlags];

    /// Reorg: drop the last `depth` epochs of recorded flags.
    pub fn rewind_on_reorg(&mut self, depth: u64, validator_count: usize);
}
```

`record_attestation` validates `attesting_indices` (ascending, no dup, in range) then sets `flags_for_all` into `current_epoch[idx]` for each attester.

### 8.3 Base Reward + Flag Deltas

```rust
pub fn base_reward(effective_balance: u64, total_active_balance: u64) -> u64;

pub fn compute_flag_deltas(
    previous_epoch_participation: &[ParticipationFlags],
    effective_balances: &dyn EffectiveBalanceView,
    total_active_balance: u64,
    in_finality_stall: bool,
) -> Vec<FlagDelta>;
```

Per validator:

```
base  = base_reward(eff_bal, total_active_balance)
src_w = base * 14 / 64
tgt_w = base * 26 / 64
hd_w  = base * 14 / 64

if TIMELY_SOURCE set: reward += src_w else penalty += src_w
if TIMELY_TARGET set: reward += tgt_w else penalty += tgt_w
if TIMELY_HEAD   set: reward += hd_w  // head miss: no penalty

if in_finality_stall:
    reward = 0
```

Deltas are not automatically debited/credited — the caller (consensus) applies them to validator balances.

### 8.4 Proposer Inclusion Reward

```rust
pub fn proposer_inclusion_reward(attester_base_reward: u64) -> u64 {
    attester_base_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT)
    // = base * 8 / 56
}
```

Accumulated by the consensus layer and routed to the proposer of the first block that includes a given attestation.

## 9. Inactivity Accounting (Continuous)

### 9.1 Finality-Stall Detection

```rust
pub fn in_finality_stall(current_epoch: u64, finalized_epoch: u64) -> bool {
    current_epoch.saturating_sub(finalized_epoch) > MIN_EPOCHS_TO_INACTIVITY_PENALTY
}
```

### 9.2 Score Update

```rust
impl InactivityScoreTracker {
    pub fn new(validator_count: usize) -> Self;
    pub fn resize_for(&mut self, validator_count: usize);
    pub fn score(&self, idx: u32) -> u64;

    pub fn update_for_epoch(
        &mut self,
        previous_epoch_participation: &[ParticipationFlags],
        in_finality_stall: bool,
    ) {
        for (i, flags) in previous_epoch_participation.iter().enumerate() {
            let s = &mut self.scores[i];
            if flags.is_target_timely() {
                *s = s.saturating_sub(1);
            } else if in_finality_stall {
                *s = s.saturating_add(INACTIVITY_SCORE_BIAS);
            }
        }
        if !in_finality_stall {
            for s in &mut self.scores { *s = s.saturating_sub(INACTIVITY_SCORE_RECOVERY_RATE); }
        }
    }

    pub fn epoch_penalties(
        &self,
        effective_balances: &dyn EffectiveBalanceView,
        in_finality_stall: bool,
    ) -> Vec<(u32, u64)>;

    /// Reorg: drop `depth` epochs of score accumulation. Implemented as a
    /// shadow buffer of prior scores; rewind restores the snapshot.
    pub fn rewind_on_reorg(&mut self, depth: u64);
}
```

### 9.3 Per-Epoch Penalty

```
penalty = eff_bal * score / INACTIVITY_PENALTY_QUOTIENT   (only when in stall)
```

Non-zero penalties returned as `Vec<(validator_index, mojos)>`; consensus applies them to validator balances.

## 10. Epoch Boundary Orchestration

Consensus calls this sequence exactly once per epoch transition from `N` to `N+1`. Ordering is fixed and deterministic.

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

**Ordering:**

1. **Compute flag deltas** over `participation.previous_epoch_all()` with `in_finality_stall = in_finality_stall(current_epoch_ending, justification.finalized_checkpoint().epoch)`.
   → returned in `EpochBoundaryReport::flag_deltas` for consensus to apply.
2. **Update inactivity scores** over the same previous-epoch flags.
3. **Compute inactivity penalties** for the ending epoch (non-zero only if in stall).
   → returned in `EpochBoundaryReport::inactivity_penalties`.
4. **Finalise expired slashes** via `manager.finalise_expired_slashes(...)` (correlation penalty + reporter bond return + exit lock).
   → returned in `EpochBoundaryReport::finalisations`.
5. **Rotate participation tracker** to `current_epoch_ending + 1` with `validator_count`.
6. **Advance manager epoch** via `manager.set_epoch(current_epoch_ending + 1)`.
7. **Resize trackers** if `validator_count` changed (new activations).
8. **Prune old processed evidence and correlation-window entries** via `manager.prune(current_epoch_ending.saturating_sub(SLASH_LOOKBACK_EPOCHS + 1))`.

```rust
pub struct EpochBoundaryReport {
    pub flag_deltas: Vec<FlagDelta>,
    pub inactivity_penalties: Vec<(u32, u64)>,
    pub finalisations: Vec<FinalisationResult>,
    pub in_finality_stall: bool,
}
```

## 11. Genesis & Initialisation

```rust
pub struct GenesisParameters {
    pub genesis_epoch: u64,               // typically 0
    pub initial_validator_count: usize,
    pub network_id: Bytes32,
}

pub struct SlashingSystem {
    pub manager: SlashingManager,
    pub participation: ParticipationTracker,
    pub inactivity: InactivityScoreTracker,
}

impl SlashingSystem {
    pub fn genesis(params: &GenesisParameters) -> Self {
        Self {
            manager: SlashingManager::new(params.genesis_epoch),
            participation: ParticipationTracker::new(params.initial_validator_count, params.genesis_epoch),
            inactivity: InactivityScoreTracker::new(params.initial_validator_count),
        }
    }
}
```

At genesis:

- `processed` is empty; no evidence has been seen.
- `PendingSlashBook` is empty.
- `slashed_in_window` is empty.
- All validators have `ParticipationFlags(0)` for both previous and current epoch.
- All inactivity scores are 0.
- `in_finality_stall` returns false at `(0, 0)`.

## 12. Reward Routing & Bond Escrow

### 12.1 RewardPayout

```rust
pub trait RewardPayout {
    /// Create (or credit) a pay-to-puzzle-hash account for `principal_ph`
    /// with `amount_mojos`. Implementations (in consensus layer) create
    /// a reward coin or credit an existing account.
    fn pay(&mut self, principal_ph: Bytes32, amount_mojos: u64);
}
```

Paid principals:
- Reporter puzzle hash → `wb_reward` on evidence inclusion.
- Block-proposer puzzle hash → `prop_reward` on evidence inclusion.
- Appellant puzzle hash → `appellant_award` on sustained appeal.
- Reporter puzzle hash → `reporter_award` on rejected appeal.

### 12.2 RewardClawback

```rust
pub trait RewardClawback {
    /// Deduct up to `amount` from `principal_ph`'s reward account.
    /// Returns amount actually clawed back (may be < `amount` if already withdrawn).
    fn claw_back(&mut self, principal_ph: Bytes32, amount: u64) -> u64;
}
```

Called on sustained appeal to reverse the optimistic `wb_reward` + `prop_reward`. Shortfall is absorbed by the forfeited reporter bond; residue (if any) is burned and flagged.

### 12.3 BondEscrow

```rust
pub trait BondEscrow {
    fn lock(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError>;
    fn release(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<(), BondError>;
    fn forfeit(&mut self, principal_idx: u32, amount: u64, tag: BondTag) -> Result<u64, BondError>;
    fn escrowed(&self, principal_idx: u32, tag: BondTag) -> u64;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum BondTag {
    Reporter(Bytes32),   // evidence_hash
    Appellant(Bytes32),  // appeal_hash
}
```

Implementation (in `dig-collateral` or dedicated crate) holds escrowed mojos against the validator's stake. If `lock` is called while `stake_after_base_slash < amount`, it returns `InsufficientBalance`. For evidence admission this means the reporter must have enough stake to cover the bond; for appeals, the appellant must have enough.

## 13. Reorg Handling

A fork-choice reorg invalidates previously-recorded participation flags, pending slashes, and inactivity-score updates that happened on the replaced branch.

```rust
pub fn rewind_all_on_reorg(
    manager: &mut SlashingManager,
    participation: &mut ParticipationTracker,
    inactivity: &mut InactivityScoreTracker,
    protection: &mut SlashingProtection,
    validator_set: &mut dyn ValidatorView,
    collateral: Option<&mut dyn CollateralSlasher>,
    bond_escrow: &mut dyn BondEscrow,
    new_tip_epoch: u64,
    new_tip_slot: u64,
    validator_count: usize,
) -> ReorgReport;
```

Sequence:

1. `manager.rewind_on_reorg(new_tip_epoch, ...)` — pending slashes submitted at epochs > `new_tip_epoch` are dropped. For each: credit back base slash (like Sustained appeal, no reporter penalty), release reporter bond in full, remove from `processed` and `slashed_in_window`.
2. `participation.rewind_on_reorg(current_epoch - new_tip_epoch, validator_count)` — drop epochs > `new_tip_epoch`.
3. `inactivity.rewind_on_reorg(current_epoch - new_tip_epoch)` — restore prior score snapshot.
4. `protection.reconcile_with_chain_tip(new_tip_slot, new_tip_epoch)` — validator-local watermarks rewound.

```rust
pub struct ReorgReport {
    pub rewound_pending_slashes: Vec<Bytes32>,
    pub participation_epochs_dropped: u64,
    pub inactivity_epochs_dropped: u64,
    pub protection_rewound: bool,
}
```

**Snapshot retention:** Both `ParticipationTracker` and `InactivityScoreTracker` maintain a ring buffer of prior-epoch states of depth `CORRELATION_WINDOW_EPOCHS`. Reorgs deeper than that are a protocol-level failure; `ReorgTooDeep` error returned.

## 14. Slashing Protection (Validator-Local)

(As v0.3. Summary:)

- JSON watermarks on disk.
- `check_proposal_slot(slot) -> bool`: slot > `last_proposed_slot`.
- `check_attestation(source, target, hash) -> bool`: strictly monotone target; source not earlier than `last_attested_source_epoch`; surround-vote self-check; same (source, target) → same hash.
- `would_surround(source, target) -> bool`.
- `record_proposal(slot)`, `record_attestation(source, target, hash)`.
- `rewind_proposal_to_slot`, `rewind_attestation_to_epoch`, `reconcile_with_chain_tip`.
- Legacy JSON (no hash field) loads with `None`.

## 15. Traits

### 15.1 ValidatorView + ValidatorEntry

```rust
pub trait ValidatorView {
    fn get(&self, index: u32) -> Option<&dyn ValidatorEntry>;
    fn get_mut(&mut self, index: u32) -> Option<&mut dyn ValidatorEntry>;
    fn len(&self) -> usize;
}

pub trait ValidatorEntry {
    fn public_key(&self) -> &PublicKey;
    fn puzzle_hash(&self) -> Bytes32;
    fn effective_balance(&self) -> u64;
    fn is_slashed(&self) -> bool;
    fn activation_epoch(&self) -> u64;
    fn exit_epoch(&self) -> u64;
    fn is_active_at_epoch(&self, epoch: u64) -> bool;

    /// Canonical slashing API: debit by absolute mojos.
    fn slash_absolute(&mut self, amount_mojos: u64, epoch: u64) -> u64;

    /// Undo a prior slash_absolute on sustained appeal or reorg.
    fn credit_stake(&mut self, amount_mojos: u64) -> u64;

    /// Clear Slashed; restore Active. Returns true if status changed.
    fn restore_status(&mut self) -> bool;

    /// Schedule the exit lock after a finalised slash.
    fn schedule_exit(&mut self, exit_lock_until_epoch: u64);
}
```

### 15.2 EffectiveBalanceView, PublicKeyLookup, CollateralSlasher

```rust
pub trait EffectiveBalanceView {
    fn get(&self, index: u32) -> u64;
    fn total_active(&self) -> u64;
}

pub trait PublicKeyLookup {
    fn pubkey_of(&self, index: u32) -> Option<&PublicKey>;
}

pub trait CollateralSlasher {
    fn slash(&mut self, idx: u32, amount: u64, epoch: u64) -> Result<(u64, u64), CollateralError>;
    fn credit(&mut self, idx: u32, amount: u64) -> Result<u64, CollateralError>;
}
```

### 15.3 Fork-Choice & Block Oracles

```rust
pub trait JustificationView {
    fn current_justified_checkpoint(&self) -> Checkpoint;
    fn previous_justified_checkpoint(&self) -> Checkpoint;
    fn finalized_checkpoint(&self) -> Checkpoint;
    fn canonical_block_root_at_slot(&self, slot: u64) -> Option<Bytes32>;
    fn canonical_target_root_for_epoch(&self, epoch: u64) -> Option<Bytes32>;
}

pub trait ProposerView {
    fn proposer_at_slot(&self, slot: u64) -> Option<u32>;
    fn current_slot(&self) -> u64;
}

pub trait InvalidBlockOracle {
    fn verify_failure(
        &self, header: &L2BlockHeader, witness: &[u8], reason: InvalidBlockReason,
    ) -> Result<(), SlashingError> { Ok(()) }
    fn re_execute(
        &self, header: &L2BlockHeader, witness: &[u8],
    ) -> Result<ExecutionOutcome, SlashingError>;
}

pub enum ExecutionOutcome {
    Valid,
    Invalid(InvalidBlockReason),
}
```

### 15.4 Bonds + Rewards

(See §12.)

## 16. REMARK Admission

### 16.1 Evidence REMARK

```
wire = SLASH_EVIDENCE_REMARK_MAGIC_V1 || serde_json(SlashingEvidence)
```

APIs: `encode_slashing_evidence_remark_payload_v1`, `slashing_evidence_remark_puzzle_reveal_v1`, `slashing_evidence_remark_puzzle_hash_v1`, `build_slashing_evidence_remark_spend_bundle`, `parse_slashing_evidence_from_conditions`, `enforce_slashing_evidence_remark_admission`, `enforce_slashing_evidence_mempool_policy`, `enforce_block_level_slashing_caps`.

Rejections: `OutsideLookback`, `DuplicateEvidence`, `BlockCapExceeded`, `PayloadTooLarge`, `AdmissionPuzzleHashMismatch`.

### 16.2 Appeal REMARK

```
wire = SLASH_APPEAL_REMARK_MAGIC_V1 || serde_json(SlashAppeal)
```

APIs: `encode_slash_appeal_remark_payload_v1`, `slash_appeal_remark_puzzle_reveal_v1`, `slash_appeal_remark_puzzle_hash_v1`, `build_slash_appeal_remark_spend_bundle`, `parse_slash_appeals_from_conditions`, `enforce_slash_appeal_remark_admission`, `enforce_slash_appeal_mempool_policy`, `enforce_block_level_appeal_caps`.

Appeal-specific rejections: `AppealForUnknownSlash`, `AppealWindowExpired`, `AppealForFinalisedSlash`, `AppealVariantMismatch`, `DuplicateAppeal`, `AppealPayloadTooLarge`.

### 16.3 Spend Signature

Both REMARK bundles spend a coin owned by the reporter (evidence) or appellant (appeal). The spend is signed via the principal's BLS key; the `aggregated_signature` field on the bundle carries that signature. `BondEscrow.lock` is called in a separate spend emitted by the consensus layer on admission.

## 17. Error Types

### 17.1 SlashingError

```rust
#[derive(Debug, thiserror::Error)]
pub enum SlashingError {
    #[error("evidence already processed")] AlreadySlashed,
    #[error("offense epoch {offense_epoch} older than lookback (current {current_epoch})")]
    OffenseTooOld { offense_epoch: u64, current_epoch: u64 },
    #[error("validator not registered: {0}")] ValidatorNotRegistered(u32),
    #[error("reporter not registered: {0}")] ReporterNotRegistered(u32),
    #[error("reporter cannot accuse self (index {0})")] ReporterIsAccused(u32),
    #[error("invalid proposer slashing: {0}")] InvalidProposerSlashing(String),
    #[error("invalid attester slashing: {0}")] InvalidAttesterSlashing(String),
    #[error("invalid indexed attestation: {0}")] InvalidIndexedAttestation(String),
    #[error("attestations do not prove a slashable offense")] AttesterSlashingNotSlashable,
    #[error("attester slashing intersecting indices empty")] EmptySlashableIntersection,
    #[error("invalid block evidence: {0}")] InvalidSlashingEvidence(String),
    #[error("BLS signature verification failed")] BlsVerifyFailed,
    #[error("pending slash book at capacity ({0})")] PendingBookFull(usize),
    #[error("bond lock failed: {0}")] BondLockFailed(String),
    #[error("reorg deeper than retention window")] ReorgTooDeep,
}
```

### 17.2 AppealError

```rust
#[derive(Debug, thiserror::Error)]
pub enum AppealError {
    #[error("unknown evidence hash 0x{0}")] UnknownEvidence(String),
    #[error("appeal window expired (submitted {submitted_at}, window {window}, current {current})")]
    WindowExpired { submitted_at: u64, window: u64, current: u64 },
    #[error("slash already reverted")] SlashAlreadyReverted,
    #[error("slash already finalised")] SlashAlreadyFinalised,
    #[error("appeal variant does not match evidence variant")] VariantMismatch,
    #[error("appeal payload too large: {actual} > {limit}")] PayloadTooLarge { actual: usize, limit: usize },
    #[error("appeal is a byte-duplicate of a prior attempt")] DuplicateAppeal,
    #[error("appeal attempts exceeded ({count} >= {limit})")] TooManyAttempts { count: usize, limit: usize },
    #[error("appellant validator not registered: {0}")] AppellantNotRegistered(u32),
    #[error("appellant bond lock failed: {0}")] AppellantBondLockFailed(String),
    #[error("missing oracle: {0}")] MissingOracle(&'static str),
    #[error("malformed witness: {0}")] MalformedWitness(String),
    #[error("verifier error: {0}")] VerifierError(String),
}
```

### 17.3 BondError, ParticipationError, SlashingRemarkError

```rust
#[derive(Debug, thiserror::Error)]
pub enum BondError {
    #[error("insufficient balance to lock bond: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("bond tag {tag:?} not found")] TagNotFound { tag: BondTag },
    #[error("bond tag {tag:?} already locked")] DoubleLock { tag: BondTag },
}

#[derive(Debug, thiserror::Error)]
pub enum ParticipationError {
    #[error("index {0} out of range")] IndexOutOfRange(u32),
    #[error("attestation slot {slot} outside current epoch {epoch}")]
    SlotOutsideEpoch { slot: u64, epoch: u64 },
    #[error("attesting indices not strictly ascending")] NonAscendingIndices,
    #[error("duplicate attester index {0}")] DuplicateIndex(u32),
}

#[derive(Debug, thiserror::Error)]
pub enum SlashingRemarkError {
    #[error("payload encode failed: {0}")] Encode(String),
    #[error("spend assembly failed: {0}")] Spend(#[from] SpendError),
    #[error("REMARK puzzle_hash mismatch: got 0x{got}, expected 0x{expected}")]
    AdmissionPuzzleHashMismatch { got: String, expected: String },
    #[error("outside lookback: epoch {epoch}, current {current_epoch}")]
    OutsideLookback { epoch: u64, current_epoch: u64 },
    #[error("duplicate evidence or appeal")] DuplicateEvidence,
    #[error("block cap exceeded: {actual} > {limit}")] BlockCapExceeded { actual: usize, limit: usize },
    #[error("payload too large: {actual} > {limit}")] PayloadTooLarge { actual: usize, limit: usize },
    #[error("appeal for unknown slash 0x{0}")] AppealForUnknownSlash(String),
    #[error("appeal window expired for slash 0x{0}")] AppealWindowExpired(String),
    #[error("appeal for finalised slash 0x{0}")] AppealForFinalisedSlash(String),
    #[error("appeal variant does not match evidence variant")] AppealVariantMismatch,
}
```

## 18. Serialization

| Type | `serde` | `bincode` | JSON wire |
|------|---------|-----------|-----------|
| Offense / evidence / attestation types | Yes | Yes | Yes |
| `SlashingEvidence` / payload enum | Yes | Yes | Yes (REMARK) |
| `SlashAppeal` / payload enum | Yes | Yes | Yes (REMARK) |
| `AppealVerdict` / `AppealAdjudicationResult` | Yes | Yes | No |
| `PendingSlash` / `PendingSlashStatus` / `AppealAttempt` | Yes | Yes | No |
| `SlashingResult` / `PerValidatorSlash` / `FinalisationResult` / `FlagDelta` / `EpochBoundaryReport` / `ReorgReport` | Yes | Yes | No |
| `ParticipationFlags` | Yes | Yes | Yes |
| `SlashingProtection` | Yes | No | Yes (disk) |

Conventions: LE integers, `serde_bytes` for BLS fields, frozen `_V1` prefixes, SHA-256 exclusively, `chia_bls` exclusively.

## 19. Public API Summary

### 19.1 Constants

All of §2 re-exported from `lib.rs`.

### 19.2 Evidence

```rust
ProposerSlashing, AttesterSlashing, InvalidBlockProof — constructors + hash + helpers
SlashingEvidence::proposer / ::attester / ::invalid_block
SlashingEvidence::hash / ::slashable_validators
verify_evidence(..) -> Result<VerifiedEvidence, SlashingError>
verify_evidence_for_inclusion(..) -> Result<VerifiedEvidence, SlashingError>
IndexedAttestation::validate_structure / ::verify_signature
AttestationData::signing_root
```

### 19.3 Appeals

```rust
ProposerSlashingAppeal::new / AttesterSlashingAppeal::new / InvalidBlockAppeal::new
SlashAppeal::new / ::hash
verify_appeal(..) -> Result<AppealVerdict, AppealError>
AppealAdjudicator::adjudicate(..)
```

### 19.4 Manager

```rust
SlashingManager::new / ::set_epoch
SlashingManager::submit_evidence(..)
SlashingManager::submit_appeal(..)
SlashingManager::finalise_expired_slashes(..)
SlashingManager::rewind_on_reorg(..)
SlashingManager::is_slashed / ::is_processed / ::pending / ::prune
PendingSlashBook::*
```

### 19.5 Participation + Inactivity

```rust
ParticipationFlags::set / ::has
ParticipationTracker::new / ::record_attestation / ::rotate_epoch / ::previous_epoch_flags / ::rewind_on_reorg
classify_timeliness(..)
base_reward(eff_bal, total) / compute_flag_deltas(..) / proposer_inclusion_reward(base)
InactivityScoreTracker::new / ::update_for_epoch / ::epoch_penalties / ::rewind_on_reorg
in_finality_stall(current, finalized)
```

### 19.6 Orchestration + Genesis

```rust
run_epoch_boundary(..) -> EpochBoundaryReport
rewind_all_on_reorg(..) -> ReorgReport
SlashingSystem::genesis(&GenesisParameters)
```

### 19.7 REMARK Admission

Both `*_evidence_*` and `*_appeal_*` families.

### 19.8 Slashing Protection

As §14.

## 20. Directory Structure

```
dig-slashing/
├── Cargo.toml
├── README.md
├── docs/
│   └── resources/
│       └── SPEC.md                          (this file)
├── src/
│   ├── lib.rs                               Crate root; public re-exports.
│   ├── constants.rs                         §2.
│   ├── error.rs                             §17.
│   ├── evidence/
│   │   ├── mod.rs
│   │   ├── offense.rs                       OffenseType.
│   │   ├── checkpoint.rs                    Checkpoint.
│   │   ├── attestation_data.rs              AttestationData + signing_root.
│   │   ├── indexed_attestation.rs           IndexedAttestation + verify/validate.
│   │   ├── proposer_slashing.rs             SignedBlockHeader + ProposerSlashing.
│   │   ├── attester_slashing.rs             AttesterSlashing + predicates.
│   │   ├── invalid_block.rs                 InvalidBlockProof + InvalidBlockReason.
│   │   ├── envelope.rs                      SlashingEvidence + payload + hash.
│   │   └── verify.rs                        §5 verifiers.
│   ├── appeal/
│   │   ├── mod.rs
│   │   ├── proposer.rs                      ProposerSlashingAppeal + grounds.
│   │   ├── attester.rs                      AttesterSlashingAppeal + grounds.
│   │   ├── invalid_block.rs                 InvalidBlockAppeal + grounds.
│   │   ├── envelope.rs                      SlashAppeal + payload + hash.
│   │   ├── verify.rs                        §6 verify_appeal dispatcher + per-ground.
│   │   └── adjudicator.rs                   AppealAdjudicator.
│   ├── manager.rs                           §7 SlashingManager.
│   ├── pending.rs                           PendingSlashBook + PendingSlash + AppealAttempt.
│   ├── lifecycle.rs                         PendingSlashStatus helpers.
│   ├── result.rs                            SlashingResult, PerValidatorSlash,
│   │                                         AppealAdjudicationResult, FinalisationResult,
│   │                                         EpochBoundaryReport, ReorgReport.
│   ├── participation/
│   │   ├── mod.rs
│   │   ├── flags.rs
│   │   ├── tracker.rs
│   │   ├── timeliness.rs
│   │   └── rewards.rs
│   ├── inactivity/
│   │   ├── mod.rs
│   │   ├── score.rs
│   │   └── penalty.rs
│   ├── orchestration.rs                     §10 run_epoch_boundary, §13 rewind_all_on_reorg.
│   ├── system.rs                            §11 SlashingSystem + GenesisParameters.
│   ├── traits.rs                            §15.
│   ├── remark/
│   │   ├── mod.rs
│   │   ├── evidence_wire.rs
│   │   ├── appeal_wire.rs
│   │   ├── parse.rs
│   │   └── policy.rs
│   ├── protection.rs                        §14 SlashingProtection.
│   └── tests/
│       ├── fixtures.rs
│       ├── mock_validator_set.rs
│       ├── mock_effective_balances.rs
│       ├── mock_bond_escrow.rs
│       ├── mock_reward_payout.rs
│       ├── mock_reward_clawback.rs
│       ├── mock_invalid_block_oracle.rs
│       ├── mock_justification.rs
│       └── mock_proposer.rs
├── tests/
│   │  One file per requirement in §22. Naming: `dsl_NNN_<short_name>_test.rs`
│   │  where NNN is the 3-digit requirement ID. See §22 catalogue for full list.
│   │  Every requirement in §22 is traced to exactly one test file here.
│   ├── dsl_001_offense_type_bps_mapping_test.rs
│   ├── dsl_002_evidence_hash_determinism_test.rs
│   │   ... (see §22) ...
│   └── dsl_130_rewind_all_on_reorg_test.rs
└── benches/
    ├── verify_attester_slashing.rs
    ├── verify_attester_appeal.rs
    └── participation_rewards.rs
```

## 21. Crate Boundary

### 21.1 Owned

| Concern | Crates used |
|---------|-------------|
| OffenseType, evidence + attestation types | `chia-protocol`, `serde_bytes` |
| Evidence hash | `chia-sha2` |
| Per-offense verifiers | `chia-bls::verify`, `chia-bls::aggregate_verify`, `dig-block::block_signing_message` |
| Appeal envelopes + 3 payload variants + grounds | — |
| Per-ground appeal verifiers | `chia-bls::verify`, `chia-bls::aggregate_verify` |
| AppealAdjudicator | — |
| SlashingManager + PendingSlashBook | — |
| Reward/bond routing (via traits) | — |
| Epoch-boundary orchestration | — |
| Reorg rewind orchestration | — |
| Genesis / SlashingSystem | — |
| Participation + rewards | `num-integer::Roots::sqrt` |
| Inactivity accounting (continuous) | — |
| Timeliness classification | — |
| Evidence + appeal REMARK wires, puzzles, admission, policy | `serde_json`, `clvm-utils::tree_hash` |
| SlashingProtection | `serde_json`, `hex`, `tracing` |
| Error types (4) | `thiserror` |
| Trait definitions (ValidatorView, EffectiveBalanceView, PublicKeyLookup, CollateralSlasher, BondEscrow, RewardPayout, RewardClawback, JustificationView, ProposerView, InvalidBlockOracle) | `chia-bls::PublicKey` |

### 21.2 Not Owned

| Concern | Owner |
|---------|-------|
| Block format + signing-message helpers | `dig-block` |
| Validator set, stake math, activation/exit queues | `dig-consensus` |
| Effective-balance calculation | `dig-consensus` |
| Collateral manager | `dig-collateral` |
| Bond escrow storage | `dig-collateral` or dedicated crate |
| Reward account storage | `dig-consensus` or reward-distribution crate |
| Fork choice, justification, finalisation, proposer selection | `dig-consensus` |
| Block re-execution engine | `dig-block` / `dig-clvm` |
| Epoch arithmetic | `dig-epoch` |
| Attestation gossip + aggregation + inclusion | `dig-gossip` / `dig-consensus` |
| Network constants | `dig-constants` |
| Mempool pending set | `dig-mempool` |
| CLVM execution | `dig-clvm` (dev-dep only) |
| DFSP / storage-provider slashing | Separate future crate |
| Sync committee + sync-committee slashings | Not in DIG (weight units reserved but unassigned) |

### 21.3 Dependency Direction

```
dig-slashing
    │
    ├──► dig-block, dig-epoch, dig-constants
    ├──► chia-protocol, chia-bls, chia-sha2, chia-sdk-types, clvm-utils
    ├──► num-integer
    ├──► serde, serde_json, serde_bytes, bincode
    ├──► thiserror, hex, tracing
    └──► parking_lot (optional)

Downstream:
    dig-consensus   ──► dig-slashing (SlashingManager, run_epoch_boundary,
                                      ValidatorView/EffectiveBalanceView/
                                      ProposerView/JustificationView/
                                      RewardPayout/RewardClawback impls)
    dig-collateral  ──► dig-slashing (CollateralSlasher impl, BondEscrow impl)
    dig-mempool     ──► dig-slashing (evidence + appeal REMARK admission + policy)
    validator-app   ──► dig-slashing (SlashingProtection)
    full-node       ──► dig-slashing (verification on block admission,
                                      epoch-boundary orchestration)

    dig-block, dig-epoch, dig-constants ── (no dependency on dig-slashing)
```

## 22. Requirements Catalogue & Test File Mapping

Each requirement has a unique ID `DSL-NNN` and a dedicated test file `tests/dsl_NNN_<short_name>_test.rs`. Every requirement is testable and traced.

### 22.1 Evidence & Attestation Types

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-001 | `OffenseType::base_penalty_bps` returns 500/300/100/100 for the four variants; all `< MAX_PENALTY_BPS`. | `dsl_001_offense_type_bps_mapping_test.rs` |
| DSL-002 | `SlashingEvidence::hash` is deterministic; mutation of any field shifts the hash. | `dsl_002_evidence_hash_determinism_test.rs` |
| DSL-003 | `Checkpoint` serde + equality + hash round-trip. | `dsl_003_checkpoint_roundtrip_test.rs` |
| DSL-004 | `AttestationData::signing_root` is deterministic, domain-prefixed, changes on any field mutation. | `dsl_004_attestation_data_signing_root_test.rs` |
| DSL-005 | `IndexedAttestation::validate_structure` rejects non-ascending, duplicates, empty, over committee cap, bad sig width. | `dsl_005_indexed_attestation_validate_structure_test.rs` |
| DSL-006 | `IndexedAttestation::verify_signature` aggregate BLS verify succeeds on valid aggregate; fails on corruption. | `dsl_006_indexed_attestation_verify_signature_test.rs` |
| DSL-007 | `AttesterSlashing::slashable_indices` returns the sorted intersection. | `dsl_007_attester_slashing_slashable_indices_test.rs` |
| DSL-008 | `InvalidBlockProof` + `InvalidBlockReason` construction + round-trip. | `dsl_008_invalid_block_proof_roundtrip_test.rs` |
| DSL-009 | `SignedBlockHeader` serde round-trip. | `dsl_009_signed_block_header_roundtrip_test.rs` |
| DSL-010 | `SlashingEvidence::slashable_validators` returns 1 for Proposer/InvalidBlock; N for Attester. | `dsl_010_slashable_validators_list_test.rs` |

### 22.2 Evidence Verification

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-011 | `verify_evidence` rejects `OffenseTooOld` when `evidence.epoch + SLASH_LOOKBACK_EPOCHS < current_epoch`. | `dsl_011_verify_evidence_offense_too_old_test.rs` |
| DSL-012 | `verify_evidence` rejects `ReporterIsAccused` when `reporter_index ∈ slashable_validators`. | `dsl_012_verify_evidence_reporter_is_accused_test.rs` |
| DSL-013 | `verify_proposer_slashing` enforces same-slot, same-proposer, different-root, valid sigs, active validator. | `dsl_013_verify_proposer_slashing_preconditions_test.rs` |
| DSL-014 | `verify_attester_slashing` accepts double-vote (same target, different data). | `dsl_014_verify_attester_double_vote_predicate_test.rs` |
| DSL-015 | `verify_attester_slashing` accepts surround-vote (a.src < b.src AND a.tgt > b.tgt). | `dsl_015_verify_attester_surround_vote_predicate_test.rs` |
| DSL-016 | `verify_attester_slashing` rejects `EmptySlashableIntersection`. | `dsl_016_verify_attester_empty_intersection_test.rs` |
| DSL-017 | `verify_attester_slashing` rejects `AttesterSlashingNotSlashable` (neither predicate holds). | `dsl_017_verify_attester_not_slashable_test.rs` |
| DSL-018 | `verify_invalid_block` enforces signature over `block_signing_message`. | `dsl_018_verify_invalid_block_signature_over_domain_test.rs` |
| DSL-019 | `verify_invalid_block` rejects `header.epoch != evidence.epoch`. | `dsl_019_verify_invalid_block_epoch_mismatch_test.rs` |
| DSL-020 | `verify_invalid_block` calls `InvalidBlockOracle::verify_failure` when oracle supplied. | `dsl_020_verify_invalid_block_oracle_called_test.rs` |
| DSL-021 | `verify_evidence_for_inclusion` behaves identically to `verify_evidence` minus state mutation. | `dsl_021_verify_evidence_for_inclusion_parity_test.rs` |

### 22.3 Optimistic Slashing Lifecycle

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-022 | `submit_evidence` applies `base_slash = max(eff_bal*bps/10_000, eff_bal/32)`. | `dsl_022_submit_evidence_base_slash_formula_test.rs` |
| DSL-023 | `submit_evidence` escrows `REPORTER_BOND_MOJOS` via `BondEscrow::lock`. | `dsl_023_submit_evidence_escrows_reporter_bond_test.rs` |
| DSL-024 | `submit_evidence` creates `PendingSlash { status: Accepted, window_expires_at_epoch }`. | `dsl_024_submit_evidence_creates_pending_accepted_test.rs` |
| DSL-025 | `submit_evidence` routes `wb_reward` to reporter puzzle hash + `prop_reward` to block proposer puzzle hash. | `dsl_025_submit_evidence_reward_routing_test.rs` |
| DSL-026 | `submit_evidence` rejects `AlreadySlashed` on duplicate. | `dsl_026_submit_evidence_already_slashed_test.rs` |
| DSL-027 | `submit_evidence` rejects `PendingBookFull` at capacity. | `dsl_027_submit_evidence_book_full_test.rs` |
| DSL-028 | `submit_evidence` rejects `BondLockFailed` on insufficient reporter stake. | `dsl_028_submit_evidence_bond_lock_failed_test.rs` |
| DSL-029 | `finalise_expired_slashes` transitions Accepted / ChallengeOpen to Finalised after window. | `dsl_029_finalise_transitions_to_finalised_test.rs` |
| DSL-030 | `finalise_expired_slashes` applies correlation penalty `eff_bal * min(cohort*3, total) / total`. | `dsl_030_finalise_applies_correlation_penalty_test.rs` |
| DSL-031 | `finalise_expired_slashes` returns reporter bond in full. | `dsl_031_finalise_returns_reporter_bond_test.rs` |
| DSL-032 | `finalise_expired_slashes` schedules exit lock until `current + SLASH_LOCK_EPOCHS`. | `dsl_032_finalise_schedules_exit_lock_test.rs` |
| DSL-033 | `finalise_expired_slashes` skips already-Reverted slashes. | `dsl_033_finalise_skips_reverted_test.rs` |

### 22.4 Appeal Verification — Proposer

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-034 | `ProposerAppeal::HeadersIdentical` sustained when headers byte-equal. | `dsl_034_proposer_appeal_headers_identical_sustained_test.rs` |
| DSL-035 | `ProposerAppeal::ProposerIndexMismatch` sustained. | `dsl_035_proposer_appeal_proposer_index_mismatch_test.rs` |
| DSL-036 | `ProposerAppeal::SignatureAInvalid` sustained when sig_a fails BLS verify. | `dsl_036_proposer_appeal_signature_a_invalid_test.rs` |
| DSL-037 | `ProposerAppeal::SignatureBInvalid` sustained. | `dsl_037_proposer_appeal_signature_b_invalid_test.rs` |
| DSL-038 | `ProposerAppeal::SlotMismatch` sustained. | `dsl_038_proposer_appeal_slot_mismatch_test.rs` |
| DSL-039 | `ProposerAppeal::ValidatorNotActiveAtEpoch` sustained. | `dsl_039_proposer_appeal_validator_not_active_test.rs` |
| DSL-040 | `ProposerAppeal` rejected when claim is false. | `dsl_040_proposer_appeal_rejected_on_false_claim_test.rs` |

### 22.5 Appeal Verification — Attester

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-041 | `AttesterAppeal::AttestationsIdentical` sustained. | `dsl_041_attester_appeal_attestations_identical_test.rs` |
| DSL-042 | `AttesterAppeal::NotSlashableByPredicate` sustained. | `dsl_042_attester_appeal_not_slashable_predicate_test.rs` |
| DSL-043 | `AttesterAppeal::EmptyIntersection` sustained. | `dsl_043_attester_appeal_empty_intersection_test.rs` |
| DSL-044 | `AttesterAppeal::SignatureAInvalid` sustained. | `dsl_044_attester_appeal_signature_a_invalid_test.rs` |
| DSL-045 | `AttesterAppeal::SignatureBInvalid` sustained. | `dsl_045_attester_appeal_signature_b_invalid_test.rs` |
| DSL-046 | `AttesterAppeal::InvalidIndexedAttestationStructure` sustained. | `dsl_046_attester_appeal_invalid_structure_test.rs` |
| DSL-047 | `AttesterAppeal::ValidatorNotInIntersection` sustained for named index. | `dsl_047_attester_appeal_validator_not_in_intersection_test.rs` |
| DSL-048 | `AttesterAppeal` rejected on genuine slash. | `dsl_048_attester_appeal_rejected_genuine_test.rs` |

### 22.6 Appeal Verification — Invalid Block

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-049 | `InvalidBlockAppeal::BlockActuallyValid` sustained when oracle re-executes `Valid`. | `dsl_049_invalid_block_appeal_block_valid_test.rs` |
| DSL-050 | `InvalidBlockAppeal::ProposerSignatureInvalid` sustained. | `dsl_050_invalid_block_appeal_sig_invalid_test.rs` |
| DSL-051 | `InvalidBlockAppeal::FailureReasonMismatch` sustained when oracle reports different reason. | `dsl_051_invalid_block_appeal_reason_mismatch_test.rs` |
| DSL-052 | `InvalidBlockAppeal::EvidenceEpochMismatch` sustained. | `dsl_052_invalid_block_appeal_epoch_mismatch_test.rs` |
| DSL-053 | `InvalidBlockAppeal` returns `MissingOracle` when re-execution needed but no oracle. | `dsl_053_invalid_block_appeal_missing_oracle_test.rs` |
| DSL-054 | `InvalidBlockAppeal` rejected on genuine invalid block. | `dsl_054_invalid_block_appeal_rejected_test.rs` |

### 22.7 Appeal Submission Preconditions

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-055 | `submit_appeal` rejects `UnknownEvidence` for non-existent hash. | `dsl_055_submit_appeal_unknown_evidence_test.rs` |
| DSL-056 | `submit_appeal` rejects `WindowExpired` when filed after window. | `dsl_056_submit_appeal_window_expired_test.rs` |
| DSL-057 | `submit_appeal` rejects `VariantMismatch` on mismatched payload types. | `dsl_057_submit_appeal_variant_mismatch_test.rs` |
| DSL-058 | `submit_appeal` rejects `DuplicateAppeal` on byte-equal prior attempt. | `dsl_058_submit_appeal_duplicate_test.rs` |
| DSL-059 | `submit_appeal` rejects `TooManyAttempts` at `MAX_APPEAL_ATTEMPTS_PER_SLASH`. | `dsl_059_submit_appeal_too_many_attempts_test.rs` |
| DSL-060 | `submit_appeal` rejects `SlashAlreadyReverted`. | `dsl_060_submit_appeal_already_reverted_test.rs` |
| DSL-061 | `submit_appeal` rejects `SlashAlreadyFinalised`. | `dsl_061_submit_appeal_already_finalised_test.rs` |
| DSL-062 | `submit_appeal` escrows `APPELLANT_BOND_MOJOS`. | `dsl_062_submit_appeal_escrows_appellant_bond_test.rs` |
| DSL-063 | `submit_appeal` rejects `PayloadTooLarge` > `MAX_APPEAL_PAYLOAD_BYTES`. | `dsl_063_submit_appeal_payload_too_large_test.rs` |

### 22.8 Adjudicator

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-064 | Sustained reverts per-validator base slash via `credit_stake`. | `dsl_064_adjudicate_sustained_reverts_base_slash_test.rs` |
| DSL-065 | Sustained reverts collateral via `CollateralSlasher::credit`. | `dsl_065_adjudicate_sustained_reverts_collateral_test.rs` |
| DSL-066 | Sustained calls `restore_status` on every slashed validator. | `dsl_066_adjudicate_sustained_restores_status_test.rs` |
| DSL-067 | Sustained claws back `wb_reward` + `prop_reward`. | `dsl_067_adjudicate_sustained_clawback_rewards_test.rs` |
| DSL-068 | Sustained forfeits reporter bond; appellant_award = forfeited × 50%; burn = rest. | `dsl_068_adjudicate_sustained_bond_split_test.rs` |
| DSL-069 | Sustained slashes reporter via `InvalidBlock` base formula. | `dsl_069_adjudicate_sustained_reporter_penalty_test.rs` |
| DSL-070 | Sustained transitions pending to `Reverted`. | `dsl_070_adjudicate_sustained_status_reverted_test.rs` |
| DSL-071 | Rejected forfeits appellant bond; reporter_award = 50%; burn = rest. | `dsl_071_adjudicate_rejected_bond_split_test.rs` |
| DSL-072 | Rejected leaves pending in `ChallengeOpen { appeal_count: n+1 }`. | `dsl_072_adjudicate_rejected_challenge_open_test.rs` |
| DSL-073 | Clawback shortfall absorbed from forfeited bond; residue burned. | `dsl_073_adjudicate_clawback_shortfall_test.rs` |

### 22.9 Participation & Rewards

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-074 | `ParticipationFlags::set` + `has` per bit. | `dsl_074_participation_flags_bits_test.rs` |
| DSL-075 | `classify_timeliness` sets `TIMELY_SOURCE` iff delay ∈ [1,5] AND source_justified. | `dsl_075_classify_timely_source_test.rs` |
| DSL-076 | `classify_timeliness` sets `TIMELY_TARGET` iff delay ∈ [1,32] AND target canonical. | `dsl_076_classify_timely_target_test.rs` |
| DSL-077 | `classify_timeliness` sets `TIMELY_HEAD` iff delay == 1 AND head canonical. | `dsl_077_classify_timely_head_test.rs` |
| DSL-078 | `ParticipationTracker::record_attestation` sets flags for each ascending index. | `dsl_078_participation_tracker_record_test.rs` |
| DSL-079 | `ParticipationTracker::record_attestation` rejects non-ascending indices. | `dsl_079_participation_tracker_non_ascending_test.rs` |
| DSL-080 | `ParticipationTracker::rotate_epoch` swaps prev/current, zeroes current. | `dsl_080_participation_tracker_rotate_test.rs` |
| DSL-081 | `base_reward = eff_bal * BASE_REWARD_FACTOR / isqrt(total_active)`. | `dsl_081_base_reward_formula_test.rs` |
| DSL-082 | `compute_flag_deltas` awards on hit. | `dsl_082_flag_deltas_reward_on_hit_test.rs` |
| DSL-083 | `compute_flag_deltas` penalises SOURCE + TARGET miss; does not penalise HEAD miss. | `dsl_083_flag_deltas_penalty_head_exempt_test.rs` |
| DSL-084 | `compute_flag_deltas` zeroes rewards in finality stall; penalties still apply. | `dsl_084_flag_deltas_stall_zero_rewards_test.rs` |
| DSL-085 | `proposer_inclusion_reward = base * 8 / (64 - 8)`. | `dsl_085_proposer_inclusion_reward_formula_test.rs` |
| DSL-086 | `WEIGHT_DENOMINATOR == 64` with 2 units unassigned (no sync committee). | `dsl_086_weight_denominator_no_sync_test.rs` |

### 22.10 Inactivity

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-087 | `in_finality_stall` true iff `current - finalized > 4`. | `dsl_087_in_finality_stall_threshold_test.rs` |
| DSL-088 | `InactivityScoreTracker::update` decrements on target hit. | `dsl_088_inactivity_score_hit_decrement_test.rs` |
| DSL-089 | `InactivityScoreTracker::update` increments by 4 on target miss + stall. | `dsl_089_inactivity_score_miss_in_stall_increment_test.rs` |
| DSL-090 | `InactivityScoreTracker::update` recovers by 16 per epoch out of stall. | `dsl_090_inactivity_score_out_of_stall_recovery_test.rs` |
| DSL-091 | `InactivityScoreTracker::epoch_penalties` returns empty vec out of stall. | `dsl_091_inactivity_penalty_no_stall_empty_test.rs` |
| DSL-092 | `InactivityScoreTracker::epoch_penalties` formula `eff_bal * score / 16_777_216`. | `dsl_092_inactivity_penalty_formula_test.rs` |
| DSL-093 | `InactivityScoreTracker::resize_for` grows scores vec; new entries start at 0. | `dsl_093_inactivity_resize_test.rs` |

### 22.11 Slashing Protection

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-094 | `check_proposal_slot` monotonic; fails at equal or lower slot after record. | `dsl_094_protection_proposal_monotonic_test.rs` |
| DSL-095 | `check_attestation` fails on same (source,target) with different hash. | `dsl_095_protection_attestation_same_epoch_different_hash_test.rs` |
| DSL-096 | `check_attestation` rejects surround-vote via `would_surround` self-check. | `dsl_096_protection_surround_vote_self_check_test.rs` |
| DSL-097 | `record_proposal` + `record_attestation` persist watermarks. | `dsl_097_protection_record_persist_test.rs` |
| DSL-098 | `rewind_attestation_to_epoch` clears block hash. | `dsl_098_protection_rewind_attestation_clears_hash_test.rs` |
| DSL-099 | `reconcile_with_chain_tip` rewinds both watermarks. | `dsl_099_protection_reconcile_with_tip_test.rs` |
| DSL-100 | Legacy JSON (no hash field) loads with `None`. | `dsl_100_protection_legacy_json_test.rs` |
| DSL-101 | Save/load round-trip preserves all fields. | `dsl_101_protection_save_load_roundtrip_test.rs` |

### 22.12 REMARK Admission — Evidence

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-102 | Evidence REMARK wire: magic prefix + JSON round-trip. | `dsl_102_evidence_remark_wire_roundtrip_test.rs` |
| DSL-103 | Evidence puzzle reveal emits exactly one REMARK; parseable. | `dsl_103_evidence_puzzle_reveal_emits_one_remark_test.rs` |
| DSL-104 | Admission accepts bundle with matching `puzzle_hash`. | `dsl_104_evidence_admission_matching_coin_test.rs` |
| DSL-105 | Admission rejects mismatched payload. | `dsl_105_evidence_admission_mismatch_rejected_test.rs` |
| DSL-106 | Mempool policy rejects expired evidence. | `dsl_106_evidence_mempool_expired_rejected_test.rs` |
| DSL-107 | Mempool policy rejects duplicate evidence. | `dsl_107_evidence_mempool_duplicate_rejected_test.rs` |
| DSL-108 | Block cap: `> MAX_SLASH_PROPOSALS_PER_BLOCK` rejected. | `dsl_108_evidence_block_cap_test.rs` |
| DSL-109 | Payload cap: `> MAX_SLASH_PROPOSAL_PAYLOAD_BYTES` rejected. | `dsl_109_evidence_payload_cap_test.rs` |

### 22.13 REMARK Admission — Appeal

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-110 | Appeal REMARK wire round-trip. | `dsl_110_appeal_remark_wire_roundtrip_test.rs` |
| DSL-111 | Appeal puzzle reveal emits one REMARK; parseable. | `dsl_111_appeal_puzzle_reveal_emits_one_remark_test.rs` |
| DSL-112 | Appeal admission matching coin. | `dsl_112_appeal_admission_matching_coin_test.rs` |
| DSL-113 | Appeal admission mismatched rejected. | `dsl_113_appeal_admission_mismatch_rejected_test.rs` |
| DSL-114 | Appeal mempool `AppealForUnknownSlash`. | `dsl_114_appeal_mempool_unknown_slash_test.rs` |
| DSL-115 | Appeal mempool `AppealWindowExpired`. | `dsl_115_appeal_mempool_window_expired_test.rs` |
| DSL-116 | Appeal mempool `AppealForFinalisedSlash`. | `dsl_116_appeal_mempool_finalised_slash_test.rs` |
| DSL-117 | Appeal mempool `AppealVariantMismatch`. | `dsl_117_appeal_mempool_variant_mismatch_test.rs` |
| DSL-118 | Appeal mempool duplicate rejected. | `dsl_118_appeal_mempool_duplicate_test.rs` |
| DSL-119 | Appeal block cap: `> MAX_APPEALS_PER_BLOCK` rejected. | `dsl_119_appeal_block_cap_test.rs` |
| DSL-120 | Appeal payload cap: `> MAX_APPEAL_PAYLOAD_BYTES` rejected. | `dsl_120_appeal_payload_cap_test.rs` |

### 22.14 Bonds, Rewards, Routing

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-121 | `BondEscrow::lock` returns `InsufficientBalance` when principal stake < amount. | `dsl_121_bond_lock_insufficient_balance_test.rs` |
| DSL-122 | `BondEscrow::forfeit` returns forfeited mojos; zeroes the tag. | `dsl_122_bond_forfeit_returns_mojos_test.rs` |
| DSL-123 | `BondEscrow::release` returns full escrowed amount on finalisation. | `dsl_123_bond_release_full_on_finalise_test.rs` |
| DSL-124 | `REPORTER_BOND_MOJOS == MIN_EFFECTIVE_BALANCE / 64`. | `dsl_124_bond_reporter_size_test.rs` |
| DSL-125 | `APPELLANT_BOND_MOJOS == MIN_EFFECTIVE_BALANCE / 64`. | `dsl_125_bond_appellant_size_test.rs` |
| DSL-126 | `BOND_AWARD_TO_WINNER_BPS = 5_000` (50/50 winner/burn split). | `dsl_126_bond_award_50_50_split_test.rs` |

### 22.15 Orchestration, Genesis, Reorg

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-127 | `run_epoch_boundary` runs (rotate, deltas, inactivity update, inactivity penalties, finalise, rotate tracker, advance epoch, resize, prune) in fixed order. | `dsl_127_epoch_boundary_order_test.rs` |
| DSL-128 | `SlashingSystem::genesis` initialises empty state at `genesis_epoch`. | `dsl_128_genesis_initialisation_test.rs` |
| DSL-129 | `SlashingManager::rewind_on_reorg` drops pending slashes submitted at `epoch > new_tip_epoch`; credits base slash back; releases reporter bond. | `dsl_129_manager_rewind_on_reorg_test.rs` |
| DSL-130 | `rewind_all_on_reorg` orchestrates manager + participation + inactivity + protection rewinds; returns `ReorgReport`. `ReorgTooDeep` when depth > `CORRELATION_WINDOW_EPOCHS`. | `dsl_130_rewind_all_on_reorg_test.rs` |

### 22.17 External-State Traits

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-131 | `ValidatorEntry::slash_absolute(amount, epoch)` saturates at current stake; returns mojos actually debited. | `dsl_131_validator_entry_slash_absolute_saturation_test.rs` |
| DSL-132 | `ValidatorEntry::credit_stake(amount)` adds to stake; inverse of `slash_absolute`; saturates at u64::MAX. | `dsl_132_validator_entry_credit_stake_test.rs` |
| DSL-133 | `ValidatorEntry::restore_status()` clears Slashed → Active; returns `true` iff status changed; idempotent. | `dsl_133_validator_entry_restore_status_test.rs` |
| DSL-134 | `ValidatorEntry::is_active_at_epoch(epoch)` returns `true` iff `activation_epoch <= epoch < exit_epoch`. | `dsl_134_validator_entry_is_active_boundary_test.rs` |
| DSL-135 | `ValidatorEntry::schedule_exit(exit_lock_until_epoch)` persists exit-lock epoch. | `dsl_135_validator_entry_schedule_exit_test.rs` |
| DSL-136 | `ValidatorView::get(idx) / get_mut(idx)` return Some for live idx, None out-of-range. | `dsl_136_validator_view_get_contract_test.rs` |
| DSL-137 | `EffectiveBalanceView::get(idx)` + `total_active()` return per-validator and sum-of-active balances. | `dsl_137_effective_balance_view_test.rs` |
| DSL-138 | `PublicKeyLookup::pubkey_of(idx)` returns validator pubkey; blanket impl for ValidatorView. | `dsl_138_public_key_lookup_test.rs` |
| DSL-139 | `CollateralSlasher::slash` + `credit` symmetric; `NoCollateral` is soft failure. | `dsl_139_collateral_slasher_symmetry_test.rs` |
| DSL-140 | `BondEscrow::escrowed(principal_idx, tag)` returns current amount; 0 for unknown tag; no panic. | `dsl_140_bond_escrowed_query_test.rs` |
| DSL-141 | `RewardPayout::pay(principal_ph, amount)` credits reward account; accumulates on repeat calls. | `dsl_141_reward_payout_pay_test.rs` |
| DSL-142 | `RewardClawback::claw_back` returns actual mojos deducted (0..=amount); partial return permitted. | `dsl_142_reward_clawback_partial_test.rs` |
| DSL-143 | `JustificationView` exposes checkpoints + canonical root queries; read-only. | `dsl_143_justification_view_contract_test.rs` |
| DSL-144 | `ProposerView::proposer_at_slot(slot)` returns Some for committed; None for future/missed. | `dsl_144_proposer_view_test.rs` |
| DSL-145 | `InvalidBlockOracle::re_execute` deterministic: same inputs → same `ExecutionOutcome`. | `dsl_145_invalid_block_oracle_determinism_test.rs` |

### 22.18 Gap-Fill Requirements

Added after the v0.4 audit to close contract gaps identified in §7.1 (PendingSlashBook ops), §7.2 (Manager queries), §4 (correlation saturation), §5.1 (short-circuit), §8.2/§9.2/§14.3 (reorg helpers), and §18 (ParticipationFlags serde).

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-146 | `PendingSlashBook` basic ops: `new/insert/get/get_mut/remove/len` map-like contract. | `dsl_146_pending_slash_book_basic_ops_test.rs` |
| DSL-147 | `PendingSlashBook::expired_by(current_epoch)` returns hashes with `window_expires_at_epoch < current_epoch` AND status in {Accepted, ChallengeOpen}. | `dsl_147_pending_slash_book_expired_by_test.rs` |
| DSL-148 | `SlashingManager::new(epoch)` initialises empty state; `set_epoch(e)` updates current_epoch. | `dsl_148_slashing_manager_new_set_epoch_test.rs` |
| DSL-149 | `SlashingManager::is_slashed(idx, validator_set)` delegates to `ValidatorView::get(idx)?.is_slashed()`. | `dsl_149_slashing_manager_is_slashed_test.rs` |
| DSL-150 | `SlashingManager::is_processed`, `pending`, `prune(before_epoch)` — query + maintenance contracts. | `dsl_150_slashing_manager_is_processed_pending_prune_test.rs` |
| DSL-151 | Correlation penalty clamps `min(cohort_sum * 3, total_active_balance)`; saturating multiplication; `total_active=0` guarded. | `dsl_151_correlation_penalty_saturation_clamp_test.rs` |
| DSL-152 | `submit_evidence` propagates `ReporterIsAccused` BEFORE any bond lock, reward, or state mutation. | `dsl_152_submit_evidence_reporter_is_accused_short_circuit_test.rs` |
| DSL-153 | `ParticipationTracker::rewind_on_reorg(depth, validator_count)` restores ring-buffer snapshot. | `dsl_153_participation_tracker_rewind_on_reorg_test.rs` |
| DSL-154 | `ParticipationFlags(u8)` serde roundtrip byte-exact via bincode + serde_json. | `dsl_154_participation_flags_serde_roundtrip_test.rs` |
| DSL-155 | `InactivityScoreTracker::rewind_on_reorg(depth)` restores ring-buffer snapshot; depth bounded by `CORRELATION_WINDOW_EPOCHS`. | `dsl_155_inactivity_tracker_rewind_on_reorg_test.rs` |
| DSL-156 | `SlashingProtection::rewind_proposal_to_slot(new_tip_slot)` lowers slot when higher; idempotent. | `dsl_156_protection_rewind_proposal_to_slot_test.rs` |

### 22.19 Gap Fills 2 — Serde + Defensive + Variants

Added after the second-pass audit to close serde-contract gaps, defensive-skip semantics for `submit_evidence`, `SlashAppeal` hash contract, and `BondTag` variant distinguishability.

| ID | Requirement | Test File |
|----|-------------|-----------|
| DSL-157 | `SlashingEvidence` + `SlashingEvidencePayload` round-trip via bincode + serde_json for all 3 payload variants; serde_bytes encoding preserved. | `dsl_157_slashing_evidence_serde_roundtrip_test.rs` |
| DSL-158 | `IndexedAttestation` round-trips via bincode + serde_json preserving index order, signature serde_bytes, nested AttestationData. | `dsl_158_indexed_attestation_serde_roundtrip_test.rs` |
| DSL-159 | `SlashAppeal::hash()` deterministic + sensitive to each field mutation; domain-prefixed under `DOMAIN_SLASH_APPEAL`. | `dsl_159_slash_appeal_hash_determinism_test.rs` |
| DSL-160 | `SlashAppeal` + `SlashAppealPayload` + all ground enums round-trip via bincode + serde_json. | `dsl_160_slash_appeal_serde_roundtrip_test.rs` |
| DSL-161 | `PendingSlash` + `PendingSlashStatus` (4 variants) + `AppealAttempt` + `AppealOutcome` (3 variants) round-trip via bincode. | `dsl_161_pending_slash_serde_roundtrip_test.rs` |
| DSL-162 | `submit_evidence` per-validator loop uniformly skips indices flagged `is_slashed()`; no slash, no collateral debit, no window record, no result entry; evidence still marked processed. | `dsl_162_submit_evidence_skips_already_slashed_test.rs` |
| DSL-163 | `SlashingResult` + `PerValidatorSlash` + `FinalisationResult` round-trip via bincode + serde_json. | `dsl_163_slashing_result_serde_roundtrip_test.rs` |
| DSL-164 | `AppealAdjudicationResult` round-trips via bincode + serde_json; sustained and rejected cases preserved. | `dsl_164_appeal_adjudication_result_serde_test.rs` |
| DSL-165 | `EpochBoundaryReport` + `ReorgReport` + `FlagDelta` round-trip via bincode + serde_json. | `dsl_165_epoch_boundary_reorg_report_serde_test.rs` |
| DSL-166 | `BondTag::Reporter(h)` vs `BondTag::Appellant(h)` distinguishable via PartialEq + Hash + separate escrow slots + serde discriminator; Copy derive works. | `dsl_166_bond_tag_variants_distinguishable_test.rs` |

### 22.16 Traceability Rules

1. Every requirement must have exactly one `dsl_NNN_*_test.rs` file.
2. Every test file begins with a doc comment `//! Requirement DSL-NNN: <text>` matching §22 exactly.
3. CI verifies 1:1 correspondence. A requirement without a file OR a file without a §22 entry fails the build.
4. Requirements are append-only: new behavior adds DSL-131, DSL-132, ... Existing IDs never change or reorder; a superseded requirement is marked `(superseded by DSL-NNN)` and its file is kept as a regression test.

## 23. Open Items

1. **Governance-level appeal escalation.** Deterministic fraud proofs cover evidence-verifier bugs. Policy questions may warrant a 2nd-tier governance escalation; a `GovernanceAppeal` hook will be added if that path lands.
2. **Succinct validity proof (STARK) path** for `InvalidBlockAppeal::BlockActuallyValid` — lets light clients adjudicate without full re-execution. Reserved.
3. **Appeal-prioritised inclusion.** Block proposers may delay including appeals to run out the window. An `APPEAL_INCLUSION_REWARD` bonus is under consideration.
4. **Appeal bond scaling with accused's effective balance.** Currently flat `MIN_EFFECTIVE_BALANCE / 64`; may scale to prevent grief-reporting of small validators.
5. **Multi-tier appeal windows.** Current: flat 8 epochs. ProposerEquivocation is trivially verifiable; InvalidBlock re-execution is expensive. Tier-specific windows may help.
6. **Threadsafe manager.** `parking_lot::RwLock` behind `threadsafe` cargo feature.
7. **Reporter-proposer collusion rebate.** If the reporter and the block proposer are the same validator (allowed), `wb_reward + prop_reward` both accrue to them. Current behavior matches Ethereum. A future policy may require them to differ.
