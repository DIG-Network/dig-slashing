//! Protocol constants for dig-slashing.
//!
//! Traces to: [SPEC.md §2](../docs/resources/SPEC.md).
//!
//! Every value here is **protocol law** — changing any one constant requires a
//! protocol version bump, not a bug fix. Downstream crates re-export from this
//! module; no other file in this crate defines BPS values, quotients, or
//! domain tags.
//!
//! # Why a flat module instead of a const enum
//!
//! The constants are consumed across almost every other module (evidence
//! verification, appeal adjudication, reward math, inactivity accounting).
//! A flat module with `pub const` items is the cheapest interface for that
//! usage pattern — no trait dispatch, no import noise, and every reference
//! shows up clearly in `cargo-udeps` / `gitnexus` impact analysis when a
//! consumer is added or removed.

// ── Penalty base rates (BPS — basis points, 10_000 = 100%) ──────────────────
//
// The BPS floor for each offense sets the minimum slash amount before
// correlation amplification is applied at finalisation. The per-validator
// slash is `max(eff_bal * base_bps / 10_000, eff_bal / MIN_SLASHING_PENALTY_QUOTIENT)`;
// see SPEC §4 for the full formula and DSL-022 for the implementation.

/// Base penalty for `OffenseType::ProposerEquivocation` — 5%.
///
/// Traces to SPEC §2.1. The heaviest floor of the four offenses: signing
/// two distinct blocks at the same slot is the most blatant consensus
/// misbehavior and indisputably intentional (an honest proposer produces
/// exactly one block per slot).
pub const EQUIVOCATION_BASE_BPS: u16 = 500;

/// Base penalty for `OffenseType::InvalidBlock` — 3%.
///
/// Traces to SPEC §2.1. Less severe than equivocation because invalid
/// blocks can result from bugs as well as malice, but still a protocol
/// violation: the proposer signed a block that fails validation under the
/// canonical rules.
pub const INVALID_BLOCK_BASE_BPS: u16 = 300;

/// Base penalty for both attester offenses (`AttesterDoubleVote`, `AttesterSurroundVote`) — 1%.
///
/// Traces to SPEC §2.1. Smaller per-validator floor because attestation
/// offenses are mass-participation: a single `IndexedAttestation` can carry
/// thousands of signers. Correlation amplification at finalisation
/// (DSL-030 + DSL-151) scales the aggregate when many validators are caught.
pub const ATTESTATION_BASE_BPS: u16 = 100;

/// Maximum single-offense BPS floor — 10%.
///
/// Traces to SPEC §2.1. Invariant: every offense's `base_penalty_bps()`
/// return value is `< MAX_PENALTY_BPS`. Correlation penalty at finalisation
/// may exceed this cap (proportional slashing applies on top); this constant
/// bounds only the initial optimistic debit.
pub const MAX_PENALTY_BPS: u16 = 1_000;

/// BPS denominator: `10_000` basis points = 100%.
///
/// Traces to SPEC §2.1. Divisor for every BPS-parameterised formula in
/// the crate (base slash, correlation-penalty, bond-award split).
/// Declared `u64` to match the numerator types in the slash formula
/// and avoid per-call casts.
pub const BPS_DENOMINATOR: u64 = 10_000;

/// Ethereum-parity minimum-slashing-penalty quotient — `32`.
///
/// Traces to SPEC §2.2, §4. Sets the floor term `eff_bal /
/// MIN_SLASHING_PENALTY_QUOTIENT` in the base slash formula (DSL-022).
/// Guarantees a non-trivial burn even on low-bps offenses (100 bps
/// attester votes → `eff_bal / 32` > `eff_bal / 100`).
pub const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 32;

/// Minimum per-validator effective balance, in mojos — `32e9` (32 DIG).
///
/// Traces to SPEC §2.6. Anchors the bond-size constants
/// (`REPORTER_BOND_MOJOS`, `APPELLANT_BOND_MOJOS`) and reward/penalty
/// denominators. SPEC designates this as a re-export from
/// `dig-consensus::MIN_VALIDATOR_COLLATERAL`; defined locally here
/// while that crate is not yet on crates.io. Value must stay
/// byte-identical to the upstream constant when the re-export lands.
pub const MIN_EFFECTIVE_BALANCE: u64 = 32_000_000_000;

/// Reporter bond required to submit slashing evidence — `MIN_EFFECTIVE_BALANCE / 64`.
///
/// Traces to SPEC §2.6, §12.3. Held in `BondEscrow` under
/// `BondTag::Reporter(evidence_hash)` for the 8-epoch appeal window
/// (DSL-023). Returned in full on finalisation (DSL-031) or forfeited
/// on sustained appeal (DSL-068). Locked AFTER `verify_evidence` and
/// BEFORE any `slash_absolute` call in `submit_evidence`.
pub const REPORTER_BOND_MOJOS: u64 = MIN_EFFECTIVE_BALANCE / 64;

/// Appellant bond required to file an appeal — same size as the
/// reporter bond.
///
/// Traces to SPEC §2.6. Symmetric with `REPORTER_BOND_MOJOS` so the
/// reporter and appellant face equal grief-vector costs.
pub const APPELLANT_BOND_MOJOS: u64 = MIN_EFFECTIVE_BALANCE / 64;

/// Exit-lock duration for a finalised slash — `100` epochs.
///
/// Traces to SPEC §2.2, §7.4 step 4. On finalisation (DSL-032) the
/// manager calls `ValidatorEntry::schedule_exit(current_epoch +
/// SLASH_LOCK_EPOCHS)` on every slashed validator — preventing
/// voluntary exit + stake withdrawal before the correlation window
/// tail-end + any follow-on slashes settle.
pub const SLASH_LOCK_EPOCHS: u64 = 100;

/// Appeal window length in epochs — `8`.
///
/// Traces to SPEC §2.6. A submitted `PendingSlash` can be appealed
/// any time in `[submitted_at_epoch, submitted_at_epoch +
/// SLASH_APPEAL_WINDOW_EPOCHS]`; after that the slash finalises
/// (DSL-029). Ethereum parity: 2 epochs of ~6.4 min ≈ 12 min; DIG
/// uses 8 epochs to match L2 block cadence.
pub const SLASH_APPEAL_WINDOW_EPOCHS: u64 = 8;

/// Minimum inclusion delay for an attestation to be
/// reward-eligible, in slots.
///
/// Traces to SPEC §2.5. `inclusion_slot - data.slot` MUST be
/// at least this value. `delay = 0` is impossible in the honest
/// protocol (an attestation cannot be included in the block at
/// its own slot) — the check is defensive.
pub const MIN_ATTESTATION_INCLUSION_DELAY: u64 = 1;

/// Maximum inclusion delay for an attestation to count as
/// `TIMELY_SOURCE`, in slots.
///
/// Traces to SPEC §2.5, §8.1. Beyond this, the attestation is
/// too stale to credit the source vote — the validator missed
/// the justification window.
pub const TIMELY_SOURCE_MAX_DELAY_SLOTS: u64 = 5;

/// Bit index of the `TIMELY_SOURCE` flag in `ParticipationFlags`.
///
/// Traces to SPEC §2.9, §3.10. Ethereum Altair parity: source
/// vote timely iff the attestation arrives within one epoch of
/// the source-checkpoint boundary.
pub const TIMELY_SOURCE_FLAG_INDEX: u8 = 0;

/// Bit index of the `TIMELY_TARGET` flag in `ParticipationFlags`.
///
/// Traces to SPEC §2.9, §3.10.
pub const TIMELY_TARGET_FLAG_INDEX: u8 = 1;

/// Bit index of the `TIMELY_HEAD` flag in `ParticipationFlags`.
///
/// Traces to SPEC §2.9, §3.10. Head vote timely iff `inclusion_delay
/// == 1` — only reachable when the attestation is included in the
/// very next block.
pub const TIMELY_HEAD_FLAG_INDEX: u8 = 2;

/// 50/50 winner-award / burn split in basis points applied to a
/// forfeited bond.
///
/// Traces to SPEC §2.6, §6.5. Consumed by DSL-068 (sustained →
/// reporter bond forfeited, 50% routed to appellant, 50% burned)
/// and DSL-071 (rejected → appellant bond forfeited, 50% to
/// reporter, 50% burned). Expressed in basis points so future
/// governance can tune it without changing the integer-division
/// structure of the split.
pub const BOND_AWARD_TO_WINNER_BPS: u64 = 5_000;

/// Maximum serialized-bytes length of a `SlashAppeal` envelope.
///
/// Traces to SPEC §2.6, §6.1. Caps memory + DoS cost for
/// invalid-block witness storage. Measured against the same
/// bincode encoding used by `SlashAppeal::hash` (DSL-058) —
/// deterministic, compact, length-prefixed. SPEC allows any
/// canonical encoding; we pick bincode for parity with the
/// `SlashingEvidence` envelope and to avoid pulling serde_json
/// into the hot path.
///
/// Consumed by DSL-063 (`PayloadTooLarge`) rejection.
pub const MAX_APPEAL_PAYLOAD_BYTES: usize = 131_072;

/// Maximum distinct appeal attempts per pending slash.
///
/// Traces to SPEC §2.6, §6.1. Caps adjudication cost at a fixed
/// upper bound per admitted evidence. Consumed by DSL-059
/// (`TooManyAttempts`) rejection. Sustained attempts transition
/// the slash to `Reverted` and the book entry is drained — they
/// never contribute to this count.
pub const MAX_APPEAL_ATTEMPTS_PER_SLASH: usize = 4;

/// Maximum number of pending slashes the manager will track.
///
/// Traces to SPEC §2.6. Bounds memory + pruning cost. Admission at
/// full capacity returns `SlashingError::PendingBookFull` (DSL-027).
pub const MAX_PENDING_SLASHES: usize = 4_096;

/// Whistleblower reward divisor — `512`.
///
/// Traces to SPEC §2.3, §4. `wb_reward = total_eff_bal / 512`.
/// Ethereum parity (equivalent role in consensus spec). Routed to the
/// reporter's puzzle hash on admission (DSL-025), clawback-reversible
/// on sustained appeal (DSL-067).
pub const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 512;

/// Ethereum-parity proportional-slashing multiplier — `3`.
///
/// Traces to SPEC §2.2, §4. Amplifies `cohort_sum` in the
/// finalisation correlation penalty
/// (`eff_bal * min(cohort_sum * 3, total_active) / total_active`),
/// so coordinated-attack slashes are punished more than isolated ones.
pub const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 3;

/// Proposer inclusion-reward divisor — `8`.
///
/// Traces to SPEC §2.3. `prop_reward = wb_reward / 8`. Paid to the
/// block proposer at the slot that includes the evidence — incentive
/// for proposers to actually include the REMARK bundle carrying the
/// evidence in the next block. Clawback-reversible on sustained appeal.
pub const PROPOSER_REWARD_QUOTIENT: u64 = 8;

// ── Domain separation tags (SPEC §2.10) ─────────────────────────────────────
//
// Byte-string tags prefixed into every SHA-256 digest so a hash produced for
// one protocol context (e.g. an attester signing root) cannot be reinterpreted
// in another context (e.g. a proposer signing root). These are `&[u8]`
// constants because `chia_sha2::Sha256::update` accepts `impl AsRef<[u8]>`.
//
// Tags are frozen at protocol-version level; changes require a `_V2` rename
// alongside the old tag kept live during migration.

/// Domain tag for `AttestationData::signing_root` (DSL-004).
///
/// Traces to SPEC §2.10. Binds every attester BLS signing message to the
/// attester-slashing / attestation-participation context so a signature
/// produced here cannot be replayed as a proposer signature (DSL-050).
pub const DOMAIN_BEACON_ATTESTER: &[u8] = b"DIG_BEACON_ATTESTER_V1";

/// Domain tag for `SlashingEvidence::hash` (DSL-002).
///
/// Traces to SPEC §2.10, §3.5. Prefixed into the SHA-256 digest of a
/// bincode-serialized `SlashingEvidence` envelope so the resulting hash
/// cannot collide with any other protocol digest (attester signing root,
/// appeal hash, REMARK wire hash). Used as the processed-map key
/// (DSL-026) and the `BondTag::Reporter` binding (DSL-023); collision
/// under either structure would cause double-slashing or bond misrouting.
pub const DOMAIN_SLASHING_EVIDENCE: &[u8] = b"DIG_SLASHING_EVIDENCE_V1";

/// Domain tag for `SlashAppeal::hash` (DSL-058, DSL-159).
///
/// Traces to SPEC §2.10, §3.7. Prefixed into the SHA-256 digest of
/// a bincode-serialized `SlashAppeal` envelope so the appeal hash
/// cannot collide with an evidence hash (`DOMAIN_SLASHING_EVIDENCE`)
/// or any other protocol digest. Appeal hashes key
/// `PendingSlash::appeal_history` entries (DSL-058 duplicate check)
/// and are used by the adjudicator (DSL-070 `winning_appeal_hash`).
pub const DOMAIN_SLASH_APPEAL: &[u8] = b"DIG_SLASH_APPEAL_V1";

/// Domain tag for proposer `block_signing_message` (DSL-013, DSL-018).
///
/// Traces to SPEC §2.10, §5.2 step 6 + §5.4 step 1. Prefixed into the
/// BLS signing message so a proposer signature produced for block
/// production cannot be replayed as an attester signature (which uses
/// `DOMAIN_BEACON_ATTESTER`) or any other context.
pub const DOMAIN_BEACON_PROPOSER: &[u8] = b"DIG_BEACON_PROPOSER_V1";

// ── BLS widths (SPEC §2.10) ─────────────────────────────────────────────────
//
// Canonical BLS12-381 byte widths used by `chia-bls`. Re-declared here so
// every wire-format check in this crate cites a single constant, and so
// breaking upstream changes show up as compile-time edits to one place.

/// BLS12-381 G2 signature compressed width (bytes).
///
/// Traces to SPEC §2.10. Used by `IndexedAttestation::validate_structure`
/// (DSL-005) as the exact equality check on `signature.len()`.
pub const BLS_SIGNATURE_SIZE: usize = 96;

/// BLS12-381 G1 public key compressed width (bytes).
///
/// Traces to SPEC §2.10.
pub const BLS_PUBLIC_KEY_SIZE: usize = 48;

// ── Committee size cap (SPEC §2.7) ──────────────────────────────────────────

/// Maximum number of validator indices in a single `IndexedAttestation`.
///
/// Traces to SPEC §2.7, Ethereum-parity value. Bounds memory + aggregate-
/// verify cost per attestation. `IndexedAttestation::validate_structure`
/// (DSL-005) rejects lengths strictly greater than this cap; the cap
/// itself is valid (boundary behaviour enforced by
/// `test_dsl_005_at_cap_accepted`).
pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2_048;

/// Maximum size of a slash-proposal payload (`failure_witness` bytes +
/// appeal witness bytes combined) in bytes.
///
/// Traces to SPEC §2.7. Bounds memory + wire-size of evidence and
/// appeals at 64 KiB — enough room for a block re-execution witness
/// (trie proofs + state diff) without allowing unbounded adversary
/// payloads. `verify_invalid_block` (DSL-018) rejects `failure_witness`
/// with length `> MAX_SLASH_PROPOSAL_PAYLOAD_BYTES`; REMARK admission
/// (DSL-109) mirrors this cap at the mempool layer.
pub const MAX_SLASH_PROPOSAL_PAYLOAD_BYTES: usize = 65_536;
