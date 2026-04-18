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
