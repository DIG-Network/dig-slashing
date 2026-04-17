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
