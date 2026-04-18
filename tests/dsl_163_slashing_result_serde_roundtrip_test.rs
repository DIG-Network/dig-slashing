//! Requirement DSL-163: `SlashingResult`, `PerValidatorSlash`, `FinalisationResult` round-trip byte-exactly via bincode + serde_json.
//!
//! Traces to: docs/resources/SPEC.md §3.9, §18.
//!
//! # Role
//!
//! Three result types crossed the wire for:
//!
//!   - `SlashingResult` — returned from `submit_evidence` (DSL-022..025). Carries per-validator slash vec + reward/bond totals + pending slash hash.
//!   - `PerValidatorSlash` — one entry per accused index actually debited. DSL-162 skips never appear.
//!   - `FinalisationResult` — returned from `finalise_expired_slashes` (DSL-029..032). Carries correlation-penalty pairs + reporter bond return + exit lock epoch.
//!
//! Serde roundtrip is required by:
//!
//!   - Internal snapshot/restore (bincode) — RPC servers that cache admission results across a restart need byte-identical decode.
//!   - RPC / telemetry (serde_json) — DSL-025 reward amounts surface to dashboards.
//!   - Test fixtures that inject mid-cycle result state without driving the full pipeline.
//!
//! # Test matrix (maps to DSL-163 Test Plan)
//!
//!   1. `test_dsl_163_slashing_result_bincode` — populated SlashingResult with non-empty per_validator vec + non-zero rewards.
//!   2. `test_dsl_163_per_validator_slash_bincode` — standalone PerValidatorSlash including `collateral_slashed` field.
//!   3. `test_dsl_163_finalisation_result_bincode` — FinalisationResult with multi-entry correlation vec including a zero-penalty pair (pins that zero values survive).
//!   4. `test_dsl_163_json_roundtrip_all` — same three types under serde_json (RPC wire path).
//!   5. `test_dsl_163_zero_preserved` — Default::default() instances for both SlashingResult and FinalisationResult roundtrip verbatim; proves zero-filled / empty-vec / Bytes32([0;32]) fields are NOT silently dropped.

use dig_protocol::Bytes32;
use dig_slashing::{FinalisationResult, PerValidatorSlash, SlashingResult};

// ── fixtures ───────────────────────────────────────────────────

fn populated_per_validator(idx: u32) -> PerValidatorSlash {
    PerValidatorSlash {
        validator_index: idx,
        base_slash_amount: 1_000_000_000,
        effective_balance_at_slash: 32_000_000_000,
        collateral_slashed: 500_000,
    }
}

fn populated_slashing_result() -> SlashingResult {
    SlashingResult {
        per_validator: vec![
            populated_per_validator(3),
            populated_per_validator(5),
            populated_per_validator(7),
        ],
        whistleblower_reward: 1_250_000,
        proposer_reward: 156_250,
        burn_amount: 10_000_000,
        reporter_bond_escrowed: 500_000_000,
        pending_slash_hash: Bytes32::new([0xEFu8; 32]),
    }
}

fn populated_finalisation_result() -> FinalisationResult {
    FinalisationResult {
        evidence_hash: Bytes32::new([0x42u8; 32]),
        per_validator_correlation_penalty: vec![
            (3, 100_000),
            (5, 0), // zero-penalty pair — pins the DSL-163 "zero preserved" contract at the vec-element level.
            (7, 250_000),
        ],
        reporter_bond_returned: 500_000_000,
        exit_lock_until_epoch: 1_234,
    }
}

// ── roundtrip assertions ──────────────────────────────────────

fn roundtrip_bincode<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let bytes = bincode::serialize(value).expect("bincode ser");
    let decoded: T = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(*value, decoded, "bincode preserves every field");
}

fn roundtrip_json<T>(value: &T)
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + PartialEq + std::fmt::Debug,
{
    let bytes = serde_json::to_vec(value).expect("json ser");
    let decoded: T = serde_json::from_slice(&bytes).expect("json deser");
    assert_eq!(*value, decoded, "serde_json preserves every field");
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-163 row 1: populated SlashingResult roundtrips under bincode.
///
/// Exercises every field — non-empty per_validator vec (3 entries),
/// non-zero whistleblower + proposer rewards, non-zero burn, non-
/// zero reporter_bond_escrowed, distinctive pending_slash_hash.
#[test]
fn test_dsl_163_slashing_result_bincode() {
    let result = populated_slashing_result();
    roundtrip_bincode(&result);

    // Spot-check the pending_slash_hash survived at the Bytes32
    // level — guards against silent length-prefix drift.
    let bytes = bincode::serialize(&result).expect("bincode ser");
    let decoded: SlashingResult = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(decoded.pending_slash_hash, Bytes32::new([0xEFu8; 32]));
    assert_eq!(decoded.per_validator.len(), 3);
}

/// DSL-163 row 2: standalone PerValidatorSlash roundtrips under
/// bincode.
///
/// Matters because PerValidatorSlash is also embedded inside
/// PendingSlash (DSL-161 roundtrip) + SlashingResult. Standalone
/// roundtrip proves the struct is serde-correct independent of
/// its container — useful for test fixtures constructing vecs
/// directly without building a SlashingResult envelope.
#[test]
fn test_dsl_163_per_validator_slash_bincode() {
    let pv = populated_per_validator(42);
    roundtrip_bincode(&pv);

    // Also probe extreme values — u32::MAX idx + u64::MAX eff_bal
    // to catch length-prefix edge cases.
    let max = PerValidatorSlash {
        validator_index: u32::MAX,
        base_slash_amount: u64::MAX,
        effective_balance_at_slash: u64::MAX,
        collateral_slashed: u64::MAX,
    };
    roundtrip_bincode(&max);
}

/// DSL-163 row 3: populated FinalisationResult roundtrips under
/// bincode. Critical coverage: `per_validator_correlation_penalty:
/// Vec<(u32, u64)>` includes a ZERO-PENALTY pair. Pins that serde
/// tuple encoding preserves zero-valued u64 — a subtle refactor
/// to elide zero entries for wire-compactness would fail this.
#[test]
fn test_dsl_163_finalisation_result_bincode() {
    let fr = populated_finalisation_result();
    roundtrip_bincode(&fr);

    let bytes = bincode::serialize(&fr).expect("bincode ser");
    let decoded: FinalisationResult = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(decoded.per_validator_correlation_penalty.len(), 3);
    assert_eq!(
        decoded.per_validator_correlation_penalty[1],
        (5u32, 0u64),
        "zero-penalty pair preserved verbatim",
    );
}

/// DSL-163 row 4: all three types under serde_json.
///
/// RPC wire path — telemetry + observability consumers decode
/// these over HTTP. A JSON encoding that drops the zero entries
/// or reorders per_validator would invalidate dashboards.
#[test]
fn test_dsl_163_json_roundtrip_all() {
    roundtrip_json(&populated_per_validator(42));
    roundtrip_json(&populated_slashing_result());
    roundtrip_json(&populated_finalisation_result());
}

/// DSL-163 row 5: Default::default() instances roundtrip verbatim.
///
/// Both SlashingResult and FinalisationResult derive Default.
/// Zero-filled instances surface during DSL-029 (empty
/// finalisation pass) + DSL-022 test fixtures. Zero-valued
/// Bytes32 + empty vecs must NOT be silently dropped — otherwise
/// a roundtrip would yield a different-shape struct than the
/// original.
#[test]
fn test_dsl_163_zero_preserved() {
    // SlashingResult default: all zeros + empty per_validator +
    // all-zero Bytes32 pending_slash_hash.
    let default_sr = SlashingResult::default();
    assert_eq!(default_sr.per_validator.len(), 0);
    assert_eq!(default_sr.whistleblower_reward, 0);
    assert_eq!(default_sr.pending_slash_hash, Bytes32::new([0u8; 32]));
    roundtrip_bincode(&default_sr);
    roundtrip_json(&default_sr);

    // FinalisationResult default: all zeros + empty
    // per_validator_correlation_penalty.
    let default_fr = FinalisationResult::default();
    assert_eq!(default_fr.per_validator_correlation_penalty.len(), 0);
    assert_eq!(default_fr.reporter_bond_returned, 0);
    assert_eq!(default_fr.exit_lock_until_epoch, 0);
    assert_eq!(default_fr.evidence_hash, Bytes32::new([0u8; 32]));
    roundtrip_bincode(&default_fr);
    roundtrip_json(&default_fr);

    // PerValidatorSlash zero-filled (no Default derive — construct
    // manually).
    let zero_pv = PerValidatorSlash {
        validator_index: 0,
        base_slash_amount: 0,
        effective_balance_at_slash: 0,
        collateral_slashed: 0,
    };
    roundtrip_bincode(&zero_pv);
    roundtrip_json(&zero_pv);
}
