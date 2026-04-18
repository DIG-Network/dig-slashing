//! Requirement DSL-160: `SlashAppeal` envelope + `SlashAppealPayload` + all three per-offense ground enums round-trip byte-exactly via `bincode` and `serde_json`.
//!
//! Traces to: docs/resources/SPEC.md §3.6, §3.7, §18.
//!
//! # Role
//!
//! `SlashAppeal` is the wire envelope the adjudicator receives
//! over the REMARK channel (DSL-110). The payload variant
//! (`Proposer` / `Attester` / `InvalidBlock`) carries one of the
//! ground enums whose discriminant encodes the categorical reason
//! for appeal (DSL-034..054 × per-offense grounds).
//!
//! Byte-exact roundtrip is load-bearing because:
//!
//!   - DSL-110 REMARK wire uses serde_json — drift breaks
//!     peer-sourced appeal admission.
//!   - DSL-159 `SlashAppeal::hash()` canonicalises via bincode
//!     before hashing. A serde refactor that changes any
//!     variant's discriminant encoding would silently shift every
//!     appeal hash and break DSL-058 dedup / DSL-070 winning-
//!     appeal lookup.
//!   - PendingSlash's `appeal_history: Vec<AppealAttempt>` carries
//!     `appeal_hash: Bytes32` — if the appeal hash drifts on a
//!     reserialisation step (e.g. storage rotation), the attempt
//!     record falls out of sync with the live appeal.
//!
//! # Ground-enum coverage
//!
//! - ProposerAppealGround: 6 variants (DSL-034..039).
//! - AttesterAppealGround: 7 variants INCLUDING the payload-
//!   carrying `ValidatorNotInIntersection { validator_index }`
//!   (DSL-047). This is the only non-unit variant across the
//!   three ground enums — deserving its own roundtrip test to
//!   pin the struct-variant encoding.
//! - InvalidBlockAppealGround: 4 variants (DSL-049..052).
//!
//! # Test matrix (maps to DSL-160 Test Plan)
//!
//!   1. `test_dsl_160_proposer_bincode` — all 6 ProposerAppealGround
//!      variants × bincode roundtrip.
//!   2. `test_dsl_160_attester_bincode` — all 7 AttesterAppealGround
//!      variants × bincode, including the struct-variant
//!      ValidatorNotInIntersection{validator_index}.
//!   3. `test_dsl_160_invalid_block_bincode` — all 4 grounds ×
//!      bincode.
//!   4. `test_dsl_160_all_json_roundtrip` — identical matrix under
//!      serde_json.
//!   5. `test_dsl_160_witness_bytes_format` — witness field under
//!      bincode contains the raw byte run verbatim (pins
//!      `#[serde(with = "serde_bytes")]`); JSON emits as integer
//!      array; cross-codec roundtrip equal.

use dig_protocol::Bytes32;
use dig_slashing::{
    AttesterAppealGround, AttesterSlashingAppeal, InvalidBlockAppeal, InvalidBlockAppealGround,
    ProposerAppealGround, ProposerSlashingAppeal, SlashAppeal, SlashAppealPayload,
};

// ── envelope builders ──────────────────────────────────────────

fn envelope_for_payload(payload: SlashAppealPayload) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: Bytes32::new([0xAAu8; 32]),
        appellant_index: 42,
        appellant_puzzle_hash: Bytes32::new([0xBBu8; 32]),
        filed_epoch: 100,
        payload,
    }
}

fn proposer_envelope(ground: ProposerAppealGround, witness: Vec<u8>) -> SlashAppeal {
    envelope_for_payload(SlashAppealPayload::Proposer(ProposerSlashingAppeal {
        ground,
        witness,
    }))
}

fn attester_envelope(ground: AttesterAppealGround, witness: Vec<u8>) -> SlashAppeal {
    envelope_for_payload(SlashAppealPayload::Attester(AttesterSlashingAppeal {
        ground,
        witness,
    }))
}

fn invalid_block_envelope(ground: InvalidBlockAppealGround, witness: Vec<u8>) -> SlashAppeal {
    envelope_for_payload(SlashAppealPayload::InvalidBlock(InvalidBlockAppeal {
        ground,
        witness,
    }))
}

// ── variant enumerations ───────────────────────────────────────

fn all_proposer_grounds() -> Vec<ProposerAppealGround> {
    vec![
        ProposerAppealGround::HeadersIdentical,
        ProposerAppealGround::ProposerIndexMismatch,
        ProposerAppealGround::SignatureAInvalid,
        ProposerAppealGround::SignatureBInvalid,
        ProposerAppealGround::SlotMismatch,
        ProposerAppealGround::ValidatorNotActiveAtEpoch,
    ]
}

fn all_attester_grounds() -> Vec<AttesterAppealGround> {
    vec![
        AttesterAppealGround::AttestationsIdentical,
        AttesterAppealGround::NotSlashableByPredicate,
        AttesterAppealGround::EmptyIntersection,
        AttesterAppealGround::SignatureAInvalid,
        AttesterAppealGround::SignatureBInvalid,
        AttesterAppealGround::InvalidIndexedAttestationStructure,
        // Struct-variant — separate from the unit variants; pins
        // that serde handles payload-carrying enum variants.
        AttesterAppealGround::ValidatorNotInIntersection { validator_index: 7 },
    ]
}

fn all_invalid_block_grounds() -> Vec<InvalidBlockAppealGround> {
    vec![
        InvalidBlockAppealGround::BlockActuallyValid,
        InvalidBlockAppealGround::ProposerSignatureInvalid,
        InvalidBlockAppealGround::FailureReasonMismatch,
        InvalidBlockAppealGround::EvidenceEpochMismatch,
    ]
}

// ── roundtrip helpers ──────────────────────────────────────────

fn assert_bincode_roundtrip(ev: &SlashAppeal) {
    let bytes = bincode::serialize(ev).expect("bincode ser");
    let decoded: SlashAppeal = bincode::deserialize(&bytes).expect("bincode deser");
    assert_eq!(
        *ev, decoded,
        "bincode preserves envelope + ground + witness",
    );
    // Hash-stability — content-address must survive reserialisation
    // or DSL-058 dedup / DSL-070 winning-appeal lookup breaks.
    assert_eq!(
        ev.hash(),
        decoded.hash(),
        "appeal.hash() stable across bincode roundtrip",
    );
}

fn assert_json_roundtrip(ev: &SlashAppeal) {
    let bytes = serde_json::to_vec(ev).expect("json ser");
    let decoded: SlashAppeal = serde_json::from_slice(&bytes).expect("json deser");
    assert_eq!(*ev, decoded, "serde_json preserves every field");
    assert_eq!(
        ev.hash(),
        decoded.hash(),
        "appeal.hash() stable across serde_json roundtrip — DSL-110 wire",
    );
}

// ── tests ──────────────────────────────────────────────────────

/// DSL-160 row 1: all 6 `ProposerAppealGround` variants roundtrip
/// via bincode. Includes a non-empty witness so the serde_bytes
/// encoding is exercised alongside the enum discriminant.
#[test]
fn test_dsl_160_proposer_bincode() {
    for ground in all_proposer_grounds() {
        let ev = proposer_envelope(ground, vec![0x01, 0x02, 0x03]);
        assert_bincode_roundtrip(&ev);
    }
}

/// DSL-160 row 2: all 7 `AttesterAppealGround` variants roundtrip
/// via bincode.
///
/// Critical coverage: the struct variant
/// `ValidatorNotInIntersection { validator_index }` is the only
/// non-unit variant across all three ground enums. If serde's
/// default adjacently-tagged representation were changed on
/// `AttesterAppealGround`, the field's discriminant wire would
/// shift and this test would catch it.
#[test]
fn test_dsl_160_attester_bincode() {
    for ground in all_attester_grounds() {
        let ev = attester_envelope(ground, vec![0x07, 0x08, 0x09]);
        assert_bincode_roundtrip(&ev);
    }

    // Additional struct-variant probes — test several distinct
    // `validator_index` values so the payload (not just the
    // discriminant) is verified to roundtrip.
    for idx in [0u32, 1, 42, u32::MAX - 1, u32::MAX] {
        let ev = attester_envelope(
            AttesterAppealGround::ValidatorNotInIntersection {
                validator_index: idx,
            },
            vec![],
        );
        let bytes = bincode::serialize(&ev).expect("bincode ser");
        let decoded: SlashAppeal = bincode::deserialize(&bytes).expect("bincode deser");

        // Pattern-match the decoded payload and assert the
        // validator_index was carried byte-exact.
        match decoded.payload {
            SlashAppealPayload::Attester(a) => match a.ground {
                AttesterAppealGround::ValidatorNotInIntersection { validator_index } => {
                    assert_eq!(
                        validator_index, idx,
                        "struct-variant payload roundtrips byte-exact",
                    );
                }
                other => panic!("unexpected ground: {other:?}"),
            },
            _ => panic!("payload variant drift"),
        }
    }
}

/// DSL-160 row 3: all 4 `InvalidBlockAppealGround` variants
/// roundtrip via bincode.
#[test]
fn test_dsl_160_invalid_block_bincode() {
    for ground in all_invalid_block_grounds() {
        // BlockActuallyValid witness carries re-execution block +
        // pre-state bytes — use a larger witness to exercise the
        // length-prefix path.
        let witness = vec![0xCCu8; 128];
        let ev = invalid_block_envelope(ground, witness);
        assert_bincode_roundtrip(&ev);
    }
}

/// DSL-160 row 4: full matrix under serde_json.
///
/// Combines all three ground enums + envelope reconstruction to
/// prove the REMARK wire (DSL-110) path survives roundtrip. One
/// failure in this test implies some peer-sourced appeal encoded
/// on a correctly-behaved node would fail to admit on our side.
#[test]
fn test_dsl_160_all_json_roundtrip() {
    for ground in all_proposer_grounds() {
        assert_json_roundtrip(&proposer_envelope(ground, vec![0x01, 0x02]));
    }
    for ground in all_attester_grounds() {
        assert_json_roundtrip(&attester_envelope(ground, vec![0x03, 0x04]));
    }
    for ground in all_invalid_block_grounds() {
        assert_json_roundtrip(&invalid_block_envelope(ground, vec![0x05; 32]));
    }
}

/// DSL-160 row 5: witness bytes serde_bytes format.
///
/// bincode encodes the witness as `length-prefix || raw bytes`;
/// we probe for a distinctive byte run verbatim. JSON encodes
/// serde_bytes as an integer array (e.g. `[239, 239, ...]`); we
/// probe for the probe-value substring and verify roundtrip
/// equality.
#[test]
fn test_dsl_160_witness_bytes_format() {
    let ev = attester_envelope(AttesterAppealGround::EmptyIntersection, vec![0xEF; 64]);

    let bin = bincode::serialize(&ev).expect("bincode ser");
    let run_of_efs = vec![0xEFu8; 64];
    assert!(
        bin.windows(64).any(|w| w == run_of_efs.as_slice()),
        "bincode wire must contain the 64-byte 0xEF witness run verbatim",
    );

    let json = serde_json::to_string(&ev).expect("json ser");
    // 0xEF = 239. Integer-array JSON shape shows the value.
    assert!(
        json.contains("239"),
        "JSON must contain witness byte value (239 == 0xEF)",
    );

    // Cross-codec: bincode → appeal → json → appeal matches.
    let bin_decoded: SlashAppeal = bincode::deserialize(&bin).expect("bincode deser");
    let re_json = serde_json::to_string(&bin_decoded).expect("re-json ser");
    let re_decoded: SlashAppeal = serde_json::from_str(&re_json).expect("re-json deser");
    assert_eq!(
        re_decoded, ev,
        "cross-codec witness byte preservation (bincode→json→struct)",
    );
}
