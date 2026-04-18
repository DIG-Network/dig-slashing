//! Requirement DSL-110: appeal REMARK wire encoding.
//!
//! Encode: `SLASH_APPEAL_REMARK_MAGIC_V1 || serde_json(SlashAppeal)`.
//! Parse: strip magic, serde_json decode, silent-skip on wrong
//! prefix / malformed body.
//!
//! Traces to: docs/resources/SPEC.md §16.2, §22.13.
//!
//! # Role
//!
//! Opens the appeal-side REMARK block (DSL-110..120), mirroring
//! DSL-102 on the evidence side. Separate magic prefix
//! `b"DIG_SLASH_APPEAL_V1\0"` ensures a foreign REMARK cannot be
//! reinterpreted across categories even if its JSON body would
//! deserialise as the wrong variant.
//!
//! # Test matrix (maps to DSL-110 Test Plan + acceptance)
//!
//!   1. `test_dsl_110_roundtrip` — encode → parse yields back
//!      the original appeal byte-exact
//!   2. `test_dsl_110_magic_prefix_appeal` — encoded payload
//!      starts with `SLASH_APPEAL_REMARK_MAGIC_V1` and nothing
//!      else
//!   3. `test_dsl_110_non_magic_skipped` — random-prefix payload
//!      and evidence-prefix payload both produce NO appeals
//!      (cross-category isolation verified)
//!   4. `test_dsl_110_mixed_conditions` — interleaved valid +
//!      invalid payloads → parser returns only valid ones in
//!      input order

use dig_protocol::Bytes32;
use dig_slashing::{
    ProposerAppealGround, ProposerSlashingAppeal, SLASH_APPEAL_REMARK_MAGIC_V1,
    SLASH_EVIDENCE_REMARK_MAGIC_V1, SlashAppeal, SlashAppealPayload,
    encode_slash_appeal_remark_payload_v1, parse_slash_appeals_from_conditions,
};

fn fixture_appeal(appellant_idx: u32, filed_epoch: u64) -> SlashAppeal {
    SlashAppeal {
        evidence_hash: Bytes32::new([0x77u8; 32]),
        appellant_index: appellant_idx,
        appellant_puzzle_hash: Bytes32::new([0xAAu8; 32]),
        filed_epoch,
        payload: SlashAppealPayload::Proposer(ProposerSlashingAppeal {
            ground: ProposerAppealGround::HeadersIdentical,
            witness: vec![],
        }),
    }
}

/// DSL-110 row 1: encode + parse roundtrip preserves full
/// equality across the envelope + payload variant.
#[test]
fn test_dsl_110_roundtrip() {
    let ap = fixture_appeal(11, 42);

    let wire = encode_slash_appeal_remark_payload_v1(&ap).expect("encode");
    let parsed = parse_slash_appeals_from_conditions(&[wire]);

    assert_eq!(parsed.len(), 1, "one valid payload → one appeal");
    assert_eq!(parsed[0], ap, "round-trip must preserve every field");
}

/// DSL-110 row 2: magic prefix pinned exactly.
#[test]
fn test_dsl_110_magic_prefix_appeal() {
    let ap = fixture_appeal(11, 42);
    let wire = encode_slash_appeal_remark_payload_v1(&ap).unwrap();

    assert!(
        wire.starts_with(SLASH_APPEAL_REMARK_MAGIC_V1),
        "payload must start with appeal magic; got {:?}",
        &wire[..SLASH_APPEAL_REMARK_MAGIC_V1.len().min(wire.len())],
    );
    assert_eq!(
        SLASH_APPEAL_REMARK_MAGIC_V1, b"DIG_SLASH_APPEAL_V1\0",
        "magic constant must match SPEC §4",
    );
    // Cross-category isolation: appeal payload must NOT start
    // with the evidence magic.
    assert!(
        !wire.starts_with(SLASH_EVIDENCE_REMARK_MAGIC_V1),
        "appeal payload must not share prefix with evidence magic",
    );
}

/// DSL-110 row 3: foreign-prefix and evidence-prefix payloads
/// both skip cleanly. The latter proves category isolation — an
/// evidence REMARK sharing the same block must not spuriously
/// appear as an appeal.
#[test]
fn test_dsl_110_non_magic_skipped() {
    // Foreign prefix entirely.
    let foreign: Vec<u8> = b"SOMETHING_ELSE_V1\0{}".to_vec();
    assert!(parse_slash_appeals_from_conditions(&[foreign]).is_empty());

    // Evidence-magic payload — valid JSON for an evidence but
    // NOT an appeal. Must NOT surface under the appeal parser.
    let mut evidence_like = SLASH_EVIDENCE_REMARK_MAGIC_V1.to_vec();
    evidence_like.extend_from_slice(b"{}");
    assert!(
        parse_slash_appeals_from_conditions(&[evidence_like]).is_empty(),
        "evidence-magic payload must not be interpreted as appeal",
    );

    // Pathological short / empty payloads skip without panicking.
    let empty: Vec<u8> = Vec::new();
    let short: Vec<u8> = b"DIG_".to_vec();
    assert!(parse_slash_appeals_from_conditions(&[empty, short]).is_empty());

    // Magic + garbage JSON also skips.
    let mut bad = SLASH_APPEAL_REMARK_MAGIC_V1.to_vec();
    bad.extend_from_slice(b"not json");
    assert!(parse_slash_appeals_from_conditions(&[bad]).is_empty());
}

/// Bonus: interleaved valid + foreign payloads preserve input
/// order and drop foreign entries silently.
#[test]
fn test_dsl_110_mixed_conditions() {
    let ap_a = fixture_appeal(11, 5);
    let ap_b = fixture_appeal(22, 10);

    let wire_a = encode_slash_appeal_remark_payload_v1(&ap_a).unwrap();
    let wire_b = encode_slash_appeal_remark_payload_v1(&ap_b).unwrap();
    let foreign: Vec<u8> = b"OTHER_APP\0".to_vec();

    let conditions = vec![wire_a, foreign, wire_b];
    let parsed = parse_slash_appeals_from_conditions(&conditions);

    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0], ap_a, "order preserved: valid-foreign-valid");
    assert_eq!(parsed[1], ap_b);
}
