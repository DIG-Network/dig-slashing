//! Requirement DSL-102: evidence REMARK wire encoding.
//!
//! Encode: `SLASH_EVIDENCE_REMARK_MAGIC_V1 || serde_json(SlashingEvidence)`.
//! Parse: strip the magic prefix, `serde_json` decode, skip
//! payloads with the wrong prefix or malformed JSON.
//!
//! Traces to: docs/resources/SPEC.md §16.1, §22.12.
//!
//! # Role
//!
//! Opens Phase 6 REMARK Admission. Evidence is submitted on-chain
//! as a CLVM `REMARK` condition whose payload carries the
//! serialised `SlashingEvidence`. Consensus code reads condition
//! lists from spends, hands this module any REMARK payloads it
//! sees, and gets back the evidences that parse — ignoring every
//! byte string that does not start with our magic prefix (which
//! would otherwise be noise from unrelated DSL apps sharing the
//! REMARK namespace).
//!
//! The magic prefix `b"DIG_SLASH_EVIDENCE_V1\0"` (SPEC §4) is
//! 22 bytes of namespacing + version. The trailing NUL lets the
//! prefix be pattern-matched exactly; embedding a version here
//! means any future v2 format can coexist on-chain.
//!
//! # Test matrix (maps to DSL-102 Test Plan + acceptance criteria)
//!
//!   1. `test_dsl_102_roundtrip` — encode(ev) then parse yields
//!      back `ev` byte-exact (PartialEq across the whole enum)
//!   2. `test_dsl_102_magic_prefix` — encoded payload starts
//!      with SLASH_EVIDENCE_REMARK_MAGIC_V1
//!   3. `test_dsl_102_non_magic_skipped` — random-prefix payload
//!      produces NO evidence (parser is silent-skip, not error)
//!   4. `test_dsl_102_malformed_json_skipped` — magic prefix +
//!      garbage payload → also silent skip (acceptance bullet 4)
//!   5. `test_dsl_102_mixed_conditions` — interleaved valid +
//!      invalid payloads → parser returns only the valid ones
//!      (proves the "keep scanning" semantics)

use dig_block::L2BlockHeader;
use dig_protocol::Bytes32;
use dig_slashing::{
    BLS_SIGNATURE_SIZE, OffenseType, ProposerSlashing, SLASH_EVIDENCE_REMARK_MAGIC_V1,
    SignedBlockHeader, SlashingEvidence, SlashingEvidencePayload,
    encode_slashing_evidence_remark_payload_v1, parse_slashing_evidence_from_conditions,
};

/// Canonical L2 block header used by the fixture slashings.
fn sample_header(state_byte: u8) -> L2BlockHeader {
    L2BlockHeader::new(
        100,
        3,
        Bytes32::new([0x01u8; 32]),
        Bytes32::new([state_byte; 32]),
        Bytes32::new([0x03u8; 32]),
        Bytes32::new([0x04u8; 32]),
        Bytes32::new([0x05u8; 32]),
        Bytes32::new([0x06u8; 32]),
        42,
        Bytes32::new([0x07u8; 32]),
        9,
        1,
        1_000,
        10,
        5,
        3,
        512,
        Bytes32::new([0x08u8; 32]),
    )
}

/// Build a minimal `ProposerSlashing` fixture. Two headers at the
/// same slot with different state roots is the canonical proposer-
/// equivocation shape. Signatures are zeroed — this test exercises
/// wire encoding only, not verification.
fn fixture_proposer_slashing() -> ProposerSlashing {
    ProposerSlashing {
        signed_header_a: SignedBlockHeader {
            message: sample_header(0x02),
            signature: vec![0u8; BLS_SIGNATURE_SIZE],
        },
        signed_header_b: SignedBlockHeader {
            message: sample_header(0x99),
            signature: vec![0u8; BLS_SIGNATURE_SIZE],
        },
    }
}

fn fixture_evidence() -> SlashingEvidence {
    SlashingEvidence {
        offense_type: OffenseType::ProposerEquivocation,
        epoch: 12,
        reporter_validator_index: 11,
        reporter_puzzle_hash: Bytes32::new([0xEEu8; 32]),
        payload: SlashingEvidencePayload::Proposer(fixture_proposer_slashing()),
    }
}

/// DSL-102 row 1: encode + parse round-trip.
///
/// The parser accepts a slice of REMARK payloads (as the consensus
/// layer would provide after extracting REMARK conditions from a
/// spend). We wrap the single encoded payload in a one-element
/// slice here to exercise the slice-taking contract.
#[test]
fn test_dsl_102_roundtrip() {
    let ev = fixture_evidence();

    let wire = encode_slashing_evidence_remark_payload_v1(&ev).expect("encode");
    let parsed = parse_slashing_evidence_from_conditions(&[wire]);

    assert_eq!(parsed.len(), 1, "one valid payload → one evidence");
    assert_eq!(parsed[0], ev, "round-trip must preserve every field");
}

/// DSL-102 row 2: the encoded payload starts with the magic prefix.
/// Pin the exact byte value so any future change to the magic must
/// be intentional (and breaks this test).
#[test]
fn test_dsl_102_magic_prefix() {
    let ev = fixture_evidence();
    let wire = encode_slashing_evidence_remark_payload_v1(&ev).unwrap();

    assert!(
        wire.starts_with(SLASH_EVIDENCE_REMARK_MAGIC_V1),
        "payload must be MAGIC || json; got prefix {:?}",
        &wire[..SLASH_EVIDENCE_REMARK_MAGIC_V1.len().min(wire.len())],
    );
    assert_eq!(
        SLASH_EVIDENCE_REMARK_MAGIC_V1, b"DIG_SLASH_EVIDENCE_V1\0",
        "magic constant must match SPEC §4 exactly",
    );
    assert!(
        wire.len() > SLASH_EVIDENCE_REMARK_MAGIC_V1.len(),
        "payload must carry more than just the prefix",
    );
}

/// DSL-102 row 3: a random (non-magic) prefix is silently skipped,
/// NOT an error. Many REMARK apps share the on-chain namespace;
/// returning an error on every foreign payload would make the
/// parser unusable. Proves acceptance bullet 3.
#[test]
fn test_dsl_102_non_magic_skipped() {
    let foreign: Vec<u8> = b"SOME_OTHER_APP_V1\0{}".to_vec();
    let parsed = parse_slashing_evidence_from_conditions(&[foreign]);
    assert!(
        parsed.is_empty(),
        "foreign REMARK payloads must be silently skipped",
    );

    // Pathological cases: empty slice, and a payload shorter than
    // the magic prefix. Must both skip cleanly without panicking
    // on arithmetic.
    let empty: Vec<u8> = Vec::new();
    let short: Vec<u8> = b"DIG_".to_vec();
    let parsed = parse_slashing_evidence_from_conditions(&[empty, short]);
    assert!(parsed.is_empty(), "empty/short payloads must skip cleanly");
}

/// DSL-102 row 4 (acceptance bullet 4): magic prefix present but
/// the post-prefix bytes are not valid JSON / not a SlashingEvidence
/// → skip. We never want a malformed payload to crash the parser or
/// produce a garbage evidence that later verifier code has to
/// defend against.
#[test]
fn test_dsl_102_malformed_json_skipped() {
    let mut bad = SLASH_EVIDENCE_REMARK_MAGIC_V1.to_vec();
    bad.extend_from_slice(b"this is not json");

    let parsed = parse_slashing_evidence_from_conditions(&[bad]);
    assert!(parsed.is_empty(), "malformed-JSON payload must skip");

    // Magic + valid JSON but WRONG schema (a `u32` where a
    // SlashingEvidence is expected) also skips.
    let mut wrong_schema = SLASH_EVIDENCE_REMARK_MAGIC_V1.to_vec();
    wrong_schema.extend_from_slice(b"123");
    let parsed = parse_slashing_evidence_from_conditions(&[wrong_schema]);
    assert!(
        parsed.is_empty(),
        "JSON that decodes as the wrong type must skip, not surface",
    );
}

/// Bonus coverage: a mix of valid + invalid payloads in a single
/// condition list. Parser returns ONLY the valid ones, in input
/// order — which is what the admission layer needs when processing
/// a block's REMARKs.
#[test]
fn test_dsl_102_mixed_conditions() {
    let ev_a = fixture_evidence();
    let mut ev_b = fixture_evidence();
    ev_b.reporter_validator_index = 22;
    ev_b.epoch = 50;
    if let SlashingEvidencePayload::Proposer(ref mut ps) = ev_b.payload {
        ps.signed_header_a.message = sample_header(0x11);
        ps.signed_header_b.message = sample_header(0x22);
    }

    let wire_a = encode_slashing_evidence_remark_payload_v1(&ev_a).unwrap();
    let wire_b = encode_slashing_evidence_remark_payload_v1(&ev_b).unwrap();
    let foreign: Vec<u8> = b"SOMETHING_ELSE\0".to_vec();

    let conditions = vec![wire_a, foreign, wire_b];
    let parsed = parse_slashing_evidence_from_conditions(&conditions);

    assert_eq!(parsed.len(), 2, "two valid + one foreign → two evidences");
    assert_eq!(
        parsed[0], ev_a,
        "order preserved: valid-then-skip-then-valid"
    );
    assert_eq!(parsed[1], ev_b);
}
