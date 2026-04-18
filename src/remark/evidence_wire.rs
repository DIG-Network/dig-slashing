//! Evidence REMARK wire: encoder + parser.
//!
//! Implements [DSL-102](../../docs/requirements/domains/remark/specs/DSL-102.md).
//! Traces to: [SPEC §16.1](../../docs/resources/SPEC.md).
//!
//! # Wire format
//!
//! ```text
//! payload = SLASH_EVIDENCE_REMARK_MAGIC_V1 || serde_json(SlashingEvidence)
//! ```
//!
//! The magic prefix (`b"DIG_SLASH_EVIDENCE_V1\0"`) namespaces our
//! payloads against foreign REMARK apps. The body is JSON — not
//! bincode — because downstream tooling (block explorers, auditors,
//! cross-client validators) benefits from a human-readable payload
//! that survives casual inspection. On-chain size overhead is
//! bounded by DSL-109's payload cap.
//!
//! # Parser policy
//!
//! Consensus hands us every REMARK payload it saw in a block's
//! spends; most of those payloads belong to unrelated apps. We
//! MUST silently skip (not error) on:
//!
//!   - payload shorter than the magic prefix,
//!   - payload with the wrong magic,
//!   - payload with valid magic but malformed JSON after the prefix,
//!   - payload with valid magic + valid JSON but of the wrong type.
//!
//! Returning an error on any of these would make the parser
//! unusable in production: a single foreign REMARK in a block
//! would poison every valid slashing submission alongside it.

use crate::SLASH_EVIDENCE_REMARK_MAGIC_V1;
use crate::evidence::SlashingEvidence;

/// Encode a `SlashingEvidence` as a REMARK payload.
///
/// Returns `MAGIC || serde_json(ev)` as a single contiguous
/// byte vector ready to be embedded into a CLVM `REMARK`
/// condition.
///
/// # Errors
///
/// Propagates any `serde_json` serialisation error. In practice
/// `SlashingEvidence` is serde-safe by construction (every field
/// derives `Serialize`), so this only fires if `serde_json`'s own
/// buffer allocation fails — which is a fatal process-level
/// condition, not a recoverable input issue.
pub fn encode_slashing_evidence_remark_payload_v1(
    ev: &SlashingEvidence,
) -> serde_json::Result<Vec<u8>> {
    let body = serde_json::to_vec(ev)?;
    let mut out = Vec::with_capacity(SLASH_EVIDENCE_REMARK_MAGIC_V1.len() + body.len());
    out.extend_from_slice(SLASH_EVIDENCE_REMARK_MAGIC_V1);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Extract every valid `SlashingEvidence` from a slice of REMARK
/// payloads.
///
/// The input typically comes from the consensus layer's scan of a
/// block's spends: every REMARK condition's byte payload in input
/// order. This parser is order-preserving and silent-skip: any
/// payload whose prefix does not match `SLASH_EVIDENCE_REMARK_MAGIC_V1`,
/// or whose post-prefix bytes do not deserialise as a
/// `SlashingEvidence`, is dropped on the floor. Foreign REMARK
/// payloads never raise.
///
/// # Complexity
///
/// O(total_bytes) — we iterate each payload once and pass the
/// post-prefix slice directly to `serde_json::from_slice` (no
/// intermediate allocation).
pub fn parse_slashing_evidence_from_conditions<P>(payloads: &[P]) -> Vec<SlashingEvidence>
where
    P: AsRef<[u8]>,
{
    let magic = SLASH_EVIDENCE_REMARK_MAGIC_V1;
    let mut out = Vec::new();

    for payload in payloads {
        let bytes = payload.as_ref();
        // Short or wrong-prefix: silently skip. We use a strict
        // prefix compare (not a magic-string scan) because the
        // magic MUST land at byte 0 — otherwise an attacker could
        // sneak an evidence payload into the middle of a foreign
        // REMARK and attempt admission.
        let Some(body) = bytes.strip_prefix(magic) else {
            continue;
        };
        // Malformed JSON or wrong-type JSON: silently skip.
        // serde_json returns an error for both cases and we
        // collapse them into the same silent-skip policy — the
        // admission layer has no use for a "tried but failed"
        // diagnostic per payload.
        if let Ok(ev) = serde_json::from_slice::<SlashingEvidence>(body) {
            out.push(ev);
        }
    }

    out
}
