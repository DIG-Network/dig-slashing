//! Appeal REMARK wire: encoder + parser (appeal-side analogue of
//! [`crate::remark::evidence_wire`]).
//!
//! Implements [DSL-110](../../docs/requirements/domains/remark/specs/DSL-110.md).
//! Traces to: [SPEC §16.2](../../docs/resources/SPEC.md).
//!
//! # Wire format
//!
//! ```text
//! payload = SLASH_APPEAL_REMARK_MAGIC_V1 || serde_json(SlashAppeal)
//! ```
//!
//! Separate magic from the evidence side
//! (`SLASH_EVIDENCE_REMARK_MAGIC_V1`) so a foreign REMARK cannot
//! be re-interpreted as the other category even if its body
//! happens to be a valid JSON envelope for the wrong variant.
//!
//! # Parser policy
//!
//! Matches the DSL-102 evidence-side parser byte-for-byte:
//! silent-skip on short / foreign-prefix / malformed-JSON /
//! wrong-schema payloads. See that module's rationale — same
//! argument applies here.

use crate::SLASH_APPEAL_REMARK_MAGIC_V1;
use crate::appeal::envelope::SlashAppeal;

/// Encode a `SlashAppeal` as a REMARK payload.
///
/// Returns `MAGIC || serde_json(ap)` as a single contiguous byte
/// vector ready to be embedded into a CLVM `REMARK` condition on
/// the appellant's spend.
///
/// # Errors
///
/// Propagates any `serde_json` serialisation error. In practice
/// `SlashAppeal` is serde-safe by construction, so this only
/// fires on allocator failure.
pub fn encode_slash_appeal_remark_payload_v1(ap: &SlashAppeal) -> serde_json::Result<Vec<u8>> {
    let body = serde_json::to_vec(ap)?;
    let mut out = Vec::with_capacity(SLASH_APPEAL_REMARK_MAGIC_V1.len() + body.len());
    out.extend_from_slice(SLASH_APPEAL_REMARK_MAGIC_V1);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Extract every valid `SlashAppeal` from a slice of REMARK
/// payloads.
///
/// Input typically comes from the consensus layer's scan of a
/// block's spends: every REMARK condition's byte payload in input
/// order. Order-preserving, silent-skip — see
/// [`crate::remark::evidence_wire::parse_slashing_evidence_from_conditions`]
/// for the detailed rationale.
pub fn parse_slash_appeals_from_conditions<P>(payloads: &[P]) -> Vec<SlashAppeal>
where
    P: AsRef<[u8]>,
{
    let magic = SLASH_APPEAL_REMARK_MAGIC_V1;
    let mut out = Vec::new();
    for payload in payloads {
        let bytes = payload.as_ref();
        let Some(body) = bytes.strip_prefix(magic) else {
            continue;
        };
        if let Ok(ap) = serde_json::from_slice::<SlashAppeal>(body) {
            out.push(ap);
        }
    }
    out
}
