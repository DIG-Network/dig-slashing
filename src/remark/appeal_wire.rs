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

use clvmr::Allocator;
use clvmr::serde::node_to_bytes;
use dig_protocol::Bytes32;

use crate::SLASH_APPEAL_REMARK_MAGIC_V1;
use crate::appeal::envelope::SlashAppeal;
use crate::error::SlashingError;

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

/// CLVM puzzle reveal emitting exactly one `REMARK` condition
/// carrying the DSL-110 encoded appeal payload.
///
/// Implements [DSL-111](../../docs/requirements/domains/remark/specs/DSL-111.md).
/// Appeal-side analogue of
/// [`slashing_evidence_remark_puzzle_reveal_v1`] — same
/// constant-returning quote shape `(q . ((1 payload)))`, same
/// commit-at-creation-time semantics, different payload source.
///
/// # Errors
///
/// - [`SlashingError::InvalidSlashingEvidence`] wrapping the
///   serde / CLVM allocator failure. Kept unified with the
///   evidence-side error for caller simplicity — the distinction
///   between "evidence encode failure" and "appeal encode
///   failure" is diagnostic-only.
pub fn slash_appeal_remark_puzzle_reveal_v1(ap: &SlashAppeal) -> Result<Vec<u8>, SlashingError> {
    let wire = encode_slash_appeal_remark_payload_v1(ap)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("encode: {e}")))?;

    let mut allocator = Allocator::new();

    let payload_atom = allocator
        .new_atom(&wire)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("new_atom: {e}")))?;

    let nil = allocator.nil();

    let tail = allocator
        .new_pair(payload_atom, nil)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("new_pair tail: {e}")))?;

    let opcode = allocator
        .new_small_number(1)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("new_small_number: {e}")))?;

    let condition = allocator
        .new_pair(opcode, tail)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("new_pair cond: {e}")))?;

    let condition_list = allocator
        .new_pair(condition, nil)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("new_pair list: {e}")))?;

    let puzzle = allocator
        .new_pair(opcode, condition_list)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("new_pair puzzle: {e}")))?;

    node_to_bytes(&allocator, puzzle)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("node_to_bytes: {e}")))
}

/// `tree_hash` of the appeal REMARK puzzle reveal.
///
/// Implements [DSL-111](../../docs/requirements/domains/remark/specs/DSL-111.md).
/// Returned `Bytes32` is the coin's `puzzle_hash` for the
/// appellant spend admitted on-chain (DSL-112).
///
/// Deterministic for the same reasons as DSL-103 (serde_json on
/// non-HashMap fields + fixed CLVM structure).
pub fn slash_appeal_remark_puzzle_hash_v1(ap: &SlashAppeal) -> Result<Bytes32, SlashingError> {
    let reveal = slash_appeal_remark_puzzle_reveal_v1(ap)?;
    let hash = clvm_utils::tree_hash_from_bytes(&reveal)
        .map_err(|e| SlashingError::InvalidSlashingEvidence(format!("tree_hash: {e}")))?;
    Ok(hash.into())
}
