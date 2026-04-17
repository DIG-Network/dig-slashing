//! `IndexedAttestation` — aggregate-signed committee attestation.
//!
//! Traces to: [SPEC.md §3.3](../../docs/resources/SPEC.md), catalogue row
//! [DSL-005](../../docs/requirements/domains/evidence/specs/DSL-005.md).
//!
//! # Role
//!
//! Wraps an [`AttestationData`] with the list of validator indices that
//! BLS-aggregate-signed it. Used by `AttesterSlashing` (DSL-007) — the
//! intersection of two IndexedAttestations' indices is the set of
//! validators caught in a double-vote or surround-vote.
//!
//! # Two guards
//!
//! - [`validate_structure`](IndexedAttestation::validate_structure) — cheap
//!   pre-flight: empty/over-cap/non-ascending-or-duplicate/bad-sig-width.
//!   Callers run this BEFORE the expensive aggregate verify. DSL-005.
//! - `verify_signature` — expensive aggregate BLS verify over the signing
//!   root. DSL-006 (not yet implemented).
//!
//! Ordering matters: `slashable_indices` (DSL-007) assumes ascending+deduped
//! input, so the structural guard anchors the soundness of the intersection
//! math.

use serde::{Deserialize, Serialize};

use crate::constants::{BLS_SIGNATURE_SIZE, MAX_VALIDATORS_PER_COMMITTEE};
use crate::error::SlashingError;
use crate::evidence::attestation_data::AttestationData;

/// Aggregate-signed attestation from a committee.
///
/// Per [SPEC §3.3](../../docs/resources/SPEC.md). `attesting_indices` MUST
/// be strictly ascending with no duplicates (enforced by
/// [`IndexedAttestation::validate_structure`]); `signature` MUST be a
/// 96-byte compressed BLS G2 aggregate.
///
/// # Wire shape
///
/// `signature` uses `serde_bytes` so the JSON encoding is a compact byte
/// string rather than `[u8; 96]` expanded to 96 JSON numbers. Keeps the
/// REMARK payload small (see DSL-102, DSL-110).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexedAttestation {
    /// Validator indices of every committee member that signed.
    /// MUST be strictly ascending and contain no duplicates.
    pub attesting_indices: Vec<u32>,

    /// Signed payload.
    pub data: AttestationData,

    /// Aggregate BLS G2 signature over `data.signing_root(network_id)`.
    /// MUST be exactly [`BLS_SIGNATURE_SIZE`] (96) bytes.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Hash-reference to check equality of the whole payload including sig bytes.
///
/// `Hash` is NOT derived automatically because `Vec<u8>` does derive it,
/// but we want to force callers to think about key usage — an
/// IndexedAttestation is large and an odd hashmap key. Derive it on demand
/// (at a later DSL) if a real use case appears.
// Intentionally not deriving Hash.
impl IndexedAttestation {
    /// Cheap structural guard.
    ///
    /// Implements [DSL-005](../../docs/requirements/domains/evidence/specs/DSL-005.md).
    /// Traces to SPEC §3.3 + §2.7.
    ///
    /// # Rejects (all return `Err(SlashingError::InvalidIndexedAttestation(reason))`)
    ///
    /// - **Empty** `attesting_indices`: committee with no signers is
    ///   meaningless; aggregate verify would trivially succeed on the
    ///   identity signature against an empty set.
    /// - **Over cap**: `len() > MAX_VALIDATORS_PER_COMMITTEE` (2_048).
    ///   Bounds memory + aggregate-verify cost per attestation.
    /// - **Bad signature width**: `signature.len() != BLS_SIGNATURE_SIZE`
    ///   (96). Exact equality — any other width is protocol-level malformed.
    /// - **Non-ascending or duplicate**: any consecutive pair `(a, b)` with
    ///   `a >= b`. Anchors the intersection math in `slashable_indices`
    ///   (DSL-007) which assumes ascending+deduped input.
    ///
    /// # Accepts
    ///
    /// Exactly at the cap (`len() == MAX_VALIDATORS_PER_COMMITTEE`) is
    /// valid — the check uses `>`, not `>=`.
    ///
    /// # Returns
    ///
    /// `Ok(())` on a well-formed structure. Every failure is a
    /// [`SlashingError::InvalidIndexedAttestation`] whose reason string
    /// names the specific violation.
    ///
    /// # Ordering with signature verify
    ///
    /// This function runs cheap checks only — no BLS pairings, no
    /// hashing of committee pubkeys. Callers (notably
    /// `verify_attester_slashing`, DSL-014/015) MUST run
    /// `validate_structure` first and short-circuit on error before
    /// invoking the expensive `verify_signature` (DSL-006).
    pub fn validate_structure(&self) -> Result<(), SlashingError> {
        if self.attesting_indices.is_empty() {
            return Err(SlashingError::InvalidIndexedAttestation(
                "empty attesting indices".into(),
            ));
        }
        if self.attesting_indices.len() > MAX_VALIDATORS_PER_COMMITTEE {
            return Err(SlashingError::InvalidIndexedAttestation(format!(
                "attesting indices length {} exceeds MAX_VALIDATORS_PER_COMMITTEE ({})",
                self.attesting_indices.len(),
                MAX_VALIDATORS_PER_COMMITTEE,
            )));
        }
        if self.signature.len() != BLS_SIGNATURE_SIZE {
            return Err(SlashingError::InvalidIndexedAttestation(format!(
                "signature width {} != BLS_SIGNATURE_SIZE ({})",
                self.signature.len(),
                BLS_SIGNATURE_SIZE,
            )));
        }
        for w in self.attesting_indices.windows(2) {
            // `a >= b` catches both non-ascending (`a > b`) AND duplicates
            // (`a == b`) in a single comparison. Keeps the reason string
            // honest about both failure modes.
            if w[0] >= w[1] {
                return Err(SlashingError::InvalidIndexedAttestation(
                    "attesting indices not strictly ascending (non-ascending or duplicate)".into(),
                ));
            }
        }
        Ok(())
    }
}
