//! `AttesterSlashing` — pair of conflicting attestations plus the helper
//! that extracts the slashable-validator set.
//!
//! Traces to: [SPEC.md §3.4](../../docs/resources/SPEC.md), catalogue row
//! [DSL-007](../../docs/requirements/domains/evidence/specs/DSL-007.md).
//!
//! # Role
//!
//! Carries two `IndexedAttestation`s that are slashably conflicting under
//! either the double-vote (DSL-014) or surround-vote (DSL-015) predicate.
//! `slashable_indices()` returns the validator indices that signed BOTH —
//! this is the per-validator fan-out consumed by the slash loop in
//! `SlashingManager::submit_evidence` (DSL-022).
//!
//! # Preconditions for the helper
//!
//! Both `attesting_indices` MUST be strictly ascending and deduped —
//! the contract `IndexedAttestation::validate_structure` (DSL-005)
//! enforces. Callers invoke that guard FIRST; if structure is valid,
//! `slashable_indices` is sound. If structure is malformed, the output
//! is still deterministic but may not equal the set-theoretic intersection.
//!
//! # Why a two-pointer sweep
//!
//! `Vec<u32>` is already sorted ascending by precondition, so O(n+m)
//! two-pointer walks beat `HashSet::intersection` (O(n+m) with hashing
//! overhead + non-deterministic iteration order) and `retain` (O(n·m)).

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

use crate::evidence::indexed_attestation::IndexedAttestation;

/// A pair of conflicting indexed attestations.
///
/// Per [SPEC §3.4](../../docs/resources/SPEC.md). The two halves are
/// `PartialEq`/`Eq` so higher-level code can detect the degenerate case
/// where both attestations are byte-identical (appeal ground
/// [DSL-041](../../../../docs/requirements/domains/appeal/specs/DSL-041.md)).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttesterSlashing {
    /// First attestation — arbitrary ordering; `slashable_indices` is
    /// symmetric.
    pub attestation_a: IndexedAttestation,
    /// Second attestation.
    pub attestation_b: IndexedAttestation,
}

impl AttesterSlashing {
    /// Sorted, deduped intersection of the two attestations'
    /// `attesting_indices`.
    ///
    /// Implements [DSL-007](../../docs/requirements/domains/evidence/specs/DSL-007.md).
    /// Traces to SPEC §3.4.
    ///
    /// # Algorithm
    ///
    /// Two-pointer sweep. Assumes both index lists are already strictly
    /// ascending (precondition established by
    /// `IndexedAttestation::validate_structure`, DSL-005). For each
    /// comparison:
    ///
    /// - **Equal** → emit to output, advance both pointers.
    /// - **Less (`a[i] < b[j]`)** → advance `i`; `a[i]` cannot appear in `b`
    ///   at or beyond `b[j]` (b is ascending, so smaller values cannot
    ///   appear later).
    /// - **Greater** → advance `j` for the mirror reason.
    ///
    /// O(n+m) comparisons, O(min(n,m)) output allocation.
    ///
    /// # Returns
    ///
    /// A strictly ascending `Vec<u32>` containing every validator index
    /// that signed BOTH attestations. Disjoint inputs return `vec![]`.
    ///
    /// # Determinism
    ///
    /// Pure function of inputs. No hashing, no shared state, no iterator
    /// with implementation-defined order. Repeated calls on the same
    /// receiver return byte-equal results (enforced by
    /// `test_dsl_007_deterministic`).
    ///
    /// # Downstream
    ///
    /// - `verify_attester_slashing` (DSL-016) rejects an empty result as
    ///   `SlashingError::EmptySlashableIntersection`.
    /// - `SlashingManager::submit_evidence` (DSL-022) iterates the result
    ///   and invokes the base-slash debit per validator.
    pub fn slashable_indices(&self) -> Vec<u32> {
        let a = &self.attestation_a.attesting_indices;
        let b = &self.attestation_b.attesting_indices;
        let mut out: Vec<u32> = Vec::new();
        let (mut i, mut j) = (0usize, 0usize);
        while i < a.len() && j < b.len() {
            match a[i].cmp(&b[j]) {
                Ordering::Equal => {
                    out.push(a[i]);
                    i += 1;
                    j += 1;
                }
                Ordering::Less => i += 1,
                Ordering::Greater => j += 1,
            }
        }
        out
    }
}
