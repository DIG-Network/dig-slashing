//! Pending-slash book + lifecycle-state types.
//!
//! Traces to: [SPEC.md §3.8 + §7.1](../docs/resources/SPEC.md),
//! catalogue rows
//! [DSL-024](../docs/requirements/domains/lifecycle/specs/DSL-024.md),
//! [DSL-146](../docs/requirements/domains/lifecycle/specs/DSL-146.md),
//! [DSL-147](../docs/requirements/domains/lifecycle/specs/DSL-147.md),
//! [DSL-161](../docs/requirements/domains/).
//!
//! # Role
//!
//! Optimistic slashing is reversible during the 8-epoch appeal window
//! (`SLASH_APPEAL_WINDOW_EPOCHS`). The manager holds one
//! `PendingSlash` per admitted evidence until it transitions to
//! `Finalised` (DSL-029) or `Reverted` (DSL-070). The
//! [`PendingSlashBook`] provides the keyed storage + a secondary
//! by-window-expiry index for efficient `expired_by` scans at
//! finalisation.

use std::collections::{BTreeMap, HashMap};

use dig_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::error::SlashingError;
use crate::evidence::envelope::SlashingEvidence;
use crate::evidence::verify::VerifiedEvidence;
use crate::manager::PerValidatorSlash;

/// Lifecycle status of an admitted slash.
///
/// Traces to [SPEC §3.8](../../docs/resources/SPEC.md). State machine:
///
/// ```text
///   Accepted ──(first appeal)──►  ChallengeOpen
///      │                              │
///      ├──(window expires, no sustained appeal)──► Finalised
///      │                              │
///      └────────(sustained appeal)────► Reverted
/// ```
///
/// `Accepted` is the starting state on admission (DSL-024).
/// `ChallengeOpen` tracks appeal attempts (DSL-072). `Finalised`
/// locks the slash in (DSL-029..032). `Reverted` undoes it
/// (DSL-064..067).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PendingSlashStatus {
    /// No appeals filed yet. Transitions to `ChallengeOpen` on first
    /// appeal, `Finalised` on window expiry.
    Accepted,
    /// At least one appeal has been filed; the window may still be
    /// open and further appeals may arrive up to
    /// `MAX_APPEAL_ATTEMPTS_PER_SLASH`.
    ChallengeOpen {
        /// Epoch the FIRST appeal was filed.
        first_appeal_filed_epoch: u64,
        /// Number of appeals filed so far.
        appeal_count: u8,
    },
    /// Sustained appeal — slash was rolled back via `credit_stake`
    /// (DSL-064). Terminal.
    Reverted {
        /// Hash of the winning appeal.
        winning_appeal_hash: Bytes32,
        /// Epoch the reversal was applied.
        reverted_at_epoch: u64,
    },
    /// No sustained appeal within the window. Correlation penalty
    /// applied, exit lock scheduled. Terminal.
    Finalised {
        /// Epoch the finalisation ran.
        finalised_at_epoch: u64,
    },
}

/// Adjudication outcome for an individual appeal attempt.
///
/// Traces to [SPEC §3.8](../../docs/resources/SPEC.md).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum AppealOutcome {
    /// Appeal sustained → slash reverted. DSL-064..070.
    Won,
    /// Appeal rejected → slash persists. `reason_hash` summarises the
    /// adjudicator's decision for downstream analytics / audit.
    Lost {
        /// Hash of the adjudication reason bytes.
        reason_hash: Bytes32,
    },
    /// Appeal filed but adjudication not yet run (manager sees it in
    /// this state only within a single run_epoch_boundary transaction).
    Pending,
}

/// One appeal attempt attached to a `PendingSlash`.
///
/// Traces to [SPEC §3.8](../../docs/resources/SPEC.md).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppealAttempt {
    /// Hash of the appeal envelope (SPEC §3.7).
    pub appeal_hash: Bytes32,
    /// Validator index of the appellant.
    pub appellant_index: u32,
    /// Epoch the appeal was filed.
    pub filed_epoch: u64,
    /// Adjudication outcome.
    pub outcome: AppealOutcome,
    /// Appellant bond mojos locked for this attempt.
    pub bond_mojos: u64,
}

/// A slash record held in the pending book during its appeal window.
///
/// Traces to [SPEC §3.8](../../docs/resources/SPEC.md). One
/// `PendingSlash` per admitted evidence hash; key uniquity enforced
/// by the manager's `processed` map (DSL-026).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingSlash {
    /// Content-addressed identity of the evidence envelope —
    /// matches `evidence.hash()`. Serves as the book's primary key.
    pub evidence_hash: Bytes32,
    /// Full evidence envelope. Retained so appeal adjudication
    /// (DSL-064..067) has the raw bytes without a separate store.
    pub evidence: SlashingEvidence,
    /// Verifier output captured at admission. Replaying
    /// `verify_evidence` is unnecessary.
    pub verified: VerifiedEvidence,
    /// Current lifecycle state.
    pub status: PendingSlashStatus,
    /// Epoch `submit_evidence` admitted the record — `self.current_epoch`
    /// at insertion.
    pub submitted_at_epoch: u64,
    /// Epoch after which the slash finalises if no sustained appeal
    /// arrives. Equals `submitted_at_epoch + SLASH_APPEAL_WINDOW_EPOCHS`
    /// (DSL-024).
    pub window_expires_at_epoch: u64,
    /// Per-validator debits applied at admission (DSL-022). Each
    /// entry is reversible on a sustained appeal (DSL-064 credits
    /// `base_slash_amount` back).
    pub base_slash_per_validator: Vec<PerValidatorSlash>,
    /// Reporter bond escrowed at admission (DSL-023). Returned on
    /// finalisation (DSL-031) or forfeited on sustained appeal (DSL-068).
    pub reporter_bond_mojos: u64,
    /// Appeals filed so far. Empty on admission.
    pub appeal_history: Vec<AppealAttempt>,
}

/// Keyed book of admitted pending slashes.
///
/// Traces to [SPEC §7.1](../../docs/resources/SPEC.md). Two-layer
/// index:
///
///   - `pending: HashMap<Bytes32, PendingSlash>` — primary keyed by
///     evidence hash.
///   - `by_window_expiry: BTreeMap<u64, Vec<Bytes32>>` — secondary,
///     drives the `expired_by(epoch)` scan at finalisation (DSL-029).
///
/// Capacity-bounded at `MAX_PENDING_SLASHES` (4_096); insert at
/// capacity returns `SlashingError::PendingBookFull` (DSL-027).
#[derive(Debug, Clone, Default)]
pub struct PendingSlashBook {
    pending: HashMap<Bytes32, PendingSlash>,
    by_window_expiry: BTreeMap<u64, Vec<Bytes32>>,
    capacity: usize,
}

impl PendingSlashBook {
    /// New book with the given capacity.
    ///
    /// Traces to [DSL-146](../../docs/requirements/domains/lifecycle/specs/DSL-146.md).
    /// Capacity of `0` is legal and produces a book that rejects
    /// every insert — useful for property tests of the full-book
    /// rejection branch.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            pending: HashMap::with_capacity(capacity.min(1_024)),
            by_window_expiry: BTreeMap::new(),
            capacity,
        }
    }

    /// Insert a new pending slash.
    ///
    /// Returns `Err(PendingBookFull)` at capacity (DSL-027). Does NOT
    /// check for duplicate keys — caller (the manager) must consult
    /// `processed` first (DSL-026).
    pub fn insert(&mut self, record: PendingSlash) -> Result<(), SlashingError> {
        if self.pending.len() >= self.capacity {
            return Err(SlashingError::PendingBookFull);
        }
        let hash = record.evidence_hash;
        let expiry = record.window_expires_at_epoch;
        self.pending.insert(hash, record);
        self.by_window_expiry.entry(expiry).or_default().push(hash);
        Ok(())
    }

    /// Immutable lookup by evidence hash.
    #[must_use]
    pub fn get(&self, hash: &Bytes32) -> Option<&PendingSlash> {
        self.pending.get(hash)
    }

    /// Mutable lookup — used by DSL-034..073 appeal code to update
    /// `status` + `appeal_history` in place.
    pub fn get_mut(&mut self, hash: &Bytes32) -> Option<&mut PendingSlash> {
        self.pending.get_mut(hash)
    }

    /// Remove by evidence hash. Returns the record and cleans up the
    /// secondary index.
    pub fn remove(&mut self, hash: &Bytes32) -> Option<PendingSlash> {
        let record = self.pending.remove(hash)?;
        if let Some(vec) = self
            .by_window_expiry
            .get_mut(&record.window_expires_at_epoch)
        {
            vec.retain(|h| h != hash);
            if vec.is_empty() {
                self.by_window_expiry
                    .remove(&record.window_expires_at_epoch);
            }
        }
        Some(record)
    }

    /// Hashes of every pending slash whose `submitted_at_epoch` is
    /// STRICTLY greater than `new_tip_epoch`. Used by DSL-129
    /// `SlashingManager::rewind_on_reorg` to enumerate the slashes
    /// that need to be rewound when the fork-choice tip moves
    /// backwards.
    ///
    /// Returns a `Vec<Bytes32>` rather than an iterator because
    /// the caller (`rewind_on_reorg`) then mutates `self.remove`
    /// on each entry, which would conflict with a live borrow.
    #[must_use]
    pub fn submitted_after(&self, new_tip_epoch: u64) -> Vec<Bytes32> {
        self.pending
            .values()
            .filter(|p| p.submitted_at_epoch > new_tip_epoch)
            .map(|p| p.evidence_hash)
            .collect()
    }

    /// Current record count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// `true` iff no records are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Book capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Evidence hashes with `window_expires_at_epoch < current_epoch`.
    ///
    /// Implements
    /// [DSL-147](../../docs/requirements/domains/lifecycle/specs/DSL-147.md).
    /// Drives the finalisation sweep at epoch boundary (DSL-029).
    /// Order is ascending by window_expiry — earliest-expiring first.
    #[must_use]
    pub fn expired_by(&self, current_epoch: u64) -> Vec<Bytes32> {
        self.by_window_expiry
            .range(..current_epoch)
            .flat_map(|(_, hashes)| hashes.iter().copied())
            .collect()
    }
}
