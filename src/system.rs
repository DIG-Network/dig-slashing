//! `SlashingSystem` genesis bootstrap.
//!
//! Traces to: [SPEC §11](../docs/resources/SPEC.md).
//!
//! # Role
//!
//! Bundles the three long-lived state trackers
//! (`SlashingManager`, `ParticipationTracker`,
//! `InactivityScoreTracker`) into one aggregate that the
//! embedder can construct via [`SlashingSystem::genesis`] at
//! chain birth and step forward via [`crate::run_epoch_boundary`]
//! at every epoch boundary.
//!
//! The three sub-components are independently useful (tests in
//! earlier phases construct them directly), so this aggregate is
//! intentionally a thin wrapper — it owns zero logic beyond the
//! constructor.

use dig_protocol::Bytes32;

use crate::inactivity::InactivityScoreTracker;
use crate::manager::SlashingManager;
use crate::participation::ParticipationTracker;

/// Parameters required at chain genesis to initialise the
/// slashing system.
///
/// `network_id` is carried for future domain-separation /
/// signature-binding work (currently unused by `genesis` itself
/// but required by embedders who persist the aggregate across
/// chain forks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisParameters {
    /// Epoch the chain starts at. Typically `0`; non-zero only
    /// for test-fixtures or sidechains forked from a live chain.
    pub genesis_epoch: u64,
    /// Number of validators present at genesis. Drives
    /// tracker sizing; subsequent validator-set changes go
    /// through DSL-127's step-7 resize.
    pub initial_validator_count: usize,
    /// Network identifier. Reserved for downstream
    /// domain-separated signatures; not consulted by `genesis`
    /// itself.
    pub network_id: Bytes32,
}

/// Aggregate of the three long-lived slashing-state trackers
/// an embedder carries across blocks.
///
/// Each field is independently exported by the crate; the
/// aggregate exists only to give embedders a single struct to
/// serialise / snapshot / pass into `run_epoch_boundary`.
///
/// # `network_id`
///
/// Stored privately under DSL-170. The accessor
/// [`SlashingSystem::network_id`] returns a borrow. Consumed by
/// downstream admission flows (DSL-168
/// `process_block_admissions`) that need domain-separated
/// signature verification without requiring every embedder call
/// site to thread `network_id` through its arg list.
#[derive(Debug)]
pub struct SlashingSystem {
    pub manager: SlashingManager,
    pub participation: ParticipationTracker,
    pub inactivity: InactivityScoreTracker,
    /// Network identifier captured at genesis. See DSL-170 for
    /// the rationale for carrying this on the aggregate rather
    /// than reconstructing it per call.
    network_id: Bytes32,
}

impl SlashingSystem {
    /// Construct the at-genesis state per SPEC §11.
    ///
    /// Implements [DSL-128](../docs/requirements/domains/orchestration/specs/DSL-128.md).
    ///
    /// # Post-conditions
    ///
    ///   - `manager.processed.is_empty()` and
    ///     `manager.book().is_empty()` — no slashes yet.
    ///   - `manager.current_epoch() == params.genesis_epoch`.
    ///   - `participation.current_epoch_number() == params.genesis_epoch`
    ///     and both the previous- and current-epoch flag
    ///     vectors are zero-initialised with
    ///     `initial_validator_count` entries.
    ///   - `inactivity.validator_count() == initial_validator_count`
    ///     and every score is `0`.
    ///   - `network_id()` returns the exact `params.network_id`
    ///     (DSL-170).
    #[must_use]
    pub fn genesis(params: &GenesisParameters) -> Self {
        Self {
            manager: SlashingManager::new(params.genesis_epoch),
            participation: ParticipationTracker::new(
                params.initial_validator_count,
                params.genesis_epoch,
            ),
            inactivity: InactivityScoreTracker::new(params.initial_validator_count),
            network_id: params.network_id,
        }
    }

    /// Network identifier captured at genesis.
    ///
    /// Implements [DSL-170](../docs/requirements/domains/orchestration/specs/DSL-170.md).
    /// Traces to SPEC §11.
    ///
    /// # Lifetime
    ///
    /// Returns `&Bytes32` borrowed from `&self`. Callers that need
    /// an owned value copy by `*system.network_id()` — `Bytes32`
    /// is a fixed-width byte wrapper that implements `Copy`.
    ///
    /// # Consumers
    ///
    /// - DSL-168 `process_block_admissions` reads this so the
    ///   admission pipeline can reconstruct signing-message
    ///   domain-separated digests without a per-call arg.
    /// - Embedders persisting the aggregate across chain forks
    ///   use this to detect cross-fork replay at load time.
    #[must_use]
    pub fn network_id(&self) -> &Bytes32 {
        &self.network_id
    }
}
