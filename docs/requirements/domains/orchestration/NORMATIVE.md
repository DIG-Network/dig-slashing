# Orchestration — Normative Requirements

> **Master spec:** [SPEC.md](../../../resources/SPEC.md) — Sections 10, 11, 13

System-level coordination: epoch boundary advancement, genesis initialisation, and fork-choice reorg rewind.

---

## &sect;1 Epoch Boundary Orchestration

<a id="DSL-127"></a>**DSL-127** `run_epoch_boundary(...)` MUST execute the following sequence in EXACT fixed order:
1. Compute flag deltas over `participation.previous_epoch_all()`.
2. Update inactivity scores over the same previous-epoch flags.
3. Compute inactivity penalties for the ending epoch.
4. Finalise expired slashes (applies correlation penalty + returns reporter bond + starts exit lock).
5. Rotate `ParticipationTracker` to `current_epoch_ending + 1`.
6. Advance `SlashingManager` epoch.
7. Resize trackers if `validator_count` changed.
8. Prune old processed evidence and correlation-window entries.

The function MUST return `EpochBoundaryReport { flag_deltas, inactivity_penalties, finalisations, in_finality_stall }`. Reordering of the steps is a hard failure.
> **Spec:** [`DSL-127.md`](specs/DSL-127.md)

---

## &sect;2 Genesis

<a id="DSL-128"></a>**DSL-128** `SlashingSystem::genesis(&GenesisParameters)` MUST initialise: empty `SlashingManager::processed`, empty `PendingSlashBook`, empty `slashed_in_window`, `ParticipationTracker` with `initial_validator_count` zero-flagged entries for both previous and current epoch, zero-vectored `InactivityScoreTracker`. `current_epoch` MUST equal `params.genesis_epoch`. `in_finality_stall(0, 0)` MUST return `false`.
> **Spec:** [`DSL-128.md`](specs/DSL-128.md)

---

## &sect;3 Manager Reorg Rewind

<a id="DSL-129"></a>**DSL-129** `SlashingManager::rewind_on_reorg(new_tip_epoch, ...)` MUST, for every `PendingSlash` with `submitted_at_epoch > new_tip_epoch`: credit the base slash back via `ValidatorEntry::credit_stake`, restore collateral via `CollateralSlasher::credit`, call `ValidatorEntry::restore_status`, release the reporter bond in full (no forfeit, no reporter penalty), remove the entry from `processed` and `slashed_in_window`, and return its `evidence_hash` in the report.
> **Spec:** [`DSL-129.md`](specs/DSL-129.md)

---

## &sect;4 Global Reorg Rewind

<a id="DSL-130"></a>**DSL-130** `rewind_all_on_reorg(...)` MUST orchestrate rewinds across `SlashingManager`, `ParticipationTracker`, `InactivityScoreTracker`, and `SlashingProtection`. Return `ReorgReport { rewound_pending_slashes, participation_epochs_dropped, inactivity_epochs_dropped, protection_rewound }`. MUST return `Err(SlashingError::ReorgTooDeep)` when `current_epoch - new_tip_epoch > CORRELATION_WINDOW_EPOCHS` (36).
> **Spec:** [`DSL-130.md`](specs/DSL-130.md)

---

## &sect;5 Serialization

<a id="DSL-165"></a>**DSL-165** `EpochBoundaryReport`, `ReorgReport`, and `FlagDelta` MUST round-trip byte-exactly via `bincode` + `serde_json`. Empty-vec cases preserved; `in_finality_stall` true/false both round-trip.
> **Spec:** [`DSL-165.md`](specs/DSL-165.md)
