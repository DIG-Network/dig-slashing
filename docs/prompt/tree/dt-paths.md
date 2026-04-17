# dt-paths — Path Conventions

## Project Layout

```
dig-slashing/
├── docs/
│   ├── resources/
│   │   └── SPEC.md                          # Master spec (v0.4+) with §22 requirements catalogue
│   ├── requirements/
│   │   ├── SCHEMA.md                        # Data model + conventions
│   │   ├── README.md                        # Requirements system overview
│   │   ├── REQUIREMENTS_REGISTRY.yaml       # Domain registry
│   │   ├── IMPLEMENTATION_ORDER.md          # Phased checklist (130 DSL-NNN reqs)
│   │   └── domains/
│   │       ├── evidence/                    # DSL-001..021 Offense + evidence + verification
│   │       ├── lifecycle/                   # DSL-022..033 Optimistic slashing lifecycle
│   │       ├── appeal/                      # DSL-034..073 Fraud-proof appeals + adjudication
│   │       ├── participation/               # DSL-074..086 Attestation participation + rewards
│   │       ├── inactivity/                  # DSL-087..093 Inactivity accounting
│   │       ├── protection/                  # DSL-094..101 Validator-local slashing protection
│   │       ├── remark/                      # DSL-102..120 REMARK admission (evidence + appeal)
│   │       ├── bonds/                       # DSL-121..126 Bond escrow + rewards
│   │       └── orchestration/               # DSL-127..130 Epoch boundary + genesis + reorg
│   └── prompt/                              # This workflow system
│       ├── prompt.md
│       ├── start.md
│       ├── chat.md
│       ├── tree/                            # Decision tree files (you are here)
│       └── tools/                           # Tool documentation
├── src/
│   ├── lib.rs                               # Public API re-exports
│   ├── constants.rs                         # §2 SPEC constants
│   ├── error.rs                             # SlashingError, AppealError, BondError, ...
│   ├── evidence/                            # Offense + evidence + per-offense verifiers
│   │   ├── offense.rs                       # OffenseType
│   │   ├── checkpoint.rs                    # Checkpoint (FFG vote)
│   │   ├── attestation_data.rs              # AttestationData + signing_root
│   │   ├── indexed_attestation.rs           # IndexedAttestation + validate/verify
│   │   ├── proposer_slashing.rs             # SignedBlockHeader + ProposerSlashing
│   │   ├── attester_slashing.rs             # AttesterSlashing + predicates
│   │   ├── invalid_block.rs                 # InvalidBlockProof
│   │   ├── envelope.rs                      # SlashingEvidence
│   │   └── verify.rs                        # verify_evidence + per-payload
│   ├── appeal/                              # Fraud-proof appeal types + verifiers + adjudicator
│   │   ├── proposer.rs
│   │   ├── attester.rs
│   │   ├── invalid_block.rs
│   │   ├── envelope.rs                      # SlashAppeal
│   │   ├── verify.rs                        # verify_appeal + per-ground
│   │   └── adjudicator.rs                   # AppealAdjudicator
│   ├── manager.rs                           # SlashingManager (optimistic lifecycle)
│   ├── pending.rs                           # PendingSlashBook + PendingSlash + AppealAttempt
│   ├── lifecycle.rs                         # PendingSlashStatus helpers
│   ├── result.rs                            # SlashingResult, AppealAdjudicationResult, ...
│   ├── participation/                       # ParticipationFlags, tracker, rewards
│   ├── inactivity/                          # InactivityScoreTracker, penalty
│   ├── orchestration.rs                     # run_epoch_boundary + rewind_all_on_reorg
│   ├── system.rs                            # SlashingSystem + GenesisParameters
│   ├── traits.rs                            # ValidatorView, EffectiveBalanceView,
│   │                                         BondEscrow, RewardPayout, RewardClawback,
│   │                                         JustificationView, ProposerView,
│   │                                         InvalidBlockOracle, CollateralSlasher, ...
│   ├── remark/                              # REMARK admission for evidence + appeal
│   └── protection.rs                        # SlashingProtection (validator-local watermarks)
├── tests/
│   └── dsl_{NNN}_{short_name}_test.rs       # Per-requirement TDD tests, one per DSL-NNN
├── Cargo.toml
└── .repomix/                                # Ephemeral context packs (gitignored)
```

## Sibling Crates

```
../dig-block/                                # L2BlockHeader + block_signing_message
../dig-epoch/                                # SLASH_LOOKBACK_EPOCHS + CORRELATION_WINDOW_EPOCHS
../dig-constants/                            # NetworkConstants
../dig-consensus/                            # ValidatorSet, justification (ValidatorView impl downstream)
../dig-collateral/                           # CollateralSlasher + BondEscrow impls downstream
../dig-mempool/                              # REMARK admission consumer downstream
```

## Key Paths to Remember

| Artifact | Path |
|----------|------|
| Master spec | `docs/resources/SPEC.md` |
| Requirements catalogue | `docs/resources/SPEC.md` §22 |
| Implementation order | `docs/requirements/IMPLEMENTATION_ORDER.md` |
| Domain NORMATIVE | `docs/requirements/domains/{domain}/NORMATIVE.md` |
| Requirement spec | `docs/requirements/domains/{domain}/specs/DSL-NNN.md` |
| Main entry | `src/lib.rs` |
| Test file | `tests/dsl_{NNN}_{short_name}_test.rs` (one per DSL-NNN) |

---

Navigation: Next > [dt-role.md](dt-role.md)
