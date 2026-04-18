# Implementation Order

Phased checklist for dig-slashing requirements. Work top-to-bottom within each phase.
After completing a requirement: write tests in `tests/dsl_NNN_<short_name>_test.rs`, verify they pass, update TRACKING.yaml, VERIFICATION.md, and check off here.

**A requirement is NOT complete until its dedicated test file exists, passes, and all three tracking artifacts are updated.**

---

## Phase 0: Evidence Types & Verification (DSL-001..021)

### Types
- [x] DSL-001 — OffenseType BPS mapping (500/300/100/100)
- [x] DSL-002 — SlashingEvidence::hash deterministic + sensitive
- [x] DSL-003 — Checkpoint roundtrip
- [x] DSL-004 — AttestationData::signing_root domain-prefixed
- [x] DSL-005 — IndexedAttestation::validate_structure
- [x] DSL-006 — IndexedAttestation::verify_signature (aggregate BLS)
- [x] DSL-007 — AttesterSlashing::slashable_indices (intersection)
- [x] DSL-008 — InvalidBlockProof + InvalidBlockReason roundtrip
- [x] DSL-009 — SignedBlockHeader roundtrip
- [x] DSL-010 — SlashingEvidence::slashable_validators

### Verification
- [x] DSL-011 — verify_evidence OffenseTooOld enforcement
- [x] DSL-012 — verify_evidence ReporterIsAccused rejection
- [x] DSL-013 — verify_proposer_slashing preconditions
- [x] DSL-014 — verify_attester_slashing double-vote predicate
- [x] DSL-015 — verify_attester_slashing surround-vote predicate
- [x] DSL-016 — verify_attester_slashing EmptySlashableIntersection
- [x] DSL-017 — verify_attester_slashing NotSlashableByPredicate
- [x] DSL-018 — verify_invalid_block signature over block_signing_message
- [x] DSL-019 — verify_invalid_block epoch mismatch rejection
- [x] DSL-020 — verify_invalid_block calls InvalidBlockOracle
- [x] DSL-021 — verify_evidence_for_inclusion parity

## Phase 1: Optimistic Slashing Lifecycle (DSL-022..033)

- [x] DSL-022 — submit_evidence base_slash = max(bps, quotient)
- [x] DSL-023 — submit_evidence escrows reporter bond
- [x] DSL-024 — submit_evidence creates PendingSlash Accepted
- [x] DSL-025 — submit_evidence reward routing (wb + proposer)
- [x] DSL-026 — submit_evidence AlreadySlashed on duplicate
- [x] DSL-027 — submit_evidence PendingBookFull at capacity
- [x] DSL-028 — submit_evidence BondLockFailed on insufficient stake
- [x] DSL-029 — finalise_expired_slashes transitions to Finalised
- [x] DSL-030 — finalise_expired_slashes correlation penalty
- [x] DSL-031 — finalise_expired_slashes returns reporter bond
- [x] DSL-032 — finalise_expired_slashes schedules exit lock
- [x] DSL-033 — finalise_expired_slashes skips Reverted

## Phase 2: Appeal System (DSL-034..073)

### Proposer Appeal Grounds
- [x] DSL-034 — ProposerAppeal HeadersIdentical sustained
- [x] DSL-035 — ProposerAppeal ProposerIndexMismatch sustained
- [x] DSL-036 — ProposerAppeal SignatureAInvalid sustained
- [x] DSL-037 — ProposerAppeal SignatureBInvalid sustained
- [x] DSL-038 — ProposerAppeal SlotMismatch sustained
- [x] DSL-039 — ProposerAppeal ValidatorNotActiveAtEpoch sustained
- [x] DSL-040 — ProposerAppeal rejected on false claim

### Attester Appeal Grounds
- [x] DSL-041 — AttesterAppeal AttestationsIdentical sustained
- [x] DSL-042 — AttesterAppeal NotSlashableByPredicate sustained
- [x] DSL-043 — AttesterAppeal EmptyIntersection sustained
- [x] DSL-044 — AttesterAppeal SignatureAInvalid sustained
- [x] DSL-045 — AttesterAppeal SignatureBInvalid sustained
- [x] DSL-046 — AttesterAppeal InvalidIndexedAttestationStructure sustained
- [x] DSL-047 — AttesterAppeal ValidatorNotInIntersection sustained
- [x] DSL-048 — AttesterAppeal rejected on genuine slash

### Invalid-Block Appeal Grounds
- [x] DSL-049 — InvalidBlockAppeal BlockActuallyValid sustained
- [x] DSL-050 — InvalidBlockAppeal ProposerSignatureInvalid sustained
- [x] DSL-051 — InvalidBlockAppeal FailureReasonMismatch sustained
- [x] DSL-052 — InvalidBlockAppeal EvidenceEpochMismatch sustained
- [x] DSL-053 — InvalidBlockAppeal MissingOracle error
- [x] DSL-054 — InvalidBlockAppeal rejected on genuine invalid block

### Appeal Submission Preconditions
- [x] DSL-055 — submit_appeal UnknownEvidence
- [x] DSL-056 — submit_appeal WindowExpired
- [x] DSL-057 — submit_appeal VariantMismatch
- [x] DSL-058 — submit_appeal DuplicateAppeal
- [x] DSL-059 — submit_appeal TooManyAttempts
- [x] DSL-060 — submit_appeal SlashAlreadyReverted
- [x] DSL-061 — submit_appeal SlashAlreadyFinalised
- [x] DSL-062 — submit_appeal escrows appellant bond
- [x] DSL-063 — submit_appeal PayloadTooLarge

### Adjudicator
- [x] DSL-064 — Adjudicate Sustained reverts base slash (credit_stake)
- [x] DSL-065 — Adjudicate Sustained reverts collateral
- [x] DSL-066 — Adjudicate Sustained restores validator status
- [x] DSL-067 — Adjudicate Sustained clawback rewards
- [x] DSL-068 — Adjudicate Sustained reporter-bond 50/50 split
- [x] DSL-069 — Adjudicate Sustained reporter penalty
- [x] DSL-070 — Adjudicate Sustained status Reverted
- [x] DSL-071 — Adjudicate Rejected appellant-bond 50/50 split
- [x] DSL-072 — Adjudicate Rejected keeps ChallengeOpen + appeal_count+1
- [x] DSL-073 — Adjudicate clawback shortfall absorbed from bond

## Phase 3: Participation & Rewards (DSL-074..086)

- [x] DSL-074 — ParticipationFlags bits set/has
- [x] DSL-075 — classify_timeliness TIMELY_SOURCE
- [x] DSL-076 — classify_timeliness TIMELY_TARGET
- [x] DSL-077 — classify_timeliness TIMELY_HEAD
- [x] DSL-078 — ParticipationTracker::record_attestation
- [x] DSL-079 — ParticipationTracker non-ascending rejection
- [x] DSL-080 — ParticipationTracker::rotate_epoch
- [x] DSL-081 — base_reward formula
- [x] DSL-082 — compute_flag_deltas reward on hit
- [x] DSL-083 — compute_flag_deltas penalty (source+target), head exempt
- [x] DSL-084 — compute_flag_deltas in-stall zeroes rewards
- [x] DSL-085 — proposer_inclusion_reward formula
- [x] DSL-086 — WEIGHT_DENOMINATOR = 64 (no sync committee, 2 units reserved)

## Phase 4: Inactivity Accounting (DSL-087..093)

- [x] DSL-087 — in_finality_stall threshold (> 4 epochs)
- [x] DSL-088 — InactivityScoreTracker::update hit decrement
- [x] DSL-089 — InactivityScoreTracker::update miss+stall increment (+4)
- [x] DSL-090 — InactivityScoreTracker::update out-of-stall recovery (-16)
- [x] DSL-091 — InactivityScoreTracker::epoch_penalties no-stall empty
- [x] DSL-092 — InactivityScoreTracker::epoch_penalties formula
- [x] DSL-093 — InactivityScoreTracker::resize_for

## Phase 5: Slashing Protection (DSL-094..101)

- [x] DSL-094 — check_proposal_slot monotonic
- [x] DSL-095 — check_attestation same (src,tgt) different hash fails
- [x] DSL-096 — would_surround self-check
- [x] DSL-097 — record_proposal + record_attestation persist
- [x] DSL-098 — rewind_attestation_to_epoch clears hash
- [x] DSL-099 — reconcile_with_chain_tip rewinds both
- [x] DSL-100 — Legacy JSON loads (no hash field → None)
- [x] DSL-101 — Save/load roundtrip

## Phase 6: REMARK Admission (DSL-102..120)

### Evidence REMARK
- [x] DSL-102 — Evidence REMARK wire roundtrip
- [x] DSL-103 — Evidence puzzle_reveal emits one REMARK
- [x] DSL-104 — Evidence admission matching coin
- [x] DSL-105 — Evidence admission mismatch rejected
- [x] DSL-106 — Evidence mempool expired rejected
- [x] DSL-107 — Evidence mempool duplicate rejected
- [x] DSL-108 — Evidence block cap (> MAX_SLASH_PROPOSALS_PER_BLOCK)
- [x] DSL-109 — Evidence payload cap

### Appeal REMARK
- [x] DSL-110 — Appeal REMARK wire roundtrip
- [x] DSL-111 — Appeal puzzle_reveal emits one REMARK
- [x] DSL-112 — Appeal admission matching coin
- [x] DSL-113 — Appeal admission mismatch rejected
- [x] DSL-114 — Appeal mempool AppealForUnknownSlash
- [x] DSL-115 — Appeal mempool AppealWindowExpired
- [x] DSL-116 — Appeal mempool AppealForFinalisedSlash
- [x] DSL-117 — Appeal mempool AppealVariantMismatch
- [x] DSL-118 — Appeal mempool duplicate rejected
- [x] DSL-119 — Appeal block cap
- [x] DSL-120 — Appeal payload cap

## Phase 7: Bonds & Rewards Routing (DSL-121..126)

- [x] DSL-121 — BondEscrow::lock InsufficientBalance
- [x] DSL-122 — BondEscrow::forfeit returns mojos
- [x] DSL-123 — BondEscrow::release full on finalise
- [x] DSL-124 — REPORTER_BOND_MOJOS = MIN_EFFECTIVE_BALANCE/64
- [x] DSL-125 — APPELLANT_BOND_MOJOS = MIN_EFFECTIVE_BALANCE/64
- [x] DSL-126 — BOND_AWARD_TO_WINNER_BPS = 5_000 (50/50)

## Phase 8: Orchestration (DSL-127..130)

- [ ] DSL-127 — run_epoch_boundary fixed ordering
- [ ] DSL-128 — SlashingSystem::genesis
- [ ] DSL-129 — SlashingManager::rewind_on_reorg
- [ ] DSL-130 — rewind_all_on_reorg

## Phase 9: External-State Traits (DSL-131..145)

- [ ] DSL-131 — ValidatorEntry::slash_absolute saturation
- [ ] DSL-132 — ValidatorEntry::credit_stake
- [ ] DSL-133 — ValidatorEntry::restore_status
- [ ] DSL-134 — ValidatorEntry::is_active_at_epoch boundary
- [ ] DSL-135 — ValidatorEntry::schedule_exit
- [ ] DSL-136 — ValidatorView::get / get_mut
- [ ] DSL-137 — EffectiveBalanceView::get / total_active
- [ ] DSL-138 — PublicKeyLookup::pubkey_of
- [ ] DSL-139 — CollateralSlasher slash+credit symmetry
- [ ] DSL-140 — BondEscrow::escrowed
- [ ] DSL-141 — RewardPayout::pay
- [ ] DSL-142 — RewardClawback::claw_back partial
- [ ] DSL-143 — JustificationView contract
- [ ] DSL-144 — ProposerView::proposer_at_slot
- [ ] DSL-145 — InvalidBlockOracle::re_execute determinism

## Phase 10: Gap Fills (DSL-146..156)

### Lifecycle — Book + Queries + Short-Circuits
- [ ] DSL-146 — PendingSlashBook basic ops (new/insert/get/remove/len)
- [ ] DSL-147 — PendingSlashBook::expired_by
- [ ] DSL-148 — SlashingManager::new + set_epoch
- [ ] DSL-149 — SlashingManager::is_slashed
- [ ] DSL-150 — SlashingManager is_processed + pending + prune
- [ ] DSL-151 — Correlation penalty saturation clamp
- [ ] DSL-152 — submit_evidence ReporterIsAccused short-circuit

### Participation — Reorg + Serde
- [ ] DSL-153 — ParticipationTracker::rewind_on_reorg
- [ ] DSL-154 — ParticipationFlags serde roundtrip

### Inactivity — Reorg
- [ ] DSL-155 — InactivityScoreTracker::rewind_on_reorg

### Protection — Proposal Rewind
- [ ] DSL-156 — SlashingProtection::rewind_proposal_to_slot

## Phase 11: Gap Fills 2 — Serde + Defensive + BondTag (DSL-157..166)

### Evidence — Serde
- [ ] DSL-157 — SlashingEvidence + payload serde roundtrip
- [ ] DSL-158 — IndexedAttestation serde roundtrip

### Appeal — Hash + Serde
- [ ] DSL-159 — SlashAppeal::hash determinism + sensitivity
- [ ] DSL-160 — SlashAppeal + SlashAppealPayload serde roundtrip
- [ ] DSL-161 — PendingSlash + AppealAttempt + PendingSlashStatus serde
- [ ] DSL-164 — AppealAdjudicationResult serde roundtrip

### Lifecycle — Defensive + Serde
- [ ] DSL-162 — submit_evidence skips already-slashed indices
- [ ] DSL-163 — SlashingResult + PerValidatorSlash + FinalisationResult serde

### Orchestration — Serde
- [ ] DSL-165 — EpochBoundaryReport + ReorgReport + FlagDelta serde

### Bonds — Variant Distinction
- [ ] DSL-166 — BondTag::Reporter vs Appellant distinguishable

---

## Summary

| Phase | DSL Range | Count | Status |
|-------|-----------|-------|--------|
| Phase 0: Evidence | 001..021 | 21 | gap |
| Phase 1: Lifecycle | 022..033 | 12 | gap |
| Phase 2: Appeal | 034..073 | 40 | gap |
| Phase 3: Participation | 074..086 | 13 | gap |
| Phase 4: Inactivity | 087..093 | 7 | gap |
| Phase 5: Protection | 094..101 | 8 | gap |
| Phase 6: REMARK | 102..120 | 19 | gap |
| Phase 7: Bonds | 121..126 | 6 | gap |
| Phase 8: Orchestration | 127..130 | 4 | gap |
| Phase 9: Traits | 131..145 | 15 | gap |
| Phase 10: Gap Fills | 146..156 | 11 | gap |
| Phase 11: Gap Fills 2 | 157..166 | 10 | gap |
| **Total** | | **166** | |

Every DSL-NNN has a dedicated test file at `tests/dsl_NNN_<short_name>_test.rs` per SPEC §22.16.
