# Appeal System — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-034](NORMATIVE.md#DSL-034) | ✅ | Proposer appeal HeadersIdentical sustained | 4 tests: byte-equal messages → `Sustained{HeadersIdentical}`, distinct messages → `Rejected{GroundDoesNotHold}`, signature mutation alone doesn't change verdict (message-only predicate), determinism. Test file: `tests/dsl_034_proposer_appeal_headers_identical_sustained_test.rs`. |
| [DSL-035](NORMATIVE.md#DSL-035) | ✅ | Proposer appeal ProposerIndexMismatch sustained | 4 tests: different `proposer_index` → Sustained, matching → Rejected, off-by-one → Sustained, determinism. Test file: `tests/dsl_035_proposer_appeal_proposer_index_mismatch_test.rs`. |
| [DSL-036](NORMATIVE.md#DSL-036) | ✅ | Proposer appeal SignatureAInvalid sustained | 6 tests: corrupted sig_a → Sustained, valid sig_a → Rejected, wrong-key → Sustained, cross-network replay → Sustained, unknown validator → Sustained, bad sig width → Sustained. Test file: `tests/dsl_036_proposer_appeal_signature_a_invalid_test.rs`. |
| [DSL-037](NORMATIVE.md#DSL-037) | ✅ | Proposer appeal SignatureBInvalid sustained | 6 tests (mirror of DSL-036 on header_b): corrupted → Sustained, valid → Rejected, wrong-key → Sustained, cross-network replay → Sustained, sig_a corruption ignored on B path, bad sig width → Sustained. Test file: `tests/dsl_037_proposer_appeal_signature_b_invalid_test.rs`. |
| [DSL-038](NORMATIVE.md#DSL-038) | ❌ | Proposer appeal SlotMismatch sustained | 3 tests: different slots sustained, same slot rejected, adjacent slots. |
| [DSL-039](NORMATIVE.md#DSL-039) | ❌ | Proposer appeal ValidatorNotActiveAtEpoch sustained | 4 tests: pre-activation sustained, post-exit sustained, active rejected, boundary epochs. |
| [DSL-040](NORMATIVE.md#DSL-040) | ❌ | Proposer appeal rejected on false claim | 4 tests per ground: false claim returns Rejected. |
| [DSL-041](NORMATIVE.md#DSL-041) | ❌ | Attester appeal AttestationsIdentical sustained | 3 tests: byte-equal attestations sustained, non-equal rejected. |
| [DSL-042](NORMATIVE.md#DSL-042) | ❌ | Attester appeal NotSlashableByPredicate sustained | 4 tests: non-overlapping epoch windows, neither predicate holds → sustained. |
| [DSL-043](NORMATIVE.md#DSL-043) | ❌ | Attester appeal EmptyIntersection sustained | 3 tests: disjoint indices → sustained; overlapping rejected. |
| [DSL-044](NORMATIVE.md#DSL-044) | ❌ | Attester appeal SignatureAInvalid sustained | 3 tests: corrupted aggregate sig_a → sustained. |
| [DSL-045](NORMATIVE.md#DSL-045) | ❌ | Attester appeal SignatureBInvalid sustained | Mirror of DSL-044. |
| [DSL-046](NORMATIVE.md#DSL-046) | ❌ | Attester appeal InvalidIndexedAttestationStructure sustained | 4 tests: non-ascending, duplicate, empty, over-cap indices → sustained. |
| [DSL-047](NORMATIVE.md#DSL-047) | ❌ | Attester appeal ValidatorNotInIntersection sustained | 3 tests: named index not in intersection → sustained; in intersection rejected. |
| [DSL-048](NORMATIVE.md#DSL-048) | ❌ | Attester appeal rejected on genuine slash | 4 tests: genuine double-vote and surround-vote cases. |
| [DSL-049](NORMATIVE.md#DSL-049) | ❌ | InvalidBlock appeal BlockActuallyValid sustained | 3 tests: oracle returns Valid → sustained; Invalid → rejected. |
| [DSL-050](NORMATIVE.md#DSL-050) | ❌ | InvalidBlock appeal ProposerSignatureInvalid sustained | 3 tests: bad sig → sustained; good sig rejected. |
| [DSL-051](NORMATIVE.md#DSL-051) | ❌ | InvalidBlock appeal FailureReasonMismatch sustained | 4 tests: oracle-returned reason differs from claimed → sustained. |
| [DSL-052](NORMATIVE.md#DSL-052) | ❌ | InvalidBlock appeal EvidenceEpochMismatch sustained | 3 tests: header.epoch != evidence.epoch → sustained. |
| [DSL-053](NORMATIVE.md#DSL-053) | ❌ | InvalidBlock appeal MissingOracle error | 2 tests: no oracle supplied + BlockActuallyValid → MissingOracle error. |
| [DSL-054](NORMATIVE.md#DSL-054) | ❌ | InvalidBlock appeal rejected on genuine invalid block | 3 tests: oracle confirms invalid → rejected per ground. |
| [DSL-055](NORMATIVE.md#DSL-055) | ❌ | submit_appeal UnknownEvidence | 2 tests: fresh hash → UnknownEvidence; bond not locked. |
| [DSL-056](NORMATIVE.md#DSL-056) | ❌ | submit_appeal WindowExpired | 3 tests: at exact edge + 1 rejected; in window accepted. |
| [DSL-057](NORMATIVE.md#DSL-057) | ❌ | submit_appeal VariantMismatch | 4 tests: ProposerAppeal vs AttesterSlashing evidence, all permutations. |
| [DSL-058](NORMATIVE.md#DSL-058) | ❌ | submit_appeal DuplicateAppeal | 3 tests: byte-equal duplicate rejected; near-duplicate accepted. |
| [DSL-059](NORMATIVE.md#DSL-059) | ❌ | submit_appeal TooManyAttempts | 2 tests: 4 rejected appeals then 5th → TooManyAttempts. |
| [DSL-060](NORMATIVE.md#DSL-060) | ❌ | submit_appeal SlashAlreadyReverted | 2 tests: post-sustained revert, new appeal rejected. |
| [DSL-061](NORMATIVE.md#DSL-061) | ❌ | submit_appeal SlashAlreadyFinalised | 2 tests: post-finalisation, new appeal rejected. |
| [DSL-062](NORMATIVE.md#DSL-062) | ❌ | submit_appeal escrows appellant bond | 3 tests: lock called; insufficient balance → AppellantBondLockFailed. |
| [DSL-063](NORMATIVE.md#DSL-063) | ❌ | submit_appeal PayloadTooLarge | 2 tests: > MAX_APPEAL_PAYLOAD_BYTES → PayloadTooLarge. |
| [DSL-064](NORMATIVE.md#DSL-064) | ❌ | Adjudicate Sustained reverts base slash | 3 tests: credit_stake called with amount; stake restored; multi-validator. |
| [DSL-065](NORMATIVE.md#DSL-065) | ❌ | Adjudicate Sustained reverts collateral | 3 tests: CollateralSlasher::credit called; no-op when absent. |
| [DSL-066](NORMATIVE.md#DSL-066) | ❌ | Adjudicate Sustained restores validator status | 3 tests: restore_status called; Slashed → Active. |
| [DSL-067](NORMATIVE.md#DSL-067) | ❌ | Adjudicate Sustained clawback rewards | 3 tests: wb_reward + prop_reward clawed back; shortfall recorded. |
| [DSL-068](NORMATIVE.md#DSL-068) | ❌ | Adjudicate Sustained reporter-bond 50/50 split | 3 tests: forfeit + appellant_award (50%) + burn (50%); rounding. |
| [DSL-069](NORMATIVE.md#DSL-069) | ❌ | Adjudicate Sustained reporter penalty | 3 tests: reporter slashed with InvalidBlock base formula; recorded in window. |
| [DSL-070](NORMATIVE.md#DSL-070) | ❌ | Adjudicate Sustained status Reverted | 2 tests: pending.status → Reverted; winning_appeal_hash set. |
| [DSL-071](NORMATIVE.md#DSL-071) | ❌ | Adjudicate Rejected appellant-bond 50/50 split | 3 tests: forfeit + reporter_award + burn. |
| [DSL-072](NORMATIVE.md#DSL-072) | ❌ | Adjudicate Rejected keeps ChallengeOpen | 3 tests: appeal_count increments; first_appeal_filed_epoch preserved. |
| [DSL-073](NORMATIVE.md#DSL-073) | ❌ | Adjudicate clawback shortfall absorbed from bond | 3 tests: partial clawback; shortfall + forfeit accounting. |
| [DSL-159](NORMATIVE.md#DSL-159) | ❌ | SlashAppeal::hash determinism + sensitivity | 7 tests: deterministic + 5 field mutations + domain prefix. |
| [DSL-160](NORMATIVE.md#DSL-160) | ❌ | SlashAppeal + SlashAppealPayload serde roundtrip | 5 tests: each ground variant + JSON + witness bytes. |
| [DSL-161](NORMATIVE.md#DSL-161) | ❌ | PendingSlash + AppealAttempt + PendingSlashStatus serde | 6 tests: 4 status variants, 3 AppealOutcome, full PendingSlash. |
| [DSL-164](NORMATIVE.md#DSL-164) | ❌ | AppealAdjudicationResult serde roundtrip | 5 tests: sustained, rejected, JSON, AppealOutcome variants, vec order. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
