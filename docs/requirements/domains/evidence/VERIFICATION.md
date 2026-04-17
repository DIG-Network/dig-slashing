# Evidence — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-001](NORMATIVE.md#DSL-001) | ✅ | OffenseType::base_penalty_bps mapping | 5 tests: per-variant mapping (500/300/100/100), exhaustive MAX_PENALTY_BPS cap, >0 floor. Test file: `tests/dsl_001_offense_type_bps_mapping_test.rs`. |
| [DSL-002](NORMATIVE.md#DSL-002) | ❌ | SlashingEvidence::hash determinism | 7 tests: idempotent on same input, mutation of each field shifts hash (offense_type, reporter_index, reporter_puzzle_hash, epoch, payload), domain separation tag prefix, cross-variant collision-freeness. |
| [DSL-003](NORMATIVE.md#DSL-003) | ❌ | Checkpoint serde + Eq + Hash round-trip | 5 tests: JSON round-trip, bincode round-trip, PartialEq symmetry, Hash equality for equal values, Copy semantics. |
| [DSL-004](NORMATIVE.md#DSL-004) | ❌ | AttestationData::signing_root determinism + domain | 8 tests: idempotent, domain prefix included, slot mutation shifts, index mutation shifts, beacon_block_root mutation shifts, source mutation shifts, target mutation shifts, network_id mutation shifts. |
| [DSL-005](NORMATIVE.md#DSL-005) | ❌ | IndexedAttestation::validate_structure | 7 tests: happy path Ok, non-ascending rejected, duplicates rejected, empty rejected, over-cap rejected, bad-sig-width rejected, boundary at MAX_VALIDATORS_PER_COMMITTEE. |
| [DSL-006](NORMATIVE.md#DSL-006) | ❌ | IndexedAttestation::verify_signature aggregate BLS | 6 tests: valid aggregate verifies, single-bit sig corruption fails, substituted pubkey fails, tampered message fails, empty committee (prevented by validate_structure), domain mismatch fails. |
| [DSL-007](NORMATIVE.md#DSL-007) | ❌ | AttesterSlashing::slashable_indices intersection | 5 tests: disjoint returns empty, full overlap returns full set, partial overlap sorted, idempotent, ordering insensitivity. |
| [DSL-008](NORMATIVE.md#DSL-008) | ❌ | InvalidBlockProof + InvalidBlockReason round-trip | 6 tests: JSON round-trip per reason variant, bincode round-trip, PartialEq, Hash, all 8 InvalidBlockReason variants, witness bytes preserved. |
| [DSL-009](NORMATIVE.md#DSL-009) | ❌ | SignedBlockHeader serde round-trip | 4 tests: JSON round-trip, bincode round-trip, PartialEq equality, signature bytes preserved. |
| [DSL-010](NORMATIVE.md#DSL-010) | ❌ | SlashingEvidence::slashable_validators cardinality | 5 tests: Proposer → 1, InvalidBlock → 1, Attester → N (N>=1), Attester sorted, empty-intersection case returns empty. |
| [DSL-011](NORMATIVE.md#DSL-011) | ❌ | verify_evidence OffenseTooOld | 5 tests: too-old returns error, exactly-at-boundary accepted, current-epoch accepted, wraparound safe, error fields populated correctly. |
| [DSL-012](NORMATIVE.md#DSL-012) | ❌ | verify_evidence ReporterIsAccused | 5 tests: reporter in attester set rejected, reporter is proposer rejected, non-accused reporter accepted, check ordering (after OffenseTooOld), error carries reporter index. |
| [DSL-013](NORMATIVE.md#DSL-013) | ❌ | verify_proposer_slashing preconditions | 8 tests: happy path, slot mismatch, proposer mismatch, identical headers, bad sig A, bad sig B, inactive validator, oversize sig bytes. |
| [DSL-014](NORMATIVE.md#DSL-014) | ❌ | verify_attester_slashing double-vote | 5 tests: same target + different data accepted, same target + same data rejected, offense_type = AttesterDoubleVote on success, single-validator intersection accepted, BLS verify still enforced. |
| [DSL-015](NORMATIVE.md#DSL-015) | ❌ | verify_attester_slashing surround-vote | 6 tests: a surrounds b accepted, b surrounds a (mirror) accepted, non-strict inequalities rejected, offense_type = AttesterSurroundVote on success, source-only difference rejected, target-only difference rejected. |
| [DSL-016](NORMATIVE.md#DSL-016) | ❌ | verify_attester_slashing EmptySlashableIntersection | 4 tests: disjoint sets rejected, predicate held but empty intersection rejected, non-empty accepted, error variant exact. |
| [DSL-017](NORMATIVE.md#DSL-017) | ❌ | verify_attester_slashing AttesterSlashingNotSlashable | 5 tests: identical attestations rejected, different target + no surround rejected, neither predicate holds rejected, valid sigs still rejected, error variant exact. |
| [DSL-018](NORMATIVE.md#DSL-018) | ❌ | verify_invalid_block signature over dig_block domain | 5 tests: happy path, bit-flip in signature fails, wrong network_id fails, wrong epoch in message fails, wrong proposer index in message fails. |
| [DSL-019](NORMATIVE.md#DSL-019) | ❌ | verify_invalid_block epoch mismatch | 4 tests: header.epoch == evidence.epoch accepted, header.epoch != evidence.epoch rejected, boundary cases, error carries explanatory string. |
| [DSL-020](NORMATIVE.md#DSL-020) | ❌ | verify_invalid_block oracle invocation | 6 tests: oracle.verify_failure called once, oracle Err → verifier Err, oracle Ok → verifier proceeds, no-oracle path skips check, oracle receives header + witness + reason, reason passed through unmodified. |
| [DSL-021](NORMATIVE.md#DSL-021) | ❌ | verify_evidence_for_inclusion parity | 6 tests: same Ok on happy path, same Err on each failure mode, no ValidatorView writes, no oracle side-effects, return value byte-equal, used by mempool signature compiles. |
| [DSL-157](NORMATIVE.md#DSL-157) | ❌ | SlashingEvidence + payload serde roundtrip | 7 tests: all 3 payload variants × bincode + json, serde_bytes encoding. |
| [DSL-158](NORMATIVE.md#DSL-158) | ❌ | IndexedAttestation serde roundtrip | 5 tests: bincode, json, index order, signature serde_bytes, nested AttestationData. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
