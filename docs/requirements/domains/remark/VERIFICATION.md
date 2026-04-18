# REMARK Admission — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-102](NORMATIVE.md#DSL-102) | ✅ | Evidence wire roundtrip | 5 tests against new `src/remark/evidence_wire.rs`: `encode_slashing_evidence_remark_payload_v1(&ev)` emits `SLASH_EVIDENCE_REMARK_MAGIC_V1 \|\| serde_json(ev)`; `parse_slashing_evidence_from_conditions(&[P: AsRef<[u8]>])` strips magic + decodes, silent-skipping short/foreign/malformed/wrong-schema payloads. Roundtrip PartialEq; magic-prefix substring pinned to `b"DIG_SLASH_EVIDENCE_V1\0"`; empty + short-prefix + foreign-prefix + garbage-JSON + wrong-schema-JSON all skip cleanly; interleaved valid+foreign+valid list preserves input order. Opens Phase 6 REMARK Admission with new `src/remark/` module + `SLASH_EVIDENCE_REMARK_MAGIC_V1` / `SLASH_APPEAL_REMARK_MAGIC_V1` constants (appeal prefix landed early so DSL-110 can reuse without a second constants commit). Test file: `tests/dsl_102_evidence_remark_wire_roundtrip_test.rs`. |
| [DSL-103](NORMATIVE.md#DSL-103) | ✅ | Evidence puzzle_reveal emits one REMARK | 4 tests against new `slashing_evidence_remark_puzzle_reveal_v1` + `slashing_evidence_remark_puzzle_hash_v1` in `src/remark/evidence_wire.rs`. Puzzle shape: quoted constant `(q . ((1 payload)))` where outer `1` is the CLVM quote opcode and inner `1 payload` is the REMARK condition in canonical proper-list form. Solution-less by design (prevents post-creation payload substitution). Built via clvmr Allocator + serialised through `node_to_bytes`; hash via `clvm_utils::tree_hash_from_bytes`. `cargo test` runs the puzzle in clvmr `ChiaDialect(0)` via `chia_sdk_types::run_puzzle`: output decodes as `Vec<Condition<NodePtr>>` of length 1 matching `Condition::Remark`; REMARK payload atom extracted via `allocator.sexp` pair-walk round-trips through DSL-102 `parse_slashing_evidence_from_conditions` to the original evidence; puzzle hash stable across repeated calls AND changes when `reporter_validator_index` mutates; hash equals `tree_hash_from_bytes(reveal)`. Adds `clvmr`, `clvm-utils` as main deps + `chia-sdk-types`, `clvm-traits` as dev-deps. Test file: `tests/dsl_103_evidence_puzzle_reveal_emits_one_remark_test.rs`. |
| [DSL-104](NORMATIVE.md#DSL-104) | ❌ | Admission matching coin | 2 tests: bundle with derived puzzle_hash admits. |
| [DSL-105](NORMATIVE.md#DSL-105) | ❌ | Admission mismatched rejected | 3 tests: wrong puzzle_hash rejected; error message includes both hashes. |
| [DSL-106](NORMATIVE.md#DSL-106) | ❌ | Mempool expired rejected | 3 tests: expired → OutsideLookback, on-boundary, within window admits. |
| [DSL-107](NORMATIVE.md#DSL-107) | ❌ | Mempool duplicate rejected | 3 tests: pending-dup, incoming-dup, distinct admits. |
| [DSL-108](NORMATIVE.md#DSL-108) | ❌ | Block cap (> MAX_SLASH_PROPOSALS_PER_BLOCK) | 2 tests: 65 rejected, 64 admits. |
| [DSL-109](NORMATIVE.md#DSL-109) | ❌ | Payload cap (> MAX_SLASH_PROPOSAL_PAYLOAD_BYTES) | 2 tests: oversized rejected, at-limit admits. |
| [DSL-110](NORMATIVE.md#DSL-110) | ❌ | Appeal wire roundtrip | 3 tests: encode+parse roundtrip, magic prefix DIG_SLASH_APPEAL_V1\0, non-magic rejected. |
| [DSL-111](NORMATIVE.md#DSL-111) | ❌ | Appeal puzzle_reveal emits one REMARK | 3 tests: run_puzzle yields 1 Condition::Remark, parse, hash stable. |
| [DSL-112](NORMATIVE.md#DSL-112) | ❌ | Appeal admission matching coin | 2 tests: correct puzzle_hash admits. |
| [DSL-113](NORMATIVE.md#DSL-113) | ❌ | Appeal admission mismatch rejected | 2 tests: wrong puzzle_hash rejected. |
| [DSL-114](NORMATIVE.md#DSL-114) | ❌ | Appeal unknown slash rejected | 2 tests: fresh hash → AppealForUnknownSlash. |
| [DSL-115](NORMATIVE.md#DSL-115) | ❌ | Appeal window expired | 3 tests: expired, at-boundary, in-window. |
| [DSL-116](NORMATIVE.md#DSL-116) | ❌ | Appeal for finalised slash | 3 tests: Finalised, Reverted, Accepted admits. |
| [DSL-117](NORMATIVE.md#DSL-117) | ❌ | Appeal variant mismatch | 4 tests: each cross-variant permutation. |
| [DSL-118](NORMATIVE.md#DSL-118) | ❌ | Appeal duplicate rejected | 3 tests: pending-dup, incoming-dup, distinct. |
| [DSL-119](NORMATIVE.md#DSL-119) | ❌ | Appeal block cap | 2 tests: 65 rejected, 64 admits. |
| [DSL-120](NORMATIVE.md#DSL-120) | ❌ | Appeal payload cap | 2 tests: oversized rejected, at-limit admits. |

**Status legend:** ✅ verified · ⚠️ partial · ❌ gap
