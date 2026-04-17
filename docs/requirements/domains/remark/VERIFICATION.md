# REMARK Admission — Verification

| ID | Status | Summary | Verification Approach |
|----|--------|---------|----------------------|
| [DSL-102](NORMATIVE.md#DSL-102) | ❌ | Evidence wire roundtrip | 3 tests: encode+parse roundtrip, magic-prefix present, rejects non-magic payload. |
| [DSL-103](NORMATIVE.md#DSL-103) | ❌ | Evidence puzzle_reveal emits one REMARK | 3 tests: run_puzzle yields 1 Condition::Remark, message parses, puzzle_hash stable. |
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
