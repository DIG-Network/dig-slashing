# Requirements Schema

Data model and conventions for all requirements in the dig-slashing project.

---

## Three-Document Pattern

Each domain has exactly three files in `docs/requirements/domains/{domain}/`:

| File | Purpose |
|------|---------|
| `NORMATIVE.md` | Authoritative requirement statements with MUST/SHOULD/MAY keywords |
| `VERIFICATION.md` | QA approach and verification status per requirement |
| `TRACKING.yaml` | Machine-readable status, test references, and implementation notes |

Each requirement also has a dedicated specification file in `docs/requirements/domains/{domain}/specs/DSL-NNN.md`.

---

## Requirement ID Format

**Pattern:** `DSL-{NNN}`

- **DSL**: single prefix for the entire crate (one namespace, 130 IDs)
- **NNN**: zero-padded numeric ID (001..130)

| Domain | Directory | DSL Range | Description |
|--------|-----------|-----------|-------------|
| Evidence | `evidence/` | 001..021 | Offense catalogue + evidence types + verification |
| Lifecycle | `lifecycle/` | 022..033, 146..152 | Optimistic slashing state machine + book + queries + clamp |
| Appeal | `appeal/` | 034..073 | Fraud-proof appeal system |
| Participation | `participation/` | 074..086, 153..154 | Ethereum-parity attestation rewards/penalties + reorg + serde |
| Inactivity | `inactivity/` | 087..093, 155 | Ethereum-parity inactivity accounting + reorg |
| Protection | `protection/` | 094..101, 156 | Validator-local slashing protection |
| REMARK | `remark/` | 102..120 | On-chain evidence + appeal admission |
| Bonds | `bonds/` | 121..126 | Bond escrow + rewards routing |
| Orchestration | `orchestration/` | 127..130 | Epoch boundary + genesis + reorg |
| Traits | `traits/` | 131..145 | External-state trait contracts (ValidatorView, BondEscrow, etc.) |

**Immutability:** Requirement IDs are permanent. Deprecate rather than renumber.

---

## Requirement Keywords

Per RFC 2119:

| Keyword | Meaning | Impact |
|---------|---------|--------|
| **MUST** | Absolute requirement | Blocks "done" status if not met |
| **MUST NOT** | Absolute prohibition | Blocks "done" status if violated |
| **SHOULD** | Expected behavior; may be deferred with rationale | Phase 2+ polish items |
| **SHOULD NOT** | Discouraged behavior | Phase 2+ polish items |
| **MAY** | Optional, nice-to-have | Stretch goals |

---

## Status Values

| Status | Description |
|--------|-------------|
| `gap` | Not implemented |
| `partial` | Implementation in progress or incomplete |
| `implemented` | Code complete, awaiting verification |
| `verified` | Implemented and verified per VERIFICATION.md |
| `deferred` | Explicitly postponed with rationale |

---

## TRACKING.yaml Item Schema

```yaml
- id: DSL-NNN             # Requirement ID (required)
  section: "Section Name" # Logical grouping within domain (required)
  summary: "Brief title"  # Human-readable description (required)
  status: gap             # One of: gap, partial, implemented, verified, deferred
  spec_ref: "docs/requirements/domains/{domain}/specs/DSL-NNN.md"
  catalogue_ref: "docs/resources/SPEC.md#dsl-NNN"
  tests: []               # Array of test names matching tests/dsl_NNN_*_test.rs
  notes: ""               # Implementation notes, blockers, or evidence
```

---

## Test File Naming — One Per Requirement (§22.16)

Per SPEC.md §22.16:

1. Every requirement must have exactly one `tests/dsl_NNN_<short_name>_test.rs` file.
2. Every test file begins with `//! Requirement DSL-NNN: <text>` matching SPEC.md §22 exactly.
3. CI verifies 1:1 correspondence.
4. Requirements are append-only: new behavior adds DSL-131+. Existing IDs never change or reorder.

---

## Testing Requirements

All dig-slashing requirements MUST be tested using:

### 1. TDD — Failing Test First (MUST)

1. Read SPEC.md §22 catalogue row + dedicated spec Test Plan
2. Write test in `tests/dsl_NNN_<short_name>_test.rs`
3. Run → must fail (compilation error or assertion failure)
4. Implement to make it pass
5. Re-run → must pass

### 2. Determinism (MUST)

Every verifier (`verify_evidence`, `verify_appeal`, `classify_timeliness`, `base_reward`, `compute_flag_deltas`, inactivity formulas) is a pure function of inputs. Tests must demonstrate same inputs → same output across runs.

### 3. Chia + DIG Crate Parity (MUST where applicable)

- BLS parity: aggregate signatures verified via `chia_bls::aggregate_verify` match the local verifier byte-for-byte.
- SHA-256 parity: hashes computed via `chia_sha2::Sha256` match the local hasher.
- Signing-message parity: `dig_block::block_signing_message` bytes match what the invalid-block verifier feeds `chia_bls::verify`.
- Epoch-constant parity: `dig_epoch::SLASH_LOOKBACK_EPOCHS` is the source of truth; never redefined here.

### 4. Required Test Infrastructure

```toml
# Cargo.toml [dev-dependencies]
chia-bls = { workspace = true }
chia-sdk-types = { workspace = true }    # run_puzzle
clvmr = { workspace = true }
proptest = { workspace = true }          # property tests
```

```rust
use dig_slashing::{
    SlashingEvidence, SlashingManager, verify_evidence, verify_appeal, ...
};
use dig_block::L2BlockHeader;
use dig_epoch::SLASH_LOOKBACK_EPOCHS;
use chia_bls::{sign, SecretKey, Signature, PublicKey};
use chia_protocol::Bytes32;
```

Mock trait impls live under `src/tests/`:
- `MockValidatorSet` (implements `ValidatorView` + `EffectiveBalanceView`)
- `MockBondEscrow`
- `MockRewardPayout` / `MockRewardClawback`
- `MockInvalidBlockOracle`
- `MockJustificationView` / `MockProposerView`

---

## Master Spec Reference

All requirements trace back to:
- [SPEC.md](../resources/SPEC.md) — §22 requirements catalogue
