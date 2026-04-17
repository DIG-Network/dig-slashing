# dt-wf-implement — Workflow: Implement Against Spec

**You should already have a failing test from dt-wf-test.** Your goal now is to make that test pass with the minimal correct implementation.

## Step 0: Verify Failing Test

Before writing any implementation code, confirm the test fails:

```bash
cargo test dsl_NNN
```

If the test passes, stop — either the requirement is already implemented or the test is wrong.

## Step 1: SocratiCode + GitNexus Checks

Before writing implementation code:

```
codebase_search { query: "function or type being implemented" }
codebase_graph_query { filePath: "file to modify" }
```

If modifying existing code:
```
gitnexus_impact({target: "symbol", direction: "upstream"})
```

## Step 2: Use Chia + DIG Crates First

Check crates in this order before writing custom code:

| Priority | Crate | Provides |
|----------|-------|----------|
| 1 | `chia-bls` | `Signature`, `PublicKey`, `verify`, `aggregate`, `aggregate_verify` |
| 2 | `chia-protocol` | `Bytes32`, `Coin`, `CoinSpend`, `SpendBundle` |
| 3 | `chia-sha2` | `Sha256` (every hash) |
| 4 | `chia-sdk-types` | `MerkleTree`, `MerkleProof` (participation witness, reorg snapshot), `run_puzzle` (dev) |
| 5 | `clvm-utils` | `tree_hash` (REMARK puzzle-hash) |
| 6 | `dig-block` | `L2BlockHeader`, `block_signing_message`, `beacon_block_header_signing_root`, `attestation_data_signing_root` |
| 7 | `dig-epoch` | `SLASH_LOOKBACK_EPOCHS`, `CORRELATION_WINDOW_EPOCHS`, `BLOCKS_PER_EPOCH` |
| 8 | `dig-constants` | `NetworkConstants` |
| 9 | `num-integer` | `Roots::sqrt` (base reward) |

Only write custom logic when no upstream crate provides the needed functionality.

## Step 3: Smallest Change Principle

- **Match the spec exactly.** Implement what the dedicated spec + SPEC.md §22 row say, nothing more.
- **Make the failing test pass.** That is the only goal.
- **No features beyond the requirement.** If DSL-013 says "verify_proposer_slashing preconditions", build that. Do not add caching, logging, or metrics.
- **No speculative abstractions.** No traits "for future use." No generic parameters unless the spec requires them.

## Step 4: Module Placement

| Domain | Directory | Primary Files |
|--------|-----------|---------------|
| Evidence types + verify | `src/evidence/` | `offense.rs`, `checkpoint.rs`, `attestation_data.rs`, `indexed_attestation.rs`, `proposer_slashing.rs`, `attester_slashing.rs`, `invalid_block.rs`, `envelope.rs`, `verify.rs` |
| Appeal types + verify + adjudicate | `src/appeal/` | `proposer.rs`, `attester.rs`, `invalid_block.rs`, `envelope.rs`, `verify.rs`, `adjudicator.rs` |
| Manager + lifecycle | `src/` + `src/pending.rs`, `src/manager.rs`, `src/lifecycle.rs`, `src/result.rs` |
| Participation | `src/participation/` | `flags.rs`, `tracker.rs`, `timeliness.rs`, `rewards.rs` |
| Inactivity | `src/inactivity/` | `score.rs`, `penalty.rs` |
| Orchestration | `src/orchestration.rs`, `src/system.rs` |
| Traits | `src/traits.rs` |
| REMARK | `src/remark/` | `evidence_wire.rs`, `appeal_wire.rs`, `parse.rs`, `policy.rs` |
| Protection | `src/protection.rs` |
| Constants / Errors | `src/constants.rs`, `src/error.rs` |

## Step 5: Required Commenting

Every piece of written code must carry **high-signal, LLM-friendly comments**:

- **Module-level** `//!` doc linking to SPEC.md section and (if Ethereum-parity) to the upstream spec.
- **Item-level** `///` doc describing usage, rationale, and the DSL-NNN(s) it satisfies.
- **Inline** `//` for non-obvious decisions (rounding policy, saturating arithmetic, BLS domain choice).

Template:

```rust
//! Per-offense evidence verifiers (SPEC §5).
//!
//! Every function here is pure and deterministic over its inputs. No I/O,
//! no wall-clock. Two honest validators with the same view always reach the
//! same verdict.

/// Verify a `ProposerSlashing` against the claimed proposer's public key.
///
/// Implements SPEC §5.2. Satisfies DSL-013.
///
/// # Preconditions
/// 1. headers have same slot
/// 2. headers have same proposer_index
/// 3. header messages differ (by hash)
/// 4. both signatures parse (96 bytes G2)
/// 5. validator is active at header.epoch
/// 6. both signatures verify under the validator's pubkey against the
///    `dig_block::block_signing_message` domain-bound message.
///
/// # Returns
/// `Ok(())` on a well-formed equivocation proof. Otherwise a
/// [`SlashingError::InvalidProposerSlashing`] with a human-readable reason.
pub fn verify_proposer_slashing(...) -> Result<(), SlashingError> { ... }
```

## Implementation Checklist

Before moving to validation, verify:

- [ ] The failing test from dt-wf-test now PASSES
- [ ] Code matches the spec's acceptance criteria
- [ ] Uses chia + DIG crate functions where available (Rule 1, 2)
- [ ] No custom BLS (Rule 3)
- [ ] No custom hashing (Rule 4)
- [ ] No custom signing messages (Rule 5)
- [ ] No custom Merkle (Rule 6)
- [ ] No custom epoch arithmetic (Rule 7)
- [ ] Validator-only scope (Rule 8) — no DFSP references
- [ ] Re-exports upstream types (Rule 9)
- [ ] Comprehensive module + item + inline comments
- [ ] New public API is re-exported in `src/lib.rs`
- [ ] New public symbol traces to a DSL-NNN in SPEC §22

---

Navigation: Prev < [dt-wf-test.md](dt-wf-test.md) | Next > [dt-wf-validate.md](dt-wf-validate.md)
