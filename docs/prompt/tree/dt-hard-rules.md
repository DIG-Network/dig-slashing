# dt-hard-rules — Non-Negotiable Rules

Every rule below is a hard constraint. Violating any one is a blocking defect.

## Rule 1: Use chia crate ecosystem first

Before writing ANY custom code, check these crates:

- `chia-bls` — `Signature`, `PublicKey`, `verify`, `aggregate`, `aggregate_verify`, `sign` (dev)
- `chia-protocol` — `Bytes32`, `Coin`, `CoinSpend`, `SpendBundle`
- `chia-sha2` — `Sha256` (every hash in this crate)
- `chia-sdk-types` — `MerkleTree`, `MerkleProof` (for reorg-snapshot + appeal witness); `run_puzzle` (dev)
- `clvm-utils` — `tree_hash`, `TreeHash` (for REMARK puzzle-hash derivation)

## Rule 2: Use DIG crate ecosystem second

- `dig-block` — `L2BlockHeader`, `block_signing_message`, `beacon_block_header_signing_root`, `attestation_data_signing_root`
- `dig-epoch` — `SLASH_LOOKBACK_EPOCHS`, `CORRELATION_WINDOW_EPOCHS`, `BLOCKS_PER_EPOCH`, height↔epoch helpers
- `dig-constants` — `NetworkConstants` (network id injected as parameter)

Re-export; don't redefine.

## Rule 3: No custom BLS

All BLS ops go through `chia_bls`. No hand-rolled verify, no custom pairing, no custom aggregation. Signature width = 96 bytes G2; pubkey width = 48 bytes G1. These are constants from `chia-bls` — do not redefine them.

## Rule 4: No custom hashing

All SHA-256 ops go through `chia_sha2::Sha256`. Domain separation uses the constants in §2.10 of SPEC.md (`DOMAIN_SLASHING_EVIDENCE`, `DOMAIN_BEACON_PROPOSER`, `DOMAIN_BEACON_ATTESTER`, ...).

## Rule 5: No custom signing messages

Proposer-slashing verifier calls `dig_block::block_signing_message(network_id, epoch, block_root, proposer_index)`. Attester-slashing verifier calls `AttestationData::signing_root(network_id)` (this crate) which uses `DOMAIN_BEACON_ATTESTER`. Never hand-roll domain bytes.

## Rule 6: No custom Merkle

Participation-witness + reorg-snapshot Merkle use `chia_sdk_types::MerkleTree` / `MerkleProof`. REMARK puzzle-hash uses `clvm_utils::tree_hash`. No custom tree builders.

## Rule 7: No custom epoch arithmetic

`SLASH_LOOKBACK_EPOCHS`, `CORRELATION_WINDOW_EPOCHS`, `BLOCKS_PER_EPOCH`, `L2_BLOCK_TIME_MS` all live in `dig-epoch`. Re-export through `dig_slashing::constants` — do not redefine.

## Rule 8: Validator-only scope — no DFSP

This crate has no knowledge of CIDs, bond coins, availability attestations, storage witnesses, or any other DFSP primitive. If a requirement tempts you to import DFSP concepts, stop — wrong crate.

## Rule 9: Re-export, don't redefine

`Coin`, `CoinSpend`, `SpendBundle`, `Bytes32`, `Signature`, `PublicKey`, `L2BlockHeader`, `NetworkConstants`, `SLASH_LOOKBACK_EPOCHS` — all come from upstream. Never create your own versions.

## Rule 10: TEST FIRST (TDD) — mandatory

```
1. Read SPEC.md §22 row + dedicated spec + Test Plan
2. Write test in tests/dsl_NNN_<short_name>_test.rs
3. Run test → MUST FAIL (compilation error OR assertion failure)
4. Only then proceed to dt-wf-implement
5. Implementation makes the test pass
```

Skipping the test-first step is a blocking defect.

## Rule 11: One test file per requirement

Every `DSL-NNN` has exactly one `tests/dsl_NNN_<short_name>_test.rs` file. Per §22.16 of SPEC.md:
1. Every requirement must have exactly one `dsl_NNN_*_test.rs` file.
2. Every test file begins with a doc comment `//! Requirement DSL-NNN: <text>` matching §22 exactly.
3. CI verifies 1:1 correspondence.

## Rule 12: One requirement per commit

Each commit implements exactly one `DSL-NNN` requirement. No batching, no partial implementations.

## Rule 13: Update tracking after each requirement

After implementing a requirement, update ALL THREE:
- `docs/requirements/domains/{domain}/TRACKING.yaml` — status, tests, notes
- `docs/requirements/domains/{domain}/VERIFICATION.md` — status column, verification approach
- `docs/requirements/IMPLEMENTATION_ORDER.md` — check off the `[ ]`

## Rule 14: SocratiCode search before file reads

Always `codebase_search` before reading files. Search finds the right files; you read targeted sections.

## Rule 15: Repomix pack before implementation

Before writing implementation code:
```bash
npx repomix@latest <scope> -o .repomix/pack-<scope>.xml
```

## Rule 16: GitNexus impact check before refactoring

Before renaming symbols or restructuring modules:
```bash
npx gitnexus analyze
gitnexus_impact({target: "symbol", direction: "upstream"})
```

## Rule 17: Follow the decision tree to completion

The workflow cycle (dt-wf-select through dt-wf-commit) MUST be followed in strict order. No shortcuts. No skipping steps.

## Rule 18: No async/IO/storage in core logic

Core slashing logic (verifiers, manager, participation tracker, inactivity tracker) is pure in-memory. No `async`, no `tokio`, no `std::fs`, no `std::net`. Persistence is the caller's job (e.g. `SlashingProtection::load`/`save` on disk is scoped to validator-local JSON only).

## Rule 19: Every state change is deterministic

No wall-clock time. No RNG. No ambient system calls. All state changes are a pure function of `(current inputs, injected trait impls)`. Honest validators must never diverge.

## Rule 20: Tools MUST be used before writing code

Do not write a single line of implementation code until you have:
1. Searched with SocratiCode (`codebase_search`)
2. Packed context with Repomix (`npx repomix@latest`)
3. Checked impact with GitNexus (if modifying existing code)

Not optional. Prevents redundant work and missed dependencies.

## Post-Pull Rule

After `git pull`: treat `[x]` items in IMPLEMENTATION_ORDER.md as done. Only `[ ]` items are selectable for work. Never re-implement a checked item.

---

Navigation: Prev < [dt-role.md](dt-role.md) | Next > [dt-authoritative-sources.md](dt-authoritative-sources.md)
