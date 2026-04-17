# Start

## Immediate Actions

1. **Sync**
   ```bash
   git fetch origin && git pull origin main
   ```

2. **Check tools — ALL THREE MUST BE FRESH**
   ```bash
   npx gitnexus status          # GitNexus index fresh?
   npx gitnexus analyze         # Update if stale
   # SocratiCode: verify Docker running, index current
   codebase_status {}            # SocratiCode MCP status
   ```
   **Do not proceed until tools are confirmed operational.** Coding without tools leads to redundant work and missed dependencies.

3. **Pick work** — open `docs/requirements/IMPLEMENTATION_ORDER.md`
   - Choose the first `- [ ]` item (format: `DSL-NNN`)
   - Every `- [x]` is done on main — skip it
   - Work phases in order: Phase 0 before Phase 1, etc.

4. **Pack context — BEFORE reading any code**
   ```bash
   npx repomix@latest src -o .repomix/pack-src.xml
   npx repomix@latest tests -o .repomix/pack-tests.xml
   ```

5. **Search with SocratiCode — BEFORE reading files**
   ```
   codebase_search { query: "slashing evidence verify proposer" }
   codebase_graph_query { filePath: "src/manager.rs" }
   ```

6. **Read spec** — follow the full trace:
   - `docs/resources/SPEC.md` §22 → requirement catalogue row for `DSL-NNN`
   - `docs/requirements/domains/{domain}/NORMATIVE.md#DSL-NNN` → authoritative statement (if domain-split)
   - `docs/requirements/domains/{domain}/specs/DSL-NNN.md` → detailed spec + **Test Plan**
   - `docs/requirements/domains/{domain}/VERIFICATION.md` → verification approach
   - `docs/requirements/domains/{domain}/TRACKING.yaml` → current status

7. **Continue** → [dt-wf-select.md](tree/dt-wf-select.md)

---

## Hard Requirements

1. **Use chia crate ecosystem first** — never reimplement what `chia-bls`, `chia-protocol`, `chia-sha2`, `chia-sdk-types`, `clvm-utils` provide.
2. **Use DIG crate ecosystem second** — `dig-block` for `L2BlockHeader` + signing messages, `dig-epoch` for lookback constants and height↔epoch math, `dig-constants` for `NetworkConstants`.
3. **No custom BLS** — `chia_bls::verify`, `chia_bls::aggregate`, `chia_bls::aggregate_verify` only.
4. **No custom hashing** — `chia_sha2::Sha256` only.
5. **No custom Merkle** — `chia_sdk_types::MerkleTree` / `MerkleProof` + `clvm_utils::tree_hash`.
6. **No custom signing messages** — `dig_block::block_signing_message`, `AttestationData::signing_root` (this crate) using `DOMAIN_BEACON_ATTESTER` / `DOMAIN_BEACON_PROPOSER`.
7. **No custom epoch arithmetic** — `dig_epoch::SLASH_LOOKBACK_EPOCHS`, `CORRELATION_WINDOW_EPOCHS`, `BLOCKS_PER_EPOCH` — re-export, don't redefine.
8. **Re-export, don't redefine** — `Coin`, `CoinSpend`, `SpendBundle`, `Bytes32`, `Signature`, `PublicKey` come from upstream via chia/dig-block.
9. **TEST FIRST (TDD)** — write the failing test before writing implementation code. The test defines the contract. §22 of SPEC.md tells you the requirement; the dedicated spec's Test Plan section tells you the cases.
10. **One requirement per commit** — one `DSL-NNN` per commit; don't batch unrelated work.
11. **Update tracking after each requirement** — VERIFICATION.md, TRACKING.yaml, IMPLEMENTATION_ORDER.md.
12. **SocratiCode before file reads** — search semantically first, read targeted files second.
13. **Repomix before implementation** — pack relevant scope for full context.
14. **GitNexus before refactoring** — check dependency impact before renaming or moving symbols.
15. **Follow the decision tree to completion** — dt-wf-select through dt-wf-commit, no shortcuts.
16. **Every requirement has its own test file** — `tests/dsl_NNN_<short_name>_test.rs`, per §22.16 of SPEC.md.
17. **Validator-only scope** — no DFSP, no storage-provider slashing, no CID / bond-coin / availability-attestation code here.

---

## Tech Stack

| Component | Crate | Version |
|-----------|-------|---------|
| Block types + signing messages | `dig-block` | 0.1.0 |
| Epoch arithmetic + lookback | `dig-epoch` | 0.1.0 |
| Network constants | `dig-constants` | 0.1.0 |
| Protocol types | `chia-protocol` | 0.26 |
| BLS signatures | `chia-bls` | 0.26 |
| SHA-256 | `chia-sha2` | 0.26 |
| Merkle tree + run_puzzle (dev) | `chia-sdk-types` | 0.30 |
| CLVM tree-hash | `clvm-utils` | 0.26 |
| CLVM allocator (dev) | `clvmr` | 0.11 |
| Integer sqrt | `num-integer` | latest |
| Error handling | `thiserror` | 2 |
| Serialization | `serde`, `serde_json`, `serde_bytes`, `bincode` | latest |
| Hex encoding | `hex` | latest |
| Logs | `tracing` | latest |
| Optional threadsafe | `parking_lot` | latest |
