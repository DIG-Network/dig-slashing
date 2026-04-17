# dt-wf-validate — Workflow: Validate

Run the full validation suite before committing. All checks must pass.

## Required Checks

```bash
# All tests pass (including the new DSL test)
cargo test

# No clippy warnings (treated as errors)
cargo clippy -- -D warnings

# Formatting is clean
cargo fmt --check
```

## Targeted Checks

```bash
# Run the specific DSL test
cargo test dsl_013

# Run with output visible
cargo test dsl_013 -- --nocapture
```

## Tool Checks

### No circular dependencies

```
codebase_graph_circular {}
```

### Change scope verification

```
gitnexus_detect_changes({scope: "staged"})
```

Verify changes only affect expected files and symbols.

## Critical Audit Checks

### No custom BLS

```bash
grep -rE "blst|pairing\(|Fp::|G1::|G2::" src/
# Must find nothing — use chia_bls only
```

### No custom hashing

```bash
grep -rE "sha2::|sha256\s*\(|Sha256::digest" src/
# Only chia_sha2 imports allowed
```

### No IO / async in core

```bash
grep -rE "std::fs|std::net|tokio|async fn|reqwest|sqlx" src/
# Must find nothing (except src/protection.rs which is validator-local JSON disk I/O)
```

### No DFSP references

```bash
grep -rE "\bDFSP\b|\bCid\b|SlashBond|retrievability_bond|availability_attestation" src/
# Must find nothing — validator-only scope (Rule 8)
```

### No custom opcode / constant redefinition

```bash
grep -rE "pub const.*=\s*500;?\s*$|pub const.*=\s*300;?\s*$" src/
# Only constants.rs should hold penalty BPS; every other file imports them
```

### No reimplemented epoch constants

```bash
grep -rE "pub const SLASH_LOOKBACK_EPOCHS|pub const CORRELATION_WINDOW_EPOCHS|pub const BLOCKS_PER_EPOCH" src/
# Should only appear as `pub use dig_epoch::...` in constants.rs
```

### Test-file traceability

```bash
# Every DSL-NNN in IMPLEMENTATION_ORDER marked [x] must have a matching test file
for n in $(grep -oE 'DSL-[0-9]{3}' docs/requirements/IMPLEMENTATION_ORDER.md | grep -v '\[ \]' | sort -u); do
  nnn="${n#DSL-}"
  ls tests/dsl_${nnn}_*_test.rs > /dev/null 2>&1 || echo "MISSING: $n"
done
```

## Failure Handling

- **Test failure:** Fix the implementation to match the spec, not the test. The spec is authoritative. If the spec is wrong, flag it.
- **Clippy warning:** Fix it. No `#[allow(...)]` without justification.
- **Format failure:** Run `cargo fmt` and include formatting in the commit.
- **Circular dependency:** Restructure to break the cycle.
- **Unexpected change scope:** Investigate — did you accidentally modify unrelated code?
- **DFSP reference found:** Remove it. Wrong crate.
- **Missing test file:** Every `[x]` requires a dedicated test file. Rule 11.

## All Checks Passed

When all checks are green, proceed to tracking updates.

---

Navigation: Prev < [dt-wf-implement.md](dt-wf-implement.md) | Next > [dt-wf-update-tracking.md](dt-wf-update-tracking.md)
