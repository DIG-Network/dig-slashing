# dt-wf-test — Workflow: TDD — Write Failing Tests FIRST

**This is the most important step in the workflow.** Write the test before writing the implementation. The test defines the contract. If you cannot demonstrate a failing test, you do not understand the requirement well enough to implement it.

## HARD RULE: Test MUST fail before implementation exists

```
1. Write test based on spec's Test Plan section
2. Run test → MUST FAIL (compilation error OR assertion failure)
3. Only then proceed to dt-wf-implement
4. Implementation makes the test pass
```

If the test passes without any implementation, either:
- The requirement is already implemented (check TRACKING.yaml)
- Your test is wrong (it's not actually testing the requirement)

## Test File Naming — ONE FILE PER REQUIREMENT (§22.16)

```
tests/dsl_{NNN}_{short_name}_test.rs
```

Naming rules:
- `NNN` = 3-digit zero-padded DSL id (`001`..`130`)
- `short_name` = lowercase-snake-case summary from §22 catalogue
- Suffix is exactly `_test.rs`

Examples (from §22 of SPEC.md):

| DSL ID | File |
|--------|------|
| DSL-001 | `tests/dsl_001_offense_type_bps_mapping_test.rs` |
| DSL-013 | `tests/dsl_013_verify_proposer_slashing_preconditions_test.rs` |
| DSL-014 | `tests/dsl_014_verify_attester_double_vote_predicate_test.rs` |
| DSL-034 | `tests/dsl_034_proposer_appeal_headers_identical_sustained_test.rs` |
| DSL-081 | `tests/dsl_081_base_reward_formula_test.rs` |
| DSL-089 | `tests/dsl_089_inactivity_score_miss_in_stall_increment_test.rs` |
| DSL-096 | `tests/dsl_096_protection_surround_vote_self_check_test.rs` |
| DSL-127 | `tests/dsl_127_epoch_boundary_order_test.rs` |

## File Structure

```rust
//! Requirement DSL-013: verify_proposer_slashing enforces same-slot,
//! same-proposer, different-root, valid sigs, active validator.
//!
//! Test-driven verification of the proposer-slashing evidence verifier.
//! Tests written BEFORE implementation per TDD workflow.
//!
//! Proves DSL-013 by:
//!   - Constructing a valid ProposerSlashing with two signed headers at
//!     the same slot and proposer but with different message roots, and
//!     asserting verify_proposer_slashing returns Ok.
//!   - Mutating each precondition in turn (different slot, different
//!     proposer, identical roots, bad sig_a, bad sig_b, inactive
//!     validator) and asserting verify_proposer_slashing returns an
//!     error of the expected variant.

use dig_slashing::{
    verify_proposer_slashing, ProposerSlashing, SignedBlockHeader,
    SlashingError,
};
use dig_block::L2BlockHeader;
use chia_bls::{sign, SecretKey, Signature};
use chia_protocol::Bytes32;

#[test]
fn dsl_013_valid_proposer_slashing_verifies() {
    // Arrange: build two distinct L2BlockHeaders at the same slot with
    // the same proposer_index; sign both with the same BLS key.
    // Act: verify_proposer_slashing(evidence, &pk, network_id, current_epoch)
    // Assert: returns Ok(())
}

#[test]
fn dsl_013_rejects_different_slot() {
    // Arrange: headers at different slots.
    // Act: verify.
    // Assert: Err(SlashingError::InvalidProposerSlashing(_)) mentioning slot mismatch.
}

// ... one #[test] per row of the spec's Test Plan table ...
```

## Where to Find Test Cases

**Every requirement has a row in SPEC.md §22 and (for domain-split reqs) a dedicated spec with a Test Plan section.** Both are your test blueprint.

Open `docs/requirements/domains/{domain}/specs/DSL-NNN.md` and find:

```markdown
## Verification

### Test Plan

| Test | Type | Description | Expected Result |
|------|------|-------------|-----------------|
| test_name_1 | Unit | What it tests | Expected outcome |
| test_name_2 | Integration | What it tests | Expected outcome |
...
```

**Implement every row in the Test Plan table as a test function.** Each row = one `#[test]` function inside the single `dsl_NNN_*_test.rs` file for that requirement.

## Required Test Types

### Integration Tests (MUST for every requirement)

Full pipeline:
- Build test fixtures via `src/tests/fixtures.rs` (`test_keypair`, `test_header`, `test_attestation_data`, ...)
- Use `MockValidatorSet`, `MockEffectiveBalanceView`, `MockBondEscrow` from `src/tests/`
- Submit through the public API (`SlashingManager::submit_evidence`, `verify_evidence`, `verify_appeal`, ...)
- Assert on results, errors, state transitions

### Unit Tests

Individual function behavior:
- Input/output correctness
- Error path coverage
- Boundary conditions (off-by-one on epoch windows, BPS rounding, sqrt edge cases)

### Permutation Matrix

Cover all dimensions for each requirement:

| Dimension | Examples |
|-----------|----------|
| Valid inputs | Well-formed evidence, matching pubkey, within lookback |
| Invalid inputs | Bad signature, wrong proposer index, mismatched epochs, identical headers, empty intersection |
| Edge cases | Zero effective balance, max u64 score, empty attesting indices, appeal at exact window edge |
| Cryptographic | Signature mutation, pubkey mutation, Merkle proof tampering |
| State transitions | submit_evidence → submit_appeal (sustained) → revert, finalise, reorg |

## Running Tests

```bash
# Run the specific DSL test for the requirement
cargo test dsl_013

# Run with output visible
cargo test dsl_013 -- --nocapture

# Run all tests
cargo test
```

## When the Test Fails (Expected)

The test should fail because the function/type doesn't exist yet, or returns a default/wrong value. This is correct TDD behavior:

- **Compilation error** — the function signature doesn't exist → implement the signature stub
- **Assertion failure** — the function exists but returns wrong result → implement the logic
- **Panic** — `unimplemented!()` or `todo!()` → replace with real implementation

## When to Skip Test-First

Only skip TDD for:
- Documentation-only changes (tracking updates, spec corrections)
- Pure constant / configuration changes (Cargo.toml, `constants.rs` additions)
- Tracking file updates

For **everything else**: test first, then implement.

---

Navigation: Prev < [dt-wf-gather-context.md](dt-wf-gather-context.md) | Next > [dt-wf-implement.md](dt-wf-implement.md)
