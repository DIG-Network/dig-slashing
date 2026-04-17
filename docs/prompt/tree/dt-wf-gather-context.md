# dt-wf-gather-context — Workflow: Gather Context

**MUST use all three tools during context gathering.** This step ensures you have complete understanding before writing any code or tests. Do NOT skip this step.

## Step 0: SocratiCode Search First

Before reading any files, search for related code:

```
codebase_search { query: "requirement topic or key concept" }
```

Examples:
- `codebase_search { query: "verify proposer slashing signature BLS" }`
- `codebase_search { query: "participation flags timely source target head" }`
- `codebase_search { query: "bond escrow lock forfeit" }`
- `codebase_search { query: "SlashingManager submit_evidence" }`

Understand the dependency structure of relevant files:

```
codebase_graph_query { filePath: "src/manager.rs" }
codebase_graph_query { filePath: "src/appeal/verify.rs" }
```

Search for related patterns in context artifacts:

```
codebase_context_search { query: "Ethereum proportional slashing" }
```

## Step 1: Repomix Pack

Pack the scope you are about to work on:

```bash
# Pack implementation scope
npx repomix@latest src -o .repomix/pack-src.xml

# Pack tests for pattern reference (CRITICAL for TDD step)
npx repomix@latest tests -o .repomix/pack-tests.xml

# Pack the domain requirements
npx repomix@latest docs/requirements/domains/<domain> -o .repomix/pack-<domain>-reqs.xml

# Pack the full spec (once per session is usually enough)
npx repomix@latest docs/resources/SPEC.md -o .repomix/pack-spec.xml
```

**Packing tests is especially important** — you need to match existing test patterns when writing your failing test in the next step. Every requirement has its own test file, so pack `tests/` to see the naming + comment conventions.

## Step 2: Requirements Trace

Read the full requirements chain for the selected `DSL-NNN`:

1. **SPEC.md §22** — Read the catalogue row.
2. **NORMATIVE.md** — Read `#DSL-NNN` section for the authoritative statement (if domain-split).
3. **specs/DSL-NNN.md** — Read the detailed specification.
4. **Test Plan section** — This tells you exactly what tests to write. Copy the test table.
5. **Source citations** — Follow links to SPEC.md sections and, where relevant, Ethereum consensus spec entries.
6. **References section** — Check related DSL IDs in other domains (e.g. an appeal test may reference the evidence it rebuts).
7. **TRACKING.yaml** — Current status (should be `gap`).

## Step 3: Cross-References and Related Code

- Check the `References` section in the dedicated spec for related DSL IDs.
- Search for code that implements those related requirements:
  ```
  codebase_search { query: "related requirement function or type" }
  ```
- If modifying existing code, check impact:
  ```
  gitnexus_impact({target: "SlashingManager::submit_evidence", direction: "upstream"})
  ```

## Step 4: Existing Test Patterns

- Search for existing tests to match their style:
  ```
  codebase_search { query: "dsl proposer slashing test pattern" }
  ```
- Each test file begins with a doc comment `//! Requirement DSL-NNN: <text>` (§22.16). Match the pattern of the closest-related DSL test file.
- Understand the test infrastructure: mock trait impls live under `src/tests/` (`MockValidatorSet`, `MockEffectiveBalanceView`, `MockBondEscrow`, ...).

## Verification Checklist

Before proceeding to the test step, confirm:
- [ ] SocratiCode search completed
- [ ] Repomix context packed (src + tests + domain requirements)
- [ ] Full spec read including Test Plan
- [ ] Cross-references checked (related DSL IDs)
- [ ] Existing test patterns reviewed
- [ ] GitNexus impact checked (if modifying existing code)
- [ ] Test file name confirmed: `tests/dsl_NNN_<short_name>_test.rs`

**Do NOT proceed to dt-wf-test until all tools have been used.**

---

Navigation: Prev < [dt-wf-select.md](dt-wf-select.md) | Next > [dt-wf-test.md](dt-wf-test.md)
