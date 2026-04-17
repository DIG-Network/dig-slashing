# dt-wf-commit — Workflow: Commit, Push, Loop

One requirement per commit. Include code, tests, and tracking updates together.

## Procedure

### Step 1: Update GitNexus

```bash
npx gitnexus analyze
```

### Step 2: Stage Files

Stage exactly the files for this requirement:

```bash
git add src/evidence/verify.rs \
        tests/dsl_013_verify_proposer_slashing_preconditions_test.rs \
        docs/requirements/domains/evidence/TRACKING.yaml \
        docs/requirements/domains/evidence/VERIFICATION.md \
        docs/requirements/IMPLEMENTATION_ORDER.md
```

**Include:** Implementation + the dedicated test file + tracking.
**Exclude:** Unrelated changes, `.repomix/` files, other DSL tests you didn't touch.

### Step 3: Commit

```bash
git commit -m "feat(evidence): implement DSL-013 verify_proposer_slashing preconditions"
```

Format: `type(scope): imperative subject — reference DSL-NNN in subject`.

### Step 4: Push

```bash
git push origin main
```

### Step 5: Update GitNexus Index

```bash
npx gitnexus analyze
```

## What to Avoid

- **Mixing requirement IDs** — one commit = one requirement
- **Incomplete TDD cycle** — test MUST exist and pass before commit
- **Missing tracking updates** — code + tests + tracking = one atomic unit
- **Missing dedicated test file** — every `DSL-NNN` must have its own `tests/dsl_NNN_*_test.rs` (Rule 11)
- **Committing `.repomix/` files** — gitignored
- **Unrelated reformats** — run `cargo fmt` as its own commit if needed

## Loop — RETURN TO THE BEGINNING

**The decision tree cycle is complete for this requirement. Start the next one.**

**Next requirement → [dt-wf-select.md](dt-wf-select.md)**

Follow the full cycle again:
1. Select requirement from IMPLEMENTATION_ORDER (`DSL-NNN`)
2. Gather context with all three tools
3. Write failing test (TDD) in `tests/dsl_NNN_<short_name>_test.rs`
4. Implement to make test pass (chia + DIG crates first)
5. Validate (cargo test + clippy + fmt + audit greps)
6. Update tracking artifacts
7. Commit and push

**Do not skip any step. Do not batch multiple requirements. Complete the full decision tree for every single requirement.**

---

Navigation: Prev < [dt-wf-update-tracking.md](dt-wf-update-tracking.md) | Loop > [dt-wf-select.md](dt-wf-select.md)
