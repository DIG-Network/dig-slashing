# dt-wf-update-tracking — Workflow: Update Tracking Artifacts

After validation passes, update ALL THREE tracking artifacts for the completed requirement.

## 1. TRACKING.yaml

File: `docs/requirements/domains/{domain}/TRACKING.yaml`

```yaml
- id: DSL-NNN
  section: "Section Name"
  summary: "Brief title from SPEC §22 row"
  status: verified                # was: gap
  spec_ref: "docs/requirements/domains/{domain}/specs/DSL-NNN.md"
  catalogue_ref: "docs/resources/SPEC.md#dsl-NNN"
  tests:
    - dsl_NNN_<short_name>_test   # matches test file name exactly
  notes: "Brief description of implementation + any caveats"
```

### Status Values

| Status | Meaning |
|--------|---------|
| `gap` | Not started |
| `partial` | Some work done |
| `implemented` | Code written, tests pass |
| `verified` | Tests pass AND clippy/fmt clean AND audit greps clean |

## 2. VERIFICATION.md

File: `docs/requirements/domains/{domain}/VERIFICATION.md`

Update the row:

```markdown
| DSL-NNN | ✅ | Brief summary | Tests: dsl_NNN_<short_name>_test. Verified via TDD. |
```

## 3. IMPLEMENTATION_ORDER.md

File: `docs/requirements/IMPLEMENTATION_ORDER.md`

```markdown
# Before
- [ ] DSL-NNN — Description

# After
- [x] DSL-NNN — Description
```

## Checklist

- [ ] TRACKING.yaml updated (status, tests, notes)
- [ ] VERIFICATION.md row updated (status, approach)
- [ ] IMPLEMENTATION_ORDER.md checkbox changed `[ ]` to `[x]`
- [ ] Test file exists at `tests/dsl_NNN_<short_name>_test.rs` and matches the `tests:` entry in TRACKING.yaml exactly
- [ ] No other requirement accidentally modified

---

Navigation: Prev < [dt-wf-validate.md](dt-wf-validate.md) | Next > [dt-wf-commit.md](dt-wf-commit.md)
