# Repomix — Context Packing for LLMs

## What

Packs your codebase into a single AI-friendly file. Supports token counting, tree-sitter compression, and gitignore-aware file selection. Output formats: XML, Markdown, JSON.

## HARD RULE

**Always pack context before starting implementation.** Fresh context = better code. Pack the scope you are about to modify so the LLM has complete awareness.

## Setup

### Global Install

```bash
npm install -g repomix
```

### Or Use Directly via npx

```bash
npx repomix@latest
```

No additional configuration required. Repomix reads `.gitignore` automatically.

## Common Commands for dig-slashing

### Pack Implementation Scope

```bash
npx repomix@latest src -o .repomix/pack-src.xml
```

### Pack Tests

```bash
npx repomix@latest tests -o .repomix/pack-tests.xml
```

### Pack Requirements for a Domain

```bash
# Evidence domain (DSL-001..021)
npx repomix@latest docs/requirements/domains/evidence -o .repomix/pack-evidence-reqs.xml

# Lifecycle (DSL-022..033)
npx repomix@latest docs/requirements/domains/lifecycle -o .repomix/pack-lifecycle-reqs.xml

# Appeal (DSL-034..073)
npx repomix@latest docs/requirements/domains/appeal -o .repomix/pack-appeal-reqs.xml

# Participation (DSL-074..086)
npx repomix@latest docs/requirements/domains/participation -o .repomix/pack-participation-reqs.xml

# Inactivity (DSL-087..093)
npx repomix@latest docs/requirements/domains/inactivity -o .repomix/pack-inactivity-reqs.xml

# Protection (DSL-094..101)
npx repomix@latest docs/requirements/domains/protection -o .repomix/pack-protection-reqs.xml

# Remark (DSL-102..120)
npx repomix@latest docs/requirements/domains/remark -o .repomix/pack-remark-reqs.xml

# Bonds (DSL-121..126)
npx repomix@latest docs/requirements/domains/bonds -o .repomix/pack-bonds-reqs.xml

# Orchestration (DSL-127..130)
npx repomix@latest docs/requirements/domains/orchestration -o .repomix/pack-orchestration-reqs.xml

# All requirements
npx repomix@latest docs/requirements -o .repomix/pack-requirements.xml
```

### Pack the Full Spec

```bash
npx repomix@latest docs/resources -o .repomix/pack-spec.xml
```

### Pack with Compression

For larger scopes where token count matters:

```bash
npx repomix@latest src --compress -o .repomix/pack-src-compressed.xml
```

Compression uses tree-sitter to retain structure while reducing token count.

### Pack Multiple Scopes

```bash
# Implementation + tests together
npx repomix@latest src tests -o .repomix/pack-impl-and-tests.xml

# Evidence domain + appeal domain together
# (helpful when wiring verify_appeal against PendingSlash ← submit_evidence)
npx repomix@latest docs/requirements/domains/evidence docs/requirements/domains/appeal \
  -o .repomix/pack-evidence-and-appeal.xml
```

## Output Directory

All pack files go to `.repomix/` which is gitignored. These are ephemeral working context files — regenerated as needed and never committed.

```
.repomix/
├── pack-src.xml
├── pack-tests.xml
├── pack-evidence-reqs.xml
├── pack-appeal-reqs.xml
├── pack-participation-reqs.xml
├── pack-spec.xml
└── pack-src-compressed.xml
```

## Workflow Integration

| Workflow Step | How to Use Repomix |
|--------------|-------------------|
| **Gather context** | Pack the scope you are about to work on (implementation + requirements) |
| **Before implementing** | Pack `src/` + `tests` for full implementation context |
| **Before testing** | Pack `tests/` to see existing DSL test patterns and match style |
| **Cross-domain work** | Pack multiple domains to see relationships between DSL requirements |

## Example Session

When starting work on DSL-013 (verify_proposer_slashing):

```bash
# Pack the implementation scope
npx repomix@latest src -o .repomix/pack-src.xml

# Pack existing tests for pattern reference (previous DSL tests show the style)
npx repomix@latest tests -o .repomix/pack-tests.xml

# Pack the evidence domain requirements
npx repomix@latest docs/requirements/domains/evidence -o .repomix/pack-evidence-reqs.xml
```

Now the LLM has full context of:
- Current implementation state (verifiers, evidence types)
- Existing test patterns to match (comment styles, fixture usage, assertion patterns)
- All evidence-domain requirements and their specs

## Tips

- Regenerate packs when switching between requirements — stale context leads to stale code.
- Use `--compress` for large scopes (full `src/`) to keep token count manageable.
- Pack requirements alongside code when you need to verify spec compliance.
- The XML format is default and works well with most LLM contexts. Use `--style markdown` if you prefer Markdown output.
- Check `.gitignore` includes `.repomix/` — these files should never be committed.
- For cross-crate work (e.g. wiring against `dig-block`), you can pack the sibling crate too:
  ```bash
  npx repomix@latest ../dig-block/src -o .repomix/pack-dig-block.xml
  ```
