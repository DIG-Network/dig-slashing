# dt-git — Git Workflow

## Sync Before Work

```bash
git fetch origin && git pull origin main
```

Always sync before selecting work. Treat `[x]` items as done after pull.

## Commit Format

```
type(scope): imperative subject — DSL-NNN
```

### Types

| Type | When |
|------|------|
| `feat` | New functionality (implementing a requirement) |
| `fix` | Bug fix |
| `docs` | Documentation only (tracking updates, spec corrections) |
| `chore` | Build, deps, tooling |
| `refactor` | Code restructuring without behavior change |
| `test` | Test-only changes |

### Scopes

| Scope | Maps to | DSL range |
|-------|---------|-----------|
| `evidence` | Offense + evidence + verification | DSL-001..021 |
| `lifecycle` | Optimistic slashing lifecycle | DSL-022..033 |
| `appeal` | Fraud-proof appeal system | DSL-034..073 |
| `participation` | Attestation participation + rewards | DSL-074..086 |
| `inactivity` | Inactivity accounting | DSL-087..093 |
| `protection` | Validator-local slashing protection | DSL-094..101 |
| `remark` | REMARK admission for evidence + appeal | DSL-102..120 |
| `bonds` | Bond escrow + rewards routing | DSL-121..126 |
| `orchestration` | Epoch boundary + genesis + reorg | DSL-127..130 |
| `api` | Public crate API (lib.rs, re-exports) | — |
| `deps` | Cargo.toml dependency changes | — |

### Examples

```
feat(evidence): implement DSL-001 OffenseType BPS mapping
feat(evidence): implement DSL-013 verify_proposer_slashing preconditions
test(appeal): add DSL-041 attester appeal attestations-identical test
docs(evidence): update TRACKING for DSL-001 through DSL-010
feat(participation): implement DSL-081 base_reward formula
fix(appeal): correct bond-split rounding in DSL-068
```

## Push

```bash
git push origin main
```

Always push after commit.

---

Navigation: Prev < [dt-tools.md](dt-tools.md) | Next > [dt-wf-select.md](dt-wf-select.md)
