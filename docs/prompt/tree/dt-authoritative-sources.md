# dt-authoritative-sources — Source Authority Hierarchy

## Authoritative Sources Table

| Source | Location | Purpose |
|--------|----------|---------|
| SPEC | `docs/resources/SPEC.md` | Master specification — all requirements derive from this |
| Requirements Catalogue | `docs/resources/SPEC.md` §22 | 130 requirements (DSL-001..130) with test-file mapping |
| NORMATIVE | `domains/{domain}/NORMATIVE.md` | Authoritative requirement statements (MUST/SHOULD/MAY) |
| Dedicated Spec | `domains/{domain}/specs/DSL-NNN.md` | Detailed specification per requirement + test plan |
| VERIFICATION | `domains/{domain}/VERIFICATION.md` | QA approach and status |
| TRACKING | `domains/{domain}/TRACKING.yaml` | Machine-readable status |
| IMPLEMENTATION_ORDER | `requirements/IMPLEMENTATION_ORDER.md` | Phased checklist of DSL-NNN IDs |
| SCHEMA | `requirements/SCHEMA.md` | Data model and conventions |
| REGISTRY | `requirements/REQUIREMENTS_REGISTRY.yaml` | Domain registry |
| Ethereum Consensus Reference | Ethereum consensus specs (Altair/Bellatrix) | Reference for participation + inactivity + slashing economics |
| Chia L1 Reference | `github.com/Chia-Network/chia-blockchain` | L1 behavior reference |

All `docs/` paths are relative to the crate root.

## Traceability Chain

```
IMPLEMENTATION_ORDER     (pick next [ ] item — a DSL-NNN id)
        |
        v
   SPEC.md §22           (catalogue row — one-line requirement statement + test file name)
        |
        v
   NORMATIVE.md          (authoritative MUST/SHOULD text, if domain-split)
        |
        v
   specs/DSL-NNN.md      (detailed spec + TEST PLAN)
        |
        v
   TOOLS                 (SocratiCode search, Repomix pack, GitNexus impact)
        |
        v
   WRITE FAILING TEST    (tests/dsl_NNN_<short_name>_test.rs — TDD)
        |
        v
   implement             (chia crates first, dig-block + dig-epoch reuse, minimal own code)
        |
        v
   VERIFICATION.md       (update QA status)
   TRACKING.yaml         (update machine-readable status)
   IMPLEMENTATION_ORDER  (check off [x])
```

## Authority Order

When sources conflict, the higher-ranked source wins:

1. **SPEC.md §22 catalogue row** — the canonical requirement text and test-file name
2. **NORMATIVE.md** — domain-split MUST/SHOULD statement
3. **Dedicated spec** (`specs/DSL-NNN.md`) — elaborates the requirement
4. **SPEC.md body** — master spec provides original context + data-model + formulas
5. **Ethereum consensus spec** — reference for reward/penalty + inactivity formulas
6. **Chia L1 source** — reference implementation for Chia-crate behavior questions
7. **Existing code** — lowest authority; may need correction

If SPEC §22 and NORMATIVE disagree, flag the conflict and ask before proceeding.

## Source Citations

Every dedicated spec contains a `Source Citations` section linking back to SPEC.md sections and/or upstream references (Ethereum Altair reward weights, Bellatrix inactivity quotient, etc.). Follow these links to verify understanding. The `Test Plan` section tells you exactly what tests to write — use it.

## Per-Domain Source Map

| Domain | DSL IDs | SPEC Sections | Ethereum References |
|--------|---------|---------------|----------------------|
| evidence | DSL-001..021 | §3.2–3.5, §5 | proposer / attester slashings |
| lifecycle | DSL-022..033 | §7 | validator lifecycle |
| appeal | DSL-034..073 | §3.6–3.7, §6 | (DIG-specific — no Ethereum analogue) |
| participation | DSL-074..086 | §3.10, §8 | Altair participation flag rewards |
| inactivity | DSL-087..093 | §3.10, §9 | Bellatrix inactivity leak |
| protection | DSL-094..101 | §14 | validator-client slashing protection |
| remark | DSL-102..120 | §16 | (DIG-specific) |
| bonds | DSL-121..126 | §12, §2.6 | (DIG-specific) |
| orchestration | DSL-127..130 | §10, §11, §13 | — |

---

Navigation: Prev < [dt-hard-rules.md](dt-hard-rules.md) | Next > [dt-tools.md](dt-tools.md)
