# dig-slashing Requirements

Formal requirements for the dig-slashing crate, following the same two-tier requirements structure as dig-mempool with full traceability.

## Quick Links

- [SCHEMA.md](SCHEMA.md) — Data model and conventions
- [REQUIREMENTS_REGISTRY.yaml](REQUIREMENTS_REGISTRY.yaml) — Central domain registry
- [IMPLEMENTATION_ORDER.md](IMPLEMENTATION_ORDER.md) — Phased implementation checklist
- [domains/](domains/) — All requirement domains

## Structure

```
requirements/
├── README.md                    # This file
├── SCHEMA.md                    # Data model and conventions
├── REQUIREMENTS_REGISTRY.yaml   # Central registry
├── IMPLEMENTATION_ORDER.md      # Phased implementation checklist (166 DSL-NNN)
└── domains/
    ├── evidence/                # DSL-001..021, 157..158             Offense + verification + serde
    ├── lifecycle/               # DSL-022..033, 146..152, 162..163   Lifecycle + book + queries + serde
    ├── appeal/                  # DSL-034..073, 159..161, 164        Appeal + hash + serde
    ├── participation/           # DSL-074..086, 153..154             Participation + reorg + serde
    ├── inactivity/              # DSL-087..093, 155                  Inactivity + reorg
    ├── protection/              # DSL-094..101, 156                  Validator-local protection
    ├── remark/                  # DSL-102..120                       REMARK admission
    ├── bonds/                   # DSL-121..126, 166                  Bonds + BondTag variants
    ├── orchestration/           # DSL-127..130, 165                  Orchestration + reorg + serde
    └── traits/                  # DSL-131..145                       External-state trait contracts
```

## Three-Document Pattern

Each domain contains:

| File | Purpose |
|------|---------|
| `NORMATIVE.md` | Authoritative requirement statements (MUST/SHOULD/MAY) |
| `VERIFICATION.md` | QA approach and status per requirement |
| `TRACKING.yaml` | Machine-readable status, tests, and notes |

## Specification Files

Individual requirement specifications live in each domain's `specs/` subdirectory:

```
domains/
├── evidence/specs/              # DSL-001.md .. DSL-021.md
├── lifecycle/specs/             # DSL-022.md .. DSL-033.md
├── appeal/specs/                # DSL-034.md .. DSL-073.md
├── participation/specs/         # DSL-074.md .. DSL-086.md
├── inactivity/specs/            # DSL-087.md .. DSL-093.md
├── protection/specs/            # DSL-094.md .. DSL-101.md
├── remark/specs/                # DSL-102.md .. DSL-120.md
├── bonds/specs/                 # DSL-121.md .. DSL-126.md
└── orchestration/specs/         # DSL-127.md .. DSL-130.md
```

## Reference Document

All requirements are derived from:
- [SPEC.md](../resources/SPEC.md) — dig-slashing specification v0.4+ (§22 requirements catalogue)

## Scope

Validator slashing only. DFSP / storage-provider slashing out of scope (separate future crate).

## Requirement Count

| Domain | DSL ranges | Count |
|--------|-----------|-------|
| Evidence | DSL-001..021 | 21 |
| Lifecycle | DSL-022..033, DSL-146..152 | 19 |
| Appeal | DSL-034..073 | 40 |
| Participation | DSL-074..086, DSL-153..154 | 15 |
| Inactivity | DSL-087..093, DSL-155 | 8 |
| Protection | DSL-094..101, DSL-156 | 9 |
| REMARK | DSL-102..120 | 19 |
| Bonds | DSL-121..126 | 6 |
| Orchestration | DSL-127..130 | 4 |
| Traits | DSL-131..145 | 15 |
| **Total** | | **156** |
