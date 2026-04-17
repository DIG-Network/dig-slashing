# SocratiCode — Semantic Codebase Intelligence

## What

AI-powered semantic codebase intelligence. Provides hybrid search (semantic + BM25), polyglot dependency graphs, cross-project search, and context artifact indexing. Achieves 61% less context usage and 84% fewer tool calls compared to grep-based exploration.

## HARD RULE

**Search before reading.** Always use `codebase_search` before reading files. SocratiCode finds the right files; you read targeted sections. Never cat/head entire directories.

## Setup

### Claude Code

```bash
claude plugin marketplace add giancarloerra/socraticode
```

### MCP Host Configuration

```json
{
  "mcpServers": {
    "socraticode": {
      "command": "npx",
      "args": ["-y", "socraticode"]
    }
  }
}
```

### Prerequisites

- **Docker** — must be running (SocratiCode auto-pulls Qdrant and Ollama containers)
- **Node.js 18+** — for npx execution

## Commands

### Indexing

| Command | Purpose |
|---------|---------|
| `codebase_status {}` | Check if the index exists and is current |
| `codebase_index {}` | Index or reindex the entire codebase |
| `codebase_update {}` | Incremental update (only changed files) |
| `codebase_watch { action: "start" }` | Start file watcher for automatic re-indexing |
| `codebase_stop {}` | Stop the file watcher |

### Search

| Command | Purpose |
|---------|---------|
| `codebase_search { query: "..." }` | Hybrid semantic + keyword search across all indexed files |
| `codebase_context {}` | Get full context for the current working scope |
| `codebase_context_search { query: "..." }` | Search schemas, APIs, configurations, and context artifacts |

### Dependency Graph

| Command | Purpose |
|---------|---------|
| `codebase_graph_query { filePath: "..." }` | Show imports and dependents for a specific file |
| `codebase_graph_visualize {}` | Generate a visual dependency graph |
| `codebase_graph_circular {}` | Detect circular dependencies in the codebase |
| `codebase_graph_build {}` | Rebuild the dependency graph from scratch |

## Workflow Integration

| Workflow Step | How to Use SocratiCode |
|--------------|------------------------|
| **Select work** | `codebase_search` for existing implementations of the requirement you are considering |
| **Gather context** | `codebase_search` to find related code + `codebase_graph_query` to understand dependency structure |
| **Before reading files** | ALWAYS search first, then read only the 1-3 files that matter |
| **Before implementing** | `codebase_graph_query` on files you will modify to understand all dependents |
| **Validate** | `codebase_graph_circular` to verify no circular dependencies were introduced |

## Example Usage for dig-slashing

### Finding related slashing code

```
codebase_search { query: "proposer equivocation two headers same slot" }
codebase_search { query: "attester slashing intersection indices aggregate verify" }
codebase_search { query: "optimistic slashing appeal window pending" }
```

### Understanding what depends on the SlashingManager struct

```
codebase_graph_query { filePath: "src/manager.rs" }
```

### Finding test patterns for a similar requirement

```
codebase_search { query: "dsl_013 verify proposer slashing test" }
```

### Checking for circular deps after a change

```
codebase_graph_circular {}
```

### Searching participation + inactivity formulas

```
codebase_context_search { query: "base reward WEIGHT_DENOMINATOR timely source target head" }
codebase_context_search { query: "inactivity score bias recovery quotient Bellatrix" }
```

### Searching for appeal fraud-proof patterns

```
codebase_search { query: "appeal ground sustained rejected adjudicator" }
```

## Tips

- Use specific queries. "verify attester surround vote predicate" is better than "slashing".
- Combine search + graph: search finds the file, graph shows its relationships.
- Run `codebase_status {}` at session start to verify the index is fresh.
- If results seem stale, run `codebase_update {}` to incrementally re-index.
- For cross-crate questions (e.g. how `dig-block::block_signing_message` is used here), use `codebase_search` with the fully-qualified path.
