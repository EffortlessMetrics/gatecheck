# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
cargo fmt --all                                    # format
cargo clippy --workspace --all-targets -- -D warnings  # lint (warnings are errors)
cargo test --workspace --all-targets               # all tests
cargo test -p gatecheck-eval                       # single crate
cargo test -p gatecheck --test acceptance           # acceptance tests only
```

Run the eval command:
```bash
cargo run -p gatecheck -- eval --policy examples/conveyor-6/gates.toml --snapshot examples/conveyor-6/snapshot.json
```

## Architecture

**Core contract:** `GatePolicy + EvidenceSnapshot → GateReport`

Hexagonal workspace: pure evaluation core with adapters at the edge. Eight microcrates, each with one responsibility.

### Dependency graph

```
gatecheck (CLI)
├── gatecheck-eval      → gatecheck-types        (pure evaluator, no I/O)
├── gatecheck-fs        → gatecheck-policy, gatecheck-types  (filesystem adapters)
├── gatecheck-export-markdown → gatecheck-types   (report → markdown)
├── gatecheck-codes                               (process exit codes)
└── gatecheck-types                               (foundation, zero deps)

gatecheck-policy  → gatecheck-types              (TOML-subset parser + validation)
gatecheck-fixtures → gatecheck-types             (reusable test data for other crates)
```

### Crate roles

| Crate | Role |
|---|---|
| `gatecheck-types` | Core types (`GatePolicy`, `EvidenceSnapshot`, `GateReport`, `Requirement`) and hand-rolled JSON parser/serializer — zero external deps |
| `gatecheck-codes` | Stable CLI exit codes (`ExitCode` enum: Success=0, GateBlocked=4, etc.) |
| `gatecheck-policy` | Parses restricted TOML subset for `[gates.*]` sections, validates uniqueness/dependencies |
| `gatecheck-eval` | **Pure, deterministic** evaluation — takes policy+snapshot, returns report. No side effects |
| `gatecheck-fs` | I/O adapters: read policy/snapshot/report, write report/markdown, scaffold presets |
| `gatecheck-export-markdown` | Renders `GateReport` to human-readable Markdown summary |
| `gatecheck-fixtures` | Shared test fixtures (`conveyor_policy()`, `passing_snapshot()`, `partial_snapshot()`) |
| `gatecheck` | CLI entry point — `eval`, `init`, `explain` commands |

### Gate evaluation flow

Gates are ordered by `order` field and evaluated sequentially. Once a gate fails, all downstream dependents are **blocked**. The report tracks `earned_gate` (highest passed), `blocked_at` (first failure), and `next_gate` (first non-passing). Requirement kinds: `artifact_exists`, `receipt_pass`, `issue_linked`, `ci_check_passed`, `review_approved`, `conversations_resolved`, `attestation_present`.

## Conventions

- **Keep the evaluation core pure** — no I/O in `gatecheck-eval`.
- **Keep adapters at the edge** — filesystem, CLI, and rendering are separate crates.
- **Preserve stable report fields once shipped** — the `gate.report.v1` schema is a contract.
- **BDD-style tests** — use "given/when/then" naming. Tests document observable behavior.
- **Each crate has its own error type** — `PolicyError`, `EvaluateError`, `FsError`, `JsonError`.
- **Custom JSON** — `gatecheck-types` uses a hand-rolled JSON parser/serializer to keep zero external deps. Don't add serde.
- **Microcrate discipline** — don't merge crate responsibilities. Each crate does one thing.
