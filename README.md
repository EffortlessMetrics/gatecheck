# gatecheck

**Policy gate evaluation over evidence snapshots and receipts.**

`gatecheck` is the neutral gate evaluator for governed change. It reads a checked-in policy, evaluates it against a deterministic evidence snapshot, and emits a stable gate report plus a human-readable summary.

It is deliberately **not** the spec pipeline, **not** the diff linter, and **not** the merge cockpit. It sits between evidence producers and the merge surface.

## What it is

- policy + evidence snapshot → gate report
- local-first, deterministic, schema-shaped artifacts
- hexagonal workspace: pure evaluation core, adapters at the edge
- focused microcrates with one responsibility each
- BDD-style tests that document observable behavior

## Core commands

```bash
gatecheck eval   --policy .governance/gates.toml   --snapshot artifacts/gatecheck/snapshot.json   --out artifacts/gatecheck/report.json   --md artifacts/gatecheck/comment.md

gatecheck init --preset conveyor-6 --path .
```

## Build

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```
