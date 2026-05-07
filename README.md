# gatecheck

[![CI](https://github.com/EffortlessMetrics/gatecheck/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/EffortlessMetrics/gatecheck/actions/workflows/ci.yml)
[![Coverage](https://github.com/EffortlessMetrics/gatecheck/actions/workflows/coverage.yml/badge.svg?branch=main)](https://github.com/EffortlessMetrics/gatecheck/actions/workflows/coverage.yml)
[![Codecov](https://codecov.io/gh/EffortlessMetrics/gatecheck/branch/main/graph/badge.svg)](https://codecov.io/gh/EffortlessMetrics/gatecheck)
[![MSRV](https://img.shields.io/badge/MSRV-1.81-blue.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)

**Policy gate evaluation over evidence snapshots and receipts.**

`gatecheck` is the neutral gate evaluator for governed change. It reads a checked-in policy, evaluates it against a deterministic evidence snapshot, and emits a stable gate report plus a human-readable summary.

It is deliberately **not** the spec pipeline, **not** the diff linter, and **not** the merge cockpit. It sits between evidence producers and the merge surface.

## What it is

- policy + evidence snapshot → gate report
- local-first, deterministic, schema-shaped artifacts
- hexagonal workspace: pure evaluation core, adapters at the edge
- focused microcrates with one responsibility each
- BDD-style tests that document observable behavior

Codecov is Rust execution-surface telemetry only; see [Coverage](docs/ci/coverage.md) for what the badge does and does not claim.

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
