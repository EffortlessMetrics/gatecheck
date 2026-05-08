# Coverage

Codecov coverage is Rust execution-surface evidence.

It answers:

> Did tests execute this Rust surface?

It does not answer:

- whether gate policy evaluation is correct,
- whether evidence snapshot parsing is correct,
- whether report or receipt semantics are correct,
- whether Markdown summaries are complete,
- whether schema compatibility is proven,
- whether BDD coverage is adequate,
- whether release readiness is proven.

Those are separate proof lanes.

The Coverage workflow runs on:

- push to `main`,
- `workflow_dispatch`,
- PRs labeled `coverage`, `full-ci`, or `ci:full`.

Codecov comments are disabled. Durable receipts are:

- `coverage.json`,
- `coverage.txt`,
- `lcov.info`,
- the GitHub Actions coverage artifact,
- the Codecov dashboard.
