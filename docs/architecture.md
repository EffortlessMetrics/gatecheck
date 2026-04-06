# Architecture

The CLI is the leaf crate. Pure policy evaluation lives in `gatecheck-eval`. Filesystem I/O and preset scaffolding live in `gatecheck-fs`. Markdown output lives in `gatecheck-export-markdown`.
