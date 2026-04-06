# Design

The core contract is:

```text
GatePolicy + EvidenceSnapshot -> GateReport
```

The workspace is split into leaf microcrates with single responsibilities:

- `gatecheck-codes`
- `gatecheck-types`
- `gatecheck-policy`
- `gatecheck-eval`
- `gatecheck-fs`
- `gatecheck-export-markdown`
- `gatecheck-fixtures`
- `gatecheck`
