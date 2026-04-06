# gatecheck report

- policy: `conveyor-6`
- profile: `conveyor-6`
- subject: `pr` `42`
- earned gate: `verified`
- blocked at: `designed`
- next gate: `designed`

## Framed

status: `pass`

- [pass] `issue_linked` — linked issue present
- [pass] `artifact_exists` — artifact exists: .governance/framed/scope.md
- [pass] `artifact_exists` — artifact exists: .governance/framed/research.md

## Verified

status: `pass`

- [pass] `artifact_exists` — artifact exists: .governance/verified/verification-report.md

## Designed

status: `fail`

- [fail] `artifact_exists` — artifact missing: .governance/designed/adr.md
- [fail] `artifact_exists` — artifact missing: .governance/designed/tasks.md

## Proven

status: `blocked`

blocked by: `designed`

## Hardened

status: `blocked`

blocked by: `proven`

## Integrated

status: `blocked`

blocked by: `hardened`

