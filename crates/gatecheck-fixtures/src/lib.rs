//! Reusable fixtures for gatecheck tests.

use gatecheck_types::{
    ArtifactFact, AttestationFact, CiFact, EvidenceSnapshot, FactStatus, GateDefinition,
    GatePolicy, GitHubFacts, ReceiptFact, Requirement, SubjectRef,
};

/// Conveyor-6 starter policy used by tests.
#[must_use]
pub fn conveyor_policy() -> GatePolicy {
    GatePolicy {
        id: "conveyor-6".to_owned(),
        version: "1".to_owned(),
        profile: "conveyor-6".to_owned(),
        gates: vec![
            GateDefinition {
                id: "framed".to_owned(),
                name: "Framed".to_owned(),
                order: 1,
                depends_on: vec![],
                requirements: vec![
                    Requirement::IssueLinked,
                    Requirement::ArtifactExists {
                        path: ".governance/framed/scope.md".to_owned(),
                    },
                    Requirement::ArtifactExists {
                        path: ".governance/framed/research.md".to_owned(),
                    },
                ],
            },
            GateDefinition {
                id: "verified".to_owned(),
                name: "Verified".to_owned(),
                order: 2,
                depends_on: vec!["framed".to_owned()],
                requirements: vec![Requirement::ArtifactExists {
                    path: ".governance/verified/verification-report.md".to_owned(),
                }],
            },
            GateDefinition {
                id: "designed".to_owned(),
                name: "Designed".to_owned(),
                order: 3,
                depends_on: vec!["verified".to_owned()],
                requirements: vec![
                    Requirement::ArtifactExists {
                        path: ".governance/designed/adr.md".to_owned(),
                    },
                    Requirement::ArtifactExists {
                        path: ".governance/designed/tasks.md".to_owned(),
                    },
                ],
            },
            GateDefinition {
                id: "proven".to_owned(),
                name: "Proven".to_owned(),
                order: 4,
                depends_on: vec!["designed".to_owned()],
                requirements: vec![
                    Requirement::ReceiptPass {
                        tool: "diffguard".to_owned(),
                        check: "overall".to_owned(),
                    },
                    Requirement::CiCheckPassed {
                        name: "test".to_owned(),
                    },
                ],
            },
            GateDefinition {
                id: "hardened".to_owned(),
                name: "Hardened".to_owned(),
                order: 5,
                depends_on: vec!["proven".to_owned()],
                requirements: vec![
                    Requirement::ReviewApproved { min_count: 1 },
                    Requirement::ConversationsResolved,
                ],
            },
            GateDefinition {
                id: "integrated".to_owned(),
                name: "Integrated".to_owned(),
                order: 6,
                depends_on: vec!["hardened".to_owned()],
                requirements: vec![Requirement::AttestationPresent {
                    key: "merge-authorized".to_owned(),
                }],
            },
        ],
    }
}

/// Snapshot that passes every gate.
#[must_use]
pub fn passing_snapshot() -> EvidenceSnapshot {
    EvidenceSnapshot {
        subject: SubjectRef {
            kind: "pr".to_owned(),
            id: "42".to_owned(),
        },
        artifacts: vec![
            ArtifactFact {
                path: ".governance/framed/scope.md".to_owned(),
                content: Some("scope".to_owned()),
            },
            ArtifactFact {
                path: ".governance/framed/research.md".to_owned(),
                content: Some("research".to_owned()),
            },
            ArtifactFact {
                path: ".governance/verified/verification-report.md".to_owned(),
                content: Some("verified".to_owned()),
            },
            ArtifactFact {
                path: ".governance/designed/adr.md".to_owned(),
                content: Some("adr".to_owned()),
            },
            ArtifactFact {
                path: ".governance/designed/tasks.md".to_owned(),
                content: Some("tasks".to_owned()),
            },
        ],
        receipts: vec![ReceiptFact {
            tool: "diffguard".to_owned(),
            check: "overall".to_owned(),
            status: FactStatus::Pass,
        }],
        github: Some(GitHubFacts {
            linked_issue: Some(12),
            labels: vec!["gate:framed".to_owned()],
            branch: Some("feat/gatecheck-42".to_owned()),
            approvals: 1,
            conversations_resolved: true,
        }),
        ci: vec![CiFact {
            name: "test".to_owned(),
            status: FactStatus::Pass,
        }],
        attestations: vec![AttestationFact {
            key: "merge-authorized".to_owned(),
            value: Some("yes".to_owned()),
        }],
    }
}

/// Snapshot that blocks at Designed.
#[must_use]
pub fn partial_snapshot() -> EvidenceSnapshot {
    let mut snapshot = passing_snapshot();
    snapshot
        .artifacts
        .retain(|artifact| !artifact.path.contains(".governance/designed/"));
    snapshot.github.as_mut().expect("github facts").approvals = 0;
    snapshot
        .github
        .as_mut()
        .expect("github facts")
        .conversations_resolved = false;
    snapshot.attestations.clear();
    snapshot
}
