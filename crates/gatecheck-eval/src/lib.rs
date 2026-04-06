//! Pure gate evaluation over immutable evidence snapshots.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use gatecheck_types::{
    EvidenceSnapshot, FactStatus, FindingStatus, GateDefinition, GateFinding, GatePolicy,
    GateReport, GateResult, GateStatus, Requirement, GATE_REPORT_SCHEMA,
};

/// Evaluation-time validation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvaluateError {
    DuplicateGateId(String),
    DuplicateGateOrder(u16),
    UnknownDependency { gate: String, dependency: String },
}

impl Display for EvaluateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateGateId(id) => write!(formatter, "duplicate gate id: {id}"),
            Self::DuplicateGateOrder(order) => write!(formatter, "duplicate gate order: {order}"),
            Self::UnknownDependency { gate, dependency } => {
                write!(
                    formatter,
                    "unknown dependency `{dependency}` for gate `{gate}`"
                )
            }
        }
    }
}

impl Error for EvaluateError {}

/// Evaluate the supplied policy against a frozen evidence snapshot.
pub fn evaluate(
    policy: &GatePolicy,
    snapshot: &EvidenceSnapshot,
) -> Result<GateReport, EvaluateError> {
    validate_policy(policy)?;

    let ordered = ordered_gates(policy);
    let mut results = Vec::with_capacity(ordered.len());
    let mut statuses = BTreeMap::<String, GateStatus>::new();
    let mut earned_gate = None;
    let mut blocked_at: Option<String> = None;

    for gate in ordered {
        if let Some(blocker) = first_unmet_dependency(gate, &statuses) {
            results.push(GateResult {
                id: gate.id.clone(),
                name: gate.name.clone(),
                status: GateStatus::Blocked,
                findings: Vec::new(),
                blocked_by: Some(blocker.clone()),
            });
            statuses.insert(gate.id.clone(), GateStatus::Blocked);
            continue;
        }

        if let Some(blocker) = blocked_at.clone() {
            results.push(GateResult {
                id: gate.id.clone(),
                name: gate.name.clone(),
                status: GateStatus::Blocked,
                findings: Vec::new(),
                blocked_by: Some(blocker.clone()),
            });
            statuses.insert(gate.id.clone(), GateStatus::Blocked);
            continue;
        }

        let (status, findings) = evaluate_gate(gate, snapshot);
        if status == GateStatus::Pass {
            earned_gate = Some(gate.id.clone());
        } else if blocked_at.is_none() {
            blocked_at = Some(gate.id.clone());
        }

        results.push(GateResult {
            id: gate.id.clone(),
            name: gate.name.clone(),
            status,
            findings,
            blocked_by: None,
        });
        statuses.insert(gate.id.clone(), status);
    }

    let next_gate = results
        .iter()
        .find(|gate| gate.status != GateStatus::Pass)
        .map(|gate| gate.id.clone());

    Ok(GateReport {
        schema: GATE_REPORT_SCHEMA.to_owned(),
        policy_id: policy.id.clone(),
        profile: policy.profile.clone(),
        subject: snapshot.subject.clone(),
        earned_gate,
        blocked_at,
        next_gate,
        gates: results,
    })
}

fn validate_policy(policy: &GatePolicy) -> Result<(), EvaluateError> {
    let mut ids = BTreeSet::new();
    let mut orders = BTreeSet::new();
    for gate in &policy.gates {
        if !ids.insert(gate.id.clone()) {
            return Err(EvaluateError::DuplicateGateId(gate.id.clone()));
        }
        if !orders.insert(gate.order) {
            return Err(EvaluateError::DuplicateGateOrder(gate.order));
        }
    }
    for gate in &policy.gates {
        for dependency in &gate.depends_on {
            if !policy
                .gates
                .iter()
                .any(|candidate| candidate.id == *dependency)
            {
                return Err(EvaluateError::UnknownDependency {
                    gate: gate.id.clone(),
                    dependency: dependency.clone(),
                });
            }
        }
    }
    Ok(())
}

fn ordered_gates(policy: &GatePolicy) -> Vec<&GateDefinition> {
    let mut ordered: Vec<_> = policy.gates.iter().collect();
    ordered.sort_by_key(|gate| gate.order);
    ordered
}

fn first_unmet_dependency(
    gate: &GateDefinition,
    statuses: &BTreeMap<String, GateStatus>,
) -> Option<String> {
    gate.depends_on
        .iter()
        .find_map(|dependency| match statuses.get(dependency) {
            Some(GateStatus::Pass) => None,
            Some(_) => Some(dependency.clone()),
            None => Some(dependency.clone()),
        })
}

fn evaluate_gate(
    gate: &GateDefinition,
    snapshot: &EvidenceSnapshot,
) -> (GateStatus, Vec<GateFinding>) {
    let findings = gate
        .requirements
        .iter()
        .map(|requirement| evaluate_requirement(requirement, snapshot))
        .collect::<Vec<_>>();

    let status = if findings
        .iter()
        .all(|finding| finding.status == FindingStatus::Pass)
    {
        GateStatus::Pass
    } else if findings
        .iter()
        .any(|finding| finding.status == FindingStatus::Fail)
    {
        GateStatus::Fail
    } else {
        GateStatus::Unknown
    };

    (status, findings)
}

fn evaluate_requirement(requirement: &Requirement, snapshot: &EvidenceSnapshot) -> GateFinding {
    match requirement {
        Requirement::ArtifactExists { path } => {
            if snapshot
                .artifacts
                .iter()
                .any(|artifact| artifact.path == *path)
            {
                pass(requirement, format!("artifact exists: {path}"))
            } else {
                fail(requirement, format!("artifact missing: {path}"))
            }
        }
        Requirement::ReceiptPass { tool, check } => {
            if snapshot.receipts.iter().any(|receipt| {
                receipt.tool == *tool
                    && receipt.check == *check
                    && receipt.status == FactStatus::Pass
            }) {
                pass(requirement, format!("receipt passed: {tool}/{check}"))
            } else {
                fail(
                    requirement,
                    format!("receipt missing or failing: {tool}/{check}"),
                )
            }
        }
        Requirement::IssueLinked => match &snapshot.github {
            Some(github) if github.linked_issue.is_some() => {
                pass(requirement, "linked issue present")
            }
            Some(_) => fail(requirement, "linked issue missing"),
            None => unknown(requirement, "github facts unavailable"),
        },
        Requirement::CiCheckPassed { name } => {
            if snapshot
                .ci
                .iter()
                .any(|fact| fact.name == *name && fact.status == FactStatus::Pass)
            {
                pass(requirement, format!("ci check passed: {name}"))
            } else {
                fail(requirement, format!("ci check missing or failing: {name}"))
            }
        }
        Requirement::ReviewApproved { min_count } => match &snapshot.github {
            Some(github) if github.approvals >= *min_count => pass(
                requirement,
                format!(
                    "approval count satisfied: {} >= {min_count}",
                    github.approvals
                ),
            ),
            Some(github) => fail(
                requirement,
                format!(
                    "approval count insufficient: {} < {min_count}",
                    github.approvals
                ),
            ),
            None => unknown(requirement, "github facts unavailable"),
        },
        Requirement::ConversationsResolved => match &snapshot.github {
            Some(github) if github.conversations_resolved => {
                pass(requirement, "review conversations resolved")
            }
            Some(_) => fail(requirement, "review conversations unresolved"),
            None => unknown(requirement, "github facts unavailable"),
        },
        Requirement::AttestationPresent { key } => {
            if snapshot
                .attestations
                .iter()
                .any(|attestation| attestation.key == *key)
            {
                pass(requirement, format!("attestation present: {key}"))
            } else {
                fail(requirement, format!("attestation missing: {key}"))
            }
        }
    }
}

fn pass(requirement: &Requirement, message: impl Into<String>) -> GateFinding {
    GateFinding {
        requirement: requirement.kind().to_owned(),
        status: FindingStatus::Pass,
        message: message.into(),
    }
}

fn fail(requirement: &Requirement, message: impl Into<String>) -> GateFinding {
    GateFinding {
        requirement: requirement.kind().to_owned(),
        status: FindingStatus::Fail,
        message: message.into(),
    }
}

fn unknown(requirement: &Requirement, message: impl Into<String>) -> GateFinding {
    GateFinding {
        requirement: requirement.kind().to_owned(),
        status: FindingStatus::Unknown,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use gatecheck_types::{
        ArtifactFact, AttestationFact, CiFact, GitHubFacts, ReceiptFact, SubjectRef,
    };

    use super::*;

    fn policy() -> GatePolicy {
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
                    requirements: vec![Requirement::IssueLinked],
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
                    id: "hardened".to_owned(),
                    name: "Hardened".to_owned(),
                    order: 3,
                    depends_on: vec!["verified".to_owned()],
                    requirements: vec![Requirement::ReviewApproved { min_count: 1 }],
                },
            ],
        }
    }

    fn passing_snapshot() -> EvidenceSnapshot {
        EvidenceSnapshot {
            subject: SubjectRef {
                kind: "pr".to_owned(),
                id: "42".to_owned(),
            },
            artifacts: vec![ArtifactFact {
                path: ".governance/verified/verification-report.md".to_owned(),
                content: Some("done".to_owned()),
            }],
            receipts: vec![ReceiptFact {
                tool: "diffguard".to_owned(),
                check: "overall".to_owned(),
                status: FactStatus::Pass,
            }],
            github: Some(GitHubFacts {
                linked_issue: Some(7),
                labels: vec!["gate:framed".to_owned()],
                branch: Some("feat/7-example".to_owned()),
                approvals: 1,
                conversations_resolved: true,
            }),
            ci: vec![CiFact {
                name: "test".to_owned(),
                status: FactStatus::Pass,
            }],
            attestations: vec![AttestationFact {
                key: "merge-authorized".to_owned(),
                value: None,
            }],
        }
    }

    #[test]
    fn given_passing_snapshot_when_evaluate_then_all_gates_pass() {
        let report = evaluate(&policy(), &passing_snapshot()).expect("report");
        assert_eq!(report.earned_gate.as_deref(), Some("hardened"));
        assert_eq!(report.blocked_at, None);
        assert!(report
            .gates
            .iter()
            .all(|gate| gate.status == GateStatus::Pass));
    }

    #[test]
    fn given_missing_verified_artifact_when_evaluate_then_later_gates_are_blocked() {
        let mut snapshot = passing_snapshot();
        snapshot.artifacts.clear();
        let report = evaluate(&policy(), &snapshot).expect("report");
        assert_eq!(report.earned_gate.as_deref(), Some("framed"));
        assert_eq!(report.blocked_at.as_deref(), Some("verified"));
        assert_eq!(report.next_gate.as_deref(), Some("verified"));
        assert_eq!(report.gates[1].status, GateStatus::Fail);
        assert_eq!(report.gates[2].status, GateStatus::Blocked);
        assert_eq!(report.gates[2].blocked_by.as_deref(), Some("verified"));
    }

    #[test]
    fn given_missing_github_facts_when_issue_required_then_status_is_unknown() {
        let mut snapshot = passing_snapshot();
        snapshot.github = None;
        let report = evaluate(&policy(), &snapshot).expect("report");
        assert_eq!(report.gates[0].status, GateStatus::Unknown);
        assert_eq!(report.blocked_at.as_deref(), Some("framed"));
    }
}
