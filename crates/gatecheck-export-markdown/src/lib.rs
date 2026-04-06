//! Markdown rendering for gatecheck reports.

use gatecheck_types::{FindingStatus, GateReport, GateStatus};

/// Render a gate report as Markdown.
#[must_use]
pub fn render(report: &GateReport) -> String {
    let mut output = String::new();
    output.push_str("# gatecheck report\n\n");
    output.push_str(&format!("- policy: `{}`\n", report.policy_id));
    output.push_str(&format!("- profile: `{}`\n", report.profile));
    output.push_str(&format!(
        "- subject: `{}` `{}`\n",
        report.subject.kind, report.subject.id
    ));
    output.push_str(&format!(
        "- earned gate: `{}`\n",
        report.earned_gate.as_deref().unwrap_or("none")
    ));
    output.push_str(&format!(
        "- blocked at: `{}`\n",
        report.blocked_at.as_deref().unwrap_or("none")
    ));
    output.push_str(&format!(
        "- next gate: `{}`\n\n",
        report.next_gate.as_deref().unwrap_or("none")
    ));

    for gate in &report.gates {
        output.push_str(&format!("## {}\n\n", gate.name));
        output.push_str(&format!("status: `{}`\n\n", gate_status_label(gate.status)));
        if let Some(blocker) = &gate.blocked_by {
            output.push_str(&format!("blocked by: `{blocker}`\n\n"));
            continue;
        }
        if gate.findings.is_empty() {
            output.push_str("No findings.\n\n");
            continue;
        }
        for finding in &gate.findings {
            output.push_str(&format!(
                "- [{}] `{}` — {}\n",
                finding_status_label(finding.status),
                finding.requirement,
                finding.message
            ));
        }
        output.push('\n');
    }

    output
}

fn gate_status_label(status: GateStatus) -> &'static str {
    match status {
        GateStatus::Pass => "pass",
        GateStatus::Fail => "fail",
        GateStatus::Unknown => "unknown",
        GateStatus::Blocked => "blocked",
    }
}

fn finding_status_label(status: FindingStatus) -> &'static str {
    match status {
        FindingStatus::Pass => "pass",
        FindingStatus::Fail => "fail",
        FindingStatus::Unknown => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use gatecheck_types::{GateFinding, GateReport, GateResult, SubjectRef};

    use super::*;

    #[test]
    fn given_report_when_render_then_headline_and_summary_are_present() {
        let report = GateReport {
            schema: "gate.report.v1".to_owned(),
            policy_id: "policy".to_owned(),
            profile: "conveyor-6".to_owned(),
            subject: SubjectRef {
                kind: "pr".to_owned(),
                id: "1".to_owned(),
            },
            earned_gate: Some("framed".to_owned()),
            blocked_at: Some("verified".to_owned()),
            next_gate: Some("verified".to_owned()),
            gates: vec![GateResult {
                id: "framed".to_owned(),
                name: "Framed".to_owned(),
                status: GateStatus::Pass,
                findings: vec![GateFinding {
                    requirement: "issue_linked".to_owned(),
                    status: FindingStatus::Pass,
                    message: "linked issue present".to_owned(),
                }],
                blocked_by: None,
            }],
        };

        let markdown = render(&report);
        assert!(markdown.contains("# gatecheck report"));
        assert!(markdown.contains("earned gate"));
        assert!(markdown.contains("linked issue present"));
    }
}
