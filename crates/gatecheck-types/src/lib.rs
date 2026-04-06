//! Stable types and lightweight JSON handling for gatecheck.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Stable report schema identifier.
pub const GATE_REPORT_SCHEMA: &str = "gate.report.v1";

/// Policy data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatePolicy {
    pub id: String,
    pub version: String,
    pub profile: String,
    pub gates: Vec<GateDefinition>,
}

/// Gate definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateDefinition {
    pub id: String,
    pub name: String,
    pub order: u16,
    pub depends_on: Vec<String>,
    pub requirements: Vec<Requirement>,
}

/// Supported requirements in v0.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requirement {
    ArtifactExists { path: String },
    ReceiptPass { tool: String, check: String },
    IssueLinked,
    CiCheckPassed { name: String },
    ReviewApproved { min_count: u8 },
    ConversationsResolved,
    AttestationPresent { key: String },
}

impl Requirement {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ArtifactExists { .. } => "artifact_exists",
            Self::ReceiptPass { .. } => "receipt_pass",
            Self::IssueLinked => "issue_linked",
            Self::CiCheckPassed { .. } => "ci_check_passed",
            Self::ReviewApproved { .. } => "review_approved",
            Self::ConversationsResolved => "conversations_resolved",
            Self::AttestationPresent { .. } => "attestation_present",
        }
    }
}

/// Snapshot subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectRef {
    pub kind: String,
    pub id: String,
}

/// Artifact fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactFact {
    pub path: String,
    pub content: Option<String>,
}

/// Binary pass/fail status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactStatus {
    Pass,
    Fail,
}

impl FactStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

/// Receipt fact from another tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptFact {
    pub tool: String,
    pub check: String,
    pub status: FactStatus,
}

/// GitHub-like metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubFacts {
    pub linked_issue: Option<u64>,
    pub labels: Vec<String>,
    pub branch: Option<String>,
    pub approvals: u8,
    pub conversations_resolved: bool,
}

/// CI status fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiFact {
    pub name: String,
    pub status: FactStatus,
}

/// Attestation fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationFact {
    pub key: String,
    pub value: Option<String>,
}

/// Evidence snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSnapshot {
    pub subject: SubjectRef,
    pub artifacts: Vec<ArtifactFact>,
    pub receipts: Vec<ReceiptFact>,
    pub github: Option<GitHubFacts>,
    pub ci: Vec<CiFact>,
    pub attestations: Vec<AttestationFact>,
}

impl EvidenceSnapshot {
    /// Parse a snapshot from JSON.
    pub fn from_json_str(input: &str) -> Result<Self, JsonError> {
        let value = parse_json(input)?;
        let object = value.expect_object()?;
        Ok(Self {
            subject: parse_subject(object.get_required("subject")?)?,
            artifacts: object
                .get_optional("artifacts")
                .map(parse_artifacts)
                .transpose()?
                .unwrap_or_default(),
            receipts: object
                .get_optional("receipts")
                .map(parse_receipts)
                .transpose()?
                .unwrap_or_default(),
            github: object
                .get_optional("github")
                .map(parse_github)
                .transpose()?,
            ci: object
                .get_optional("ci")
                .map(parse_ci)
                .transpose()?
                .unwrap_or_default(),
            attestations: object
                .get_optional("attestations")
                .map(parse_attestations)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// Finding status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus {
    Pass,
    Fail,
    Unknown,
}

impl FindingStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Unknown => "unknown",
        }
    }
}

/// Gate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    Fail,
    Unknown,
    Blocked,
}

impl GateStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Unknown => "unknown",
            Self::Blocked => "blocked",
        }
    }
}

/// Requirement finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateFinding {
    pub requirement: String,
    pub status: FindingStatus,
    pub message: String,
}

/// Result for one gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateResult {
    pub id: String,
    pub name: String,
    pub status: GateStatus,
    pub findings: Vec<GateFinding>,
    pub blocked_by: Option<String>,
}

/// Final report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateReport {
    pub schema: String,
    pub policy_id: String,
    pub profile: String,
    pub subject: SubjectRef,
    pub earned_gate: Option<String>,
    pub blocked_at: Option<String>,
    pub next_gate: Option<String>,
    pub gates: Vec<GateResult>,
}

impl GateReport {
    /// Parse a report from JSON.
    pub fn from_json_str(input: &str) -> Result<Self, JsonError> {
        let value = parse_json(input)?;
        let object = value.expect_object()?;
        Ok(Self {
            schema: object.get_required_string("schema")?,
            policy_id: object.get_required_string("policy_id")?,
            profile: object.get_required_string("profile")?,
            subject: parse_subject(object.get_required("subject")?)?,
            earned_gate: object
                .get_optional("earned_gate")
                .map(parse_optional_string)
                .transpose()?
                .flatten(),
            blocked_at: object
                .get_optional("blocked_at")
                .map(parse_optional_string)
                .transpose()?
                .flatten(),
            next_gate: object
                .get_optional("next_gate")
                .map(parse_optional_string)
                .transpose()?
                .flatten(),
            gates: object
                .get_optional("gates")
                .map(parse_gate_results)
                .transpose()?
                .unwrap_or_default(),
        })
    }

    /// Serialize the report as pretty JSON.
    #[must_use]
    pub fn to_json_pretty(&self) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        push_string_field(&mut out, 2, "schema", &self.schema, true);
        push_string_field(&mut out, 2, "policy_id", &self.policy_id, true);
        push_string_field(&mut out, 2, "profile", &self.profile, true);
        out.push_str("  \"subject\": {\n");
        push_string_field(&mut out, 4, "kind", &self.subject.kind, true);
        push_string_field(&mut out, 4, "id", &self.subject.id, false);
        out.push_str("  },\n");
        push_optional_string_field(
            &mut out,
            2,
            "earned_gate",
            self.earned_gate.as_deref(),
            true,
        );
        push_optional_string_field(&mut out, 2, "blocked_at", self.blocked_at.as_deref(), true);
        push_optional_string_field(&mut out, 2, "next_gate", self.next_gate.as_deref(), true);
        out.push_str("  \"gates\": [\n");
        for (gate_index, gate) in self.gates.iter().enumerate() {
            out.push_str("    {\n");
            push_string_field(&mut out, 6, "id", &gate.id, true);
            push_string_field(&mut out, 6, "name", &gate.name, true);
            push_string_field(&mut out, 6, "status", gate.status.as_str(), true);
            push_optional_string_field(&mut out, 6, "blocked_by", gate.blocked_by.as_deref(), true);
            out.push_str("      \"findings\": [\n");
            for (finding_index, finding) in gate.findings.iter().enumerate() {
                out.push_str("        {\n");
                push_string_field(&mut out, 10, "requirement", &finding.requirement, true);
                push_string_field(&mut out, 10, "status", finding.status.as_str(), true);
                push_string_field(&mut out, 10, "message", &finding.message, false);
                out.push_str("        }");
                if finding_index + 1 != gate.findings.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str("      ]\n");
            out.push_str("    }");
            if gate_index + 1 != self.gates.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n");
        out.push('}');
        out
    }
}

fn push_string_field(out: &mut String, indent: usize, name: &str, value: &str, comma: bool) {
    out.push_str(&" ".repeat(indent));
    out.push_str(&format!("\"{}\": \"{}\"", name, escape_json(value)));
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn push_optional_string_field(
    out: &mut String,
    indent: usize,
    name: &str,
    value: Option<&str>,
    comma: bool,
) {
    out.push_str(&" ".repeat(indent));
    out.push_str(&format!("\"{}\": ", name));
    match value {
        Some(value) => out.push_str(&format!("\"{}\"", escape_json(value))),
        None => out.push_str("null"),
    }
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Lightweight JSON parser error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    message: String,
}

impl JsonError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for JsonError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for JsonError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonValue {
    Object(JsonObject),
    Array(Vec<JsonValue>),
    String(String),
    Number(String),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JsonObject(BTreeMap<String, JsonValue>);

impl JsonObject {
    fn get_required(&self, key: &str) -> Result<&JsonValue, JsonError> {
        self.0
            .get(key)
            .ok_or_else(|| JsonError::new(format!("missing `{key}`")))
    }

    fn get_optional(&self, key: &str) -> Option<&JsonValue> {
        self.0.get(key)
    }

    fn get_required_string(&self, key: &str) -> Result<String, JsonError> {
        self.get_required(key)?.expect_string()
    }
}

impl JsonValue {
    fn expect_object(&self) -> Result<&JsonObject, JsonError> {
        match self {
            Self::Object(value) => Ok(value),
            _ => Err(JsonError::new("expected JSON object")),
        }
    }

    fn expect_array(&self) -> Result<&[JsonValue], JsonError> {
        match self {
            Self::Array(values) => Ok(values),
            _ => Err(JsonError::new("expected JSON array")),
        }
    }

    fn expect_string(&self) -> Result<String, JsonError> {
        match self {
            Self::String(value) => Ok(value.clone()),
            _ => Err(JsonError::new("expected JSON string")),
        }
    }

    fn expect_u64(&self) -> Result<u64, JsonError> {
        match self {
            Self::Number(value) => value
                .parse::<u64>()
                .map_err(|_| JsonError::new(format!("invalid integer `{value}`"))),
            _ => Err(JsonError::new("expected JSON number")),
        }
    }

    fn expect_bool(&self) -> Result<bool, JsonError> {
        match self {
            Self::Bool(value) => Ok(*value),
            _ => Err(JsonError::new("expected JSON bool")),
        }
    }
}

fn parse_subject(value: &JsonValue) -> Result<SubjectRef, JsonError> {
    let object = value.expect_object()?;
    Ok(SubjectRef {
        kind: object.get_required_string("kind")?,
        id: object.get_required_string("id")?,
    })
}

fn parse_artifacts(value: &JsonValue) -> Result<Vec<ArtifactFact>, JsonError> {
    value
        .expect_array()?
        .iter()
        .map(|item| {
            let object = item.expect_object()?;
            Ok(ArtifactFact {
                path: object.get_required_string("path")?,
                content: object
                    .get_optional("content")
                    .map(parse_optional_string)
                    .transpose()?
                    .flatten(),
            })
        })
        .collect()
}

fn parse_receipts(value: &JsonValue) -> Result<Vec<ReceiptFact>, JsonError> {
    value
        .expect_array()?
        .iter()
        .map(|item| {
            let object = item.expect_object()?;
            Ok(ReceiptFact {
                tool: object.get_required_string("tool")?,
                check: object.get_required_string("check")?,
                status: parse_fact_status(object.get_required("status")?)?,
            })
        })
        .collect()
}

fn parse_github(value: &JsonValue) -> Result<GitHubFacts, JsonError> {
    let object = value.expect_object()?;
    let linked_issue = match object.get_optional("linked_issue") {
        None | Some(JsonValue::Null) => None,
        Some(value) => Some(value.expect_u64()?),
    };
    let labels = object
        .get_optional("labels")
        .map(parse_string_array)
        .transpose()?
        .unwrap_or_default();
    let branch = object
        .get_optional("branch")
        .map(parse_optional_string)
        .transpose()?
        .flatten();
    let approvals = match object.get_optional("approvals") {
        None => 0,
        Some(value) => value.expect_u64()? as u8,
    };
    let conversations_resolved = match object.get_optional("conversations_resolved") {
        None => false,
        Some(value) => value.expect_bool()?,
    };
    Ok(GitHubFacts {
        linked_issue,
        labels,
        branch,
        approvals,
        conversations_resolved,
    })
}

fn parse_ci(value: &JsonValue) -> Result<Vec<CiFact>, JsonError> {
    value
        .expect_array()?
        .iter()
        .map(|item| {
            let object = item.expect_object()?;
            Ok(CiFact {
                name: object.get_required_string("name")?,
                status: parse_fact_status(object.get_required("status")?)?,
            })
        })
        .collect()
}

fn parse_attestations(value: &JsonValue) -> Result<Vec<AttestationFact>, JsonError> {
    value
        .expect_array()?
        .iter()
        .map(|item| {
            let object = item.expect_object()?;
            Ok(AttestationFact {
                key: object.get_required_string("key")?,
                value: object
                    .get_optional("value")
                    .map(parse_optional_string)
                    .transpose()?
                    .flatten(),
            })
        })
        .collect()
}

fn parse_gate_results(value: &JsonValue) -> Result<Vec<GateResult>, JsonError> {
    value
        .expect_array()?
        .iter()
        .map(|item| {
            let object = item.expect_object()?;
            Ok(GateResult {
                id: object.get_required_string("id")?,
                name: object.get_required_string("name")?,
                status: parse_gate_status(object.get_required("status")?)?,
                findings: object
                    .get_optional("findings")
                    .map(parse_findings)
                    .transpose()?
                    .unwrap_or_default(),
                blocked_by: object
                    .get_optional("blocked_by")
                    .map(parse_optional_string)
                    .transpose()?
                    .flatten(),
            })
        })
        .collect()
}

fn parse_findings(value: &JsonValue) -> Result<Vec<GateFinding>, JsonError> {
    value
        .expect_array()?
        .iter()
        .map(|item| {
            let object = item.expect_object()?;
            Ok(GateFinding {
                requirement: object.get_required_string("requirement")?,
                status: parse_finding_status(object.get_required("status")?)?,
                message: object.get_required_string("message")?,
            })
        })
        .collect()
}

fn parse_string_array(value: &JsonValue) -> Result<Vec<String>, JsonError> {
    value
        .expect_array()?
        .iter()
        .map(JsonValue::expect_string)
        .collect()
}

fn parse_optional_string(value: &JsonValue) -> Result<Option<String>, JsonError> {
    match value {
        JsonValue::Null => Ok(None),
        _ => Ok(Some(value.expect_string()?)),
    }
}

fn parse_fact_status(value: &JsonValue) -> Result<FactStatus, JsonError> {
    match value.expect_string()?.as_str() {
        "pass" => Ok(FactStatus::Pass),
        "fail" => Ok(FactStatus::Fail),
        other => Err(JsonError::new(format!("unknown status `{other}`"))),
    }
}

fn parse_finding_status(value: &JsonValue) -> Result<FindingStatus, JsonError> {
    match value.expect_string()?.as_str() {
        "pass" => Ok(FindingStatus::Pass),
        "fail" => Ok(FindingStatus::Fail),
        "unknown" => Ok(FindingStatus::Unknown),
        other => Err(JsonError::new(format!("unknown finding status `{other}`"))),
    }
}

fn parse_gate_status(value: &JsonValue) -> Result<GateStatus, JsonError> {
    match value.expect_string()?.as_str() {
        "pass" => Ok(GateStatus::Pass),
        "fail" => Ok(GateStatus::Fail),
        "unknown" => Ok(GateStatus::Unknown),
        "blocked" => Ok(GateStatus::Blocked),
        other => Err(JsonError::new(format!("unknown gate status `{other}`"))),
    }
}

fn parse_json(input: &str) -> Result<JsonValue, JsonError> {
    let mut parser = JsonParser::new(input);
    let value = parser.parse_value()?;
    parser.skip_whitespace();
    if !parser.is_eof() {
        return Err(JsonError::new("unexpected trailing JSON"));
    }
    Ok(value)
}

struct JsonParser<'a> {
    input: &'a str,
    position: usize,
}

impl<'a> JsonParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, position: 0 }
    }

    fn parse_value(&mut self) -> Result<JsonValue, JsonError> {
        self.skip_whitespace();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => self.parse_string().map(JsonValue::String),
            Some('t') | Some('f') => self.parse_bool().map(JsonValue::Bool),
            Some('n') => {
                self.expect_literal("null")?;
                Ok(JsonValue::Null)
            }
            Some('-') | Some('0'..='9') => self.parse_number().map(JsonValue::Number),
            Some(other) => Err(JsonError::new(format!("unexpected JSON token `{other}`"))),
            None => Err(JsonError::new("unexpected end of JSON")),
        }
    }

    fn parse_object(&mut self) -> Result<JsonValue, JsonError> {
        self.expect('{')?;
        let mut object = BTreeMap::new();
        self.skip_whitespace();
        if self.peek() == Some('}') {
            self.advance();
            return Ok(JsonValue::Object(JsonObject(object)));
        }
        loop {
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.expect(':')?;
            let value = self.parse_value()?;
            object.insert(key, value);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.advance();
                    self.skip_whitespace();
                }
                Some('}') => {
                    self.advance();
                    break;
                }
                Some(other) => {
                    return Err(JsonError::new(format!("unexpected object token `{other}`")))
                }
                None => return Err(JsonError::new("unexpected end of object")),
            }
        }
        Ok(JsonValue::Object(JsonObject(object)))
    }

    fn parse_array(&mut self) -> Result<JsonValue, JsonError> {
        self.expect('[')?;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(']') {
            self.advance();
            return Ok(JsonValue::Array(values));
        }
        loop {
            values.push(self.parse_value()?);
            self.skip_whitespace();
            match self.peek() {
                Some(',') => {
                    self.advance();
                    self.skip_whitespace();
                }
                Some(']') => {
                    self.advance();
                    break;
                }
                Some(other) => {
                    return Err(JsonError::new(format!("unexpected array token `{other}`")))
                }
                None => return Err(JsonError::new("unexpected end of array")),
            }
        }
        Ok(JsonValue::Array(values))
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect('"')?;
        let mut output = String::new();
        loop {
            let character = self
                .advance()
                .ok_or_else(|| JsonError::new("unexpected end of string"))?;
            match character {
                '"' => break,
                '\\' => {
                    let escaped = self
                        .advance()
                        .ok_or_else(|| JsonError::new("unexpected end of escape"))?;
                    match escaped {
                        '"' => output.push('"'),
                        '\\' => output.push('\\'),
                        'n' => output.push('\n'),
                        'r' => output.push('\r'),
                        't' => output.push('\t'),
                        other => {
                            return Err(JsonError::new(format!("unsupported escape `\\{other}`")))
                        }
                    }
                }
                other => output.push(other),
            }
        }
        Ok(output)
    }

    fn parse_bool(&mut self) -> Result<bool, JsonError> {
        if self.starts_with("true") {
            self.expect_literal("true")?;
            Ok(true)
        } else {
            self.expect_literal("false")?;
            Ok(false)
        }
    }

    fn parse_number(&mut self) -> Result<String, JsonError> {
        let start = self.position;
        if self.peek() == Some('-') {
            self.advance();
        }
        while matches!(self.peek(), Some('0'..='9')) {
            self.advance();
        }
        if start == self.position {
            return Err(JsonError::new("expected number"));
        }
        Ok(self.input[start..self.position].to_owned())
    }

    fn expect_literal(&mut self, literal: &str) -> Result<(), JsonError> {
        if self.starts_with(literal) {
            self.position += literal.len();
            Ok(())
        } else {
            Err(JsonError::new(format!("expected `{literal}`")))
        }
    }

    fn expect(&mut self, ch: char) -> Result<(), JsonError> {
        self.skip_whitespace();
        match self.advance() {
            Some(found) if found == ch => Ok(()),
            Some(found) => Err(JsonError::new(format!("expected `{ch}`, found `{found}`"))),
            None => Err(JsonError::new(format!("expected `{ch}`"))),
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(' ' | '\n' | '\r' | '\t')) {
            self.advance();
        }
    }

    fn starts_with(&self, value: &str) -> bool {
        self.input[self.position..].starts_with(value)
    }

    fn peek(&self) -> Option<char> {
        self.input[self.position..].chars().next()
    }

    fn advance(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.position += character.len_utf8();
        Some(character)
    }

    fn is_eof(&self) -> bool {
        self.position >= self.input.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_snapshot_json_when_parse_then_subject_and_artifacts_are_available() {
        let snapshot = EvidenceSnapshot::from_json_str(
            r#"{
                "subject": { "kind": "pr", "id": "42" },
                "artifacts": [
                    { "path": ".governance/framed/scope.md", "content": "scope" }
                ],
                "receipts": [
                    { "tool": "diffguard", "check": "overall", "status": "pass" }
                ],
                "github": {
                    "linked_issue": 7,
                    "labels": ["gate:framed"],
                    "branch": "feat/7-example",
                    "approvals": 1,
                    "conversations_resolved": true
                },
                "ci": [
                    { "name": "test", "status": "pass" }
                ],
                "attestations": [
                    { "key": "merge-authorized", "value": "yes" }
                ]
            }"#,
        )
        .expect("snapshot");

        assert_eq!(snapshot.subject.id, "42");
        assert_eq!(snapshot.artifacts[0].path, ".governance/framed/scope.md");
        assert_eq!(snapshot.receipts[0].status, FactStatus::Pass);
        assert_eq!(
            snapshot
                .github
                .as_ref()
                .and_then(|facts| facts.linked_issue),
            Some(7)
        );
    }

    #[test]
    fn given_report_when_to_json_pretty_then_round_trip_succeeds() {
        let report = GateReport {
            schema: GATE_REPORT_SCHEMA.to_owned(),
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

        let round_trip = GateReport::from_json_str(&report.to_json_pretty()).expect("report");
        assert_eq!(round_trip.policy_id, "policy");
        assert_eq!(round_trip.gates[0].status, GateStatus::Pass);
    }
}
