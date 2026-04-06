//! Filesystem adapters for gatecheck.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use gatecheck_policy::{load_policy, PolicyError};
use gatecheck_types::{EvidenceSnapshot, GatePolicy, GateReport, JsonError};

/// Filesystem adapter errors.
#[derive(Debug)]
pub enum FsError {
    Read(String),
    Write(String),
    Parse(String),
    UnsupportedPreset(String),
}

impl Display for FsError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(message)
            | Self::Write(message)
            | Self::Parse(message)
            | Self::UnsupportedPreset(message) => formatter.write_str(message),
        }
    }
}

impl Error for FsError {}

impl From<PolicyError> for FsError {
    fn from(error: PolicyError) -> Self {
        Self::Parse(error.to_string())
    }
}

impl From<JsonError> for FsError {
    fn from(error: JsonError) -> Self {
        Self::Parse(error.to_string())
    }
}

/// Load a policy from disk.
pub fn read_policy(path: impl AsRef<Path>) -> Result<GatePolicy, FsError> {
    load_policy(path).map_err(Into::into)
}

/// Load a snapshot from disk.
pub fn read_snapshot(path: impl AsRef<Path>) -> Result<EvidenceSnapshot, FsError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path).map_err(|error| {
        FsError::Read(format!(
            "failed to read snapshot {}: {error}",
            path.display()
        ))
    })?;
    EvidenceSnapshot::from_json_str(&contents).map_err(Into::into)
}

/// Load a report from disk.
pub fn read_report(path: impl AsRef<Path>) -> Result<GateReport, FsError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path).map_err(|error| {
        FsError::Read(format!("failed to read report {}: {error}", path.display()))
    })?;
    GateReport::from_json_str(&contents).map_err(Into::into)
}

/// Persist a report to disk.
pub fn write_report(path: impl AsRef<Path>, report: &GateReport) -> Result<(), FsError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            FsError::Write(format!(
                "failed to create report directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    fs::write(path, report.to_json_pretty()).map_err(|error| {
        FsError::Write(format!(
            "failed to write report {}: {error}",
            path.display()
        ))
    })
}

/// Persist Markdown to disk.
pub fn write_markdown(path: impl AsRef<Path>, markdown: &str) -> Result<(), FsError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            FsError::Write(format!(
                "failed to create markdown directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    fs::write(path, markdown).map_err(|error| {
        FsError::Write(format!(
            "failed to write markdown {}: {error}",
            path.display()
        ))
    })
}

/// Scaffold a starter preset.
pub fn scaffold_preset(root: impl AsRef<Path>, preset: &str) -> Result<Vec<PathBuf>, FsError> {
    let root = root.as_ref();
    match preset {
        "conveyor-6" => scaffold_conveyor(root),
        other => Err(FsError::UnsupportedPreset(format!(
            "unsupported preset `{other}`"
        ))),
    }
}

fn scaffold_conveyor(root: &Path) -> Result<Vec<PathBuf>, FsError> {
    let files = [
        (".governance/gates.toml", PRESET_GATES),
        (
            ".governance/framed/scope.md",
            "# Scope\n\nProblem statement and acceptance criteria.\n",
        ),
        (
            ".governance/framed/research.md",
            "# Research\n\nLinks, notes, and prior art.\n",
        ),
        (
            ".governance/verified/verification-report.md",
            "# Verification Report\n\nWhat was checked and what remains unknown.\n",
        ),
        (
            ".governance/designed/adr.md",
            "# ADR\n\nDecision, tradeoffs, and non-goals.\n",
        ),
        (
            ".governance/designed/tasks.md",
            "# Tasks\n\nImplementation checklist.\n",
        ),
        (".github/PULL_REQUEST_TEMPLATE.md", PRESET_PR_TEMPLATE),
        (".github/ISSUE_TEMPLATE/feature.md", PRESET_ISSUE_TEMPLATE),
        (".github/workflows/gatecheck.yml", PRESET_WORKFLOW),
    ];

    let mut written = Vec::new();
    for (relative, contents) in files {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                FsError::Write(format!(
                    "failed to create preset directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        fs::write(&path, contents).map_err(|error| {
            FsError::Write(format!(
                "failed to write preset file {}: {error}",
                path.display()
            ))
        })?;
        written.push(path);
    }
    Ok(written)
}

const PRESET_GATES: &str = include_str!("../../../fixtures/policies/conveyor-6.toml");
const PRESET_PR_TEMPLATE: &str = "## Conveyor checklist\n\n- [ ] Linked issue\n- [ ] Framed artifacts checked in\n- [ ] Verified artifact checked in\n- [ ] Designed artifacts checked in\n- [ ] Proven evidence attached\n- [ ] Hardened review complete\n";
const PRESET_ISSUE_TEMPLATE: &str = "# Feature\n\n## Problem\n\n## Acceptance criteria\n";
const PRESET_WORKFLOW: &str = "name: gatecheck\n\non:\n  pull_request:\n\njobs:\n  gatecheck:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: dtolnay/rust-toolchain@stable\n      - name: gatecheck\n        run: |\n          cargo run -p gatecheck -- eval \\\n            --policy .governance/gates.toml \\\n            --snapshot artifacts/gatecheck/snapshot.json \\\n            --out artifacts/gatecheck/report.json \\\n            --md artifacts/gatecheck/comment.md\n";

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{nanos}"));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn given_snapshot_json_when_read_snapshot_then_data_is_available() {
        let dir = temp_dir("gatecheck-read-snapshot");
        let path = dir.join("snapshot.json");
        fs::write(
            &path,
            r#"{"subject":{"kind":"pr","id":"1"},"artifacts":[],"receipts":[],"ci":[],"attestations":[]}"#,
        )
        .expect("snapshot");

        let snapshot = read_snapshot(&path).expect("snapshot parsed");
        assert_eq!(snapshot.subject.kind, "pr");
    }

    #[test]
    fn given_report_when_write_report_then_json_is_written() {
        let dir = temp_dir("gatecheck-write-report");
        let path = dir.join("out/report.json");
        let report = GateReport {
            schema: "gate.report.v1".to_owned(),
            policy_id: "policy".to_owned(),
            profile: "conveyor-6".to_owned(),
            subject: gatecheck_types::SubjectRef {
                kind: "pr".to_owned(),
                id: "1".to_owned(),
            },
            earned_gate: Some("framed".to_owned()),
            blocked_at: None,
            next_gate: None,
            gates: vec![],
        };

        write_report(&path, &report).expect("write report");
        let contents = fs::read_to_string(&path).expect("read report");
        assert!(contents.contains("\"policy_id\": \"policy\""));
    }

    #[test]
    fn given_conveyor_preset_when_scaffold_then_expected_files_are_created() {
        let dir = temp_dir("gatecheck-preset");
        let paths = scaffold_preset(&dir, "conveyor-6").expect("preset scaffold");
        assert!(paths
            .iter()
            .any(|path| path.ends_with(".governance/gates.toml")));
        assert!(dir.join(".github/workflows/gatecheck.yml").exists());
    }
}
