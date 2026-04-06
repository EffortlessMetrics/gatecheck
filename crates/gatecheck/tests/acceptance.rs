use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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
fn given_example_policy_and_snapshot_when_eval_then_json_mentions_designed_blocker() {
    let binary = env!("CARGO_BIN_EXE_gatecheck");
    let output = Command::new(binary)
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args([
            "eval",
            "--policy",
            "examples/conveyor-6/gates.toml",
            "--snapshot",
            "examples/conveyor-6/snapshot.json",
        ])
        .output()
        .expect("run gatecheck");

    assert_eq!(output.status.code(), Some(4));
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.contains("\"blocked_at\": \"designed\""));
}

#[test]
fn given_temp_dir_when_init_then_preset_files_are_created() {
    let binary = env!("CARGO_BIN_EXE_gatecheck");
    let dir = temp_dir("gatecheck-init");
    let output = Command::new(binary)
        .args([
            "init",
            "--preset",
            "conveyor-6",
            "--path",
            dir.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run gatecheck");

    assert!(output.status.success());
    assert!(dir.join(".governance/gates.toml").exists());
    assert!(dir.join(".github/workflows/gatecheck.yml").exists());
}

#[test]
fn given_report_when_explain_then_markdown_is_emitted() {
    let binary = env!("CARGO_BIN_EXE_gatecheck");
    let dir = temp_dir("gatecheck-explain");
    let report_path = dir.join("report.json");
    fs::write(
        &report_path,
        r#"{
            "schema": "gate.report.v1",
            "policy_id": "policy",
            "profile": "conveyor-6",
            "subject": { "kind": "pr", "id": "1" },
            "earned_gate": "framed",
            "blocked_at": null,
            "next_gate": null,
            "gates": []
        }"#,
    )
    .expect("write report");

    let output = Command::new(binary)
        .args([
            "explain",
            "--report",
            report_path.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("run gatecheck");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 stdout");
    assert!(stdout.contains("# gatecheck report"));
}
