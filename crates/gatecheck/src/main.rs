//! CLI leaf crate for gatecheck.

use std::env;
use std::path::PathBuf;
use std::process;

use gatecheck_codes::ExitCode;
use gatecheck_eval::evaluate;
use gatecheck_export_markdown::render;
use gatecheck_fs::{
    read_policy, read_report, read_snapshot, scaffold_preset, write_markdown, write_report,
};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let exit = match run(args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::InternalError
        }
    };
    process::exit(exit.code());
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let Some((command, rest)) = args.split_first() else {
        print_usage();
        return Ok(ExitCode::Usage);
    };

    match command.as_str() {
        "eval" => run_eval(rest),
        "init" => run_init(rest),
        "explain" => run_explain(rest),
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(ExitCode::Success)
        }
        other => Err(format!("unknown command `{other}`")),
    }
}

fn run_eval(args: &[String]) -> Result<ExitCode, String> {
    let policy = required_flag(args, "--policy")?;
    let snapshot = required_flag(args, "--snapshot")?;
    let out = optional_flag(args, "--out");
    let markdown = optional_flag(args, "--md");

    let policy = read_policy(policy).map_err(|error| error.to_string())?;
    let snapshot = read_snapshot(snapshot).map_err(|error| error.to_string())?;
    let report = evaluate(&policy, &snapshot).map_err(|error| error.to_string())?;

    if let Some(path) = out {
        write_report(path, &report).map_err(|error| error.to_string())?;
    }
    if let Some(path) = markdown {
        write_markdown(path, &render(&report)).map_err(|error| error.to_string())?;
    }

    println!("{}", report.to_json_pretty());

    if report.blocked_at.is_some() {
        Ok(ExitCode::GateBlocked)
    } else {
        Ok(ExitCode::Success)
    }
}

fn run_init(args: &[String]) -> Result<ExitCode, String> {
    let preset = required_string_flag(args, "--preset")?;
    let path = optional_flag(args, "--path").unwrap_or_else(|| PathBuf::from("."));
    let written = scaffold_preset(path, &preset).map_err(|error| error.to_string())?;
    for item in written {
        println!("{}", item.display());
    }
    Ok(ExitCode::Success)
}

fn run_explain(args: &[String]) -> Result<ExitCode, String> {
    let report_path = required_flag(args, "--report")?;
    let report = read_report(report_path).map_err(|error| error.to_string())?;
    print!("{}", render(&report));
    Ok(ExitCode::Success)
}

fn required_flag(args: &[String], flag: &str) -> Result<PathBuf, String> {
    optional_flag(args, flag).ok_or_else(|| format!("missing required flag `{flag}`"))
}

fn required_string_flag(args: &[String], flag: &str) -> Result<String, String> {
    optional_string_flag(args, flag).ok_or_else(|| format!("missing required flag `{flag}`"))
}

fn optional_flag(args: &[String], flag: &str) -> Option<PathBuf> {
    optional_string_flag(args, flag).map(PathBuf::from)
}

fn optional_string_flag(args: &[String], flag: &str) -> Option<String> {
    args.windows(2)
        .find(|window| window[0] == flag)
        .map(|window| window[1].clone())
}

fn print_usage() {
    println!(
        "gatecheck\n\n  gatecheck eval --policy <path> --snapshot <path> [--out <path>] [--md <path>]\n  gatecheck init --preset <name> [--path <dir>]\n  gatecheck explain --report <path>"
    );
}
