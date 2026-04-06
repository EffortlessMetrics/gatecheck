//! Policy parsing and semantic validation for gatecheck.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::path::Path;

use gatecheck_types::{GateDefinition, GatePolicy, Requirement};

/// Policy parsing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Read(String),
    Parse(String),
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(message) | Self::Parse(message) => formatter.write_str(message),
        }
    }
}

impl Error for PolicyError {}

/// Load policy from disk.
pub fn load_policy(path: impl AsRef<Path>) -> Result<GatePolicy, PolicyError> {
    let path = path.as_ref();
    let contents = fs::read_to_string(path).map_err(|error| {
        PolicyError::Read(format!("failed to read policy {}: {error}", path.display()))
    })?;
    parse_policy(&contents)
}

/// Parse a gate policy from a restricted TOML subset.
pub fn parse_policy(input: &str) -> Result<GatePolicy, PolicyError> {
    let mut id = String::new();
    let mut version = String::new();
    let mut profile = String::new();
    let mut gates = Vec::<GateDefinition>::new();
    let mut current_gate: Option<GateDefinition> = None;

    let lines: Vec<&str> = input.lines().collect();
    let mut index = 0usize;
    while index < lines.len() {
        let line = strip_comments(lines[index]).trim();
        index += 1;
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if let Some(gate) = current_gate.take() {
                gates.push(gate);
            }
            let section = &line[1..line.len() - 1];
            let gate_id = section
                .strip_prefix("gates.")
                .ok_or_else(|| PolicyError::Parse(format!("unsupported section `{section}`")))?;
            current_gate = Some(GateDefinition {
                id: gate_id.to_owned(),
                name: title_case(gate_id),
                order: 0,
                depends_on: Vec::new(),
                requirements: Vec::new(),
            });
            continue;
        }

        let (key, value) = split_key_value(line)?;
        match current_gate.as_mut() {
            None => match key {
                "id" => id = parse_string(value)?,
                "version" => version = parse_string(value)?,
                "profile" => profile = parse_string(value)?,
                other => {
                    return Err(PolicyError::Parse(format!(
                        "unsupported top-level key `{other}`"
                    )))
                }
            },
            Some(gate) => match key {
                "name" => gate.name = parse_string(value)?,
                "order" => gate.order = parse_u16(value)?,
                "depends_on" => gate.depends_on = parse_string_array(value)?,
                "requires" => {
                    let mut buffer = value.to_owned();
                    while bracket_delta(&buffer) > 0 {
                        if index >= lines.len() {
                            return Err(PolicyError::Parse(
                                "unterminated requires array".to_owned(),
                            ));
                        }
                        let next = strip_comments(lines[index]);
                        buffer.push('\n');
                        buffer.push_str(next);
                        index += 1;
                    }
                    gate.requirements = parse_requirements(&buffer)?;
                }
                other => {
                    return Err(PolicyError::Parse(format!(
                        "unsupported gate key `{other}`"
                    )))
                }
            },
        }
    }

    if let Some(gate) = current_gate.take() {
        gates.push(gate);
    }

    if id.is_empty() {
        id = "gatecheck.policy".to_owned();
    }
    if version.is_empty() {
        version = "1".to_owned();
    }
    if profile.is_empty() {
        return Err(PolicyError::Parse("missing top-level `profile`".to_owned()));
    }
    if gates.is_empty() {
        return Err(PolicyError::Parse(
            "policy must declare at least one gate".to_owned(),
        ));
    }

    gates.sort_by_key(|gate| gate.order);
    for gate in &gates {
        if gate.order == 0 {
            return Err(PolicyError::Parse(format!(
                "gate `{}` is missing `order`",
                gate.id
            )));
        }
    }
    for window in gates.windows(2) {
        if window[0].order == window[1].order {
            return Err(PolicyError::Parse("gate orders must be unique".to_owned()));
        }
    }

    Ok(GatePolicy {
        id,
        version,
        profile,
        gates,
    })
}

fn strip_comments(line: &str) -> &str {
    let mut in_string = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => in_string = !in_string,
            '#' if !in_string => return &line[..index],
            _ => {}
        }
    }
    line
}

fn split_key_value(line: &str) -> Result<(&str, &str), PolicyError> {
    let mut in_string = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => in_string = !in_string,
            '=' if !in_string => {
                let key = line[..index].trim();
                let value = line[index + 1..].trim();
                return Ok((key, value));
            }
            _ => {}
        }
    }
    Err(PolicyError::Parse(format!(
        "expected key = value, got `{line}`"
    )))
}

fn bracket_delta(input: &str) -> i32 {
    let mut delta = 0_i32;
    let mut in_string = false;
    for character in input.chars() {
        match character {
            '"' => in_string = !in_string,
            '[' if !in_string => delta += 1,
            ']' if !in_string => delta -= 1,
            _ => {}
        }
    }
    delta
}

fn parse_string(input: &str) -> Result<String, PolicyError> {
    let trimmed = input.trim();
    if !(trimmed.starts_with('"') && trimmed.ends_with('"')) {
        return Err(PolicyError::Parse(format!(
            "expected quoted string, got `{input}`"
        )));
    }
    Ok(trimmed[1..trimmed.len() - 1].to_owned())
}

fn parse_u16(input: &str) -> Result<u16, PolicyError> {
    input
        .trim()
        .parse::<u16>()
        .map_err(|_| PolicyError::Parse(format!("expected integer, got `{input}`")))
}

fn parse_string_array(input: &str) -> Result<Vec<String>, PolicyError> {
    let trimmed = input.trim();
    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return Err(PolicyError::Parse(format!(
            "expected string array, got `{input}`"
        )));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    if inner.trim().is_empty() {
        return Ok(Vec::new());
    }
    split_top_level(inner, ',')
        .into_iter()
        .map(|piece| parse_string(piece.trim()))
        .collect()
}

fn parse_requirements(input: &str) -> Result<Vec<Requirement>, PolicyError> {
    let trimmed = input.trim();
    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return Err(PolicyError::Parse(format!(
            "expected array of inline tables, got `{input}`"
        )));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let tables = split_inline_tables(inner)?;
    tables
        .into_iter()
        .map(|table| parse_requirement_table(&table))
        .collect()
}

fn split_inline_tables(input: &str) -> Result<Vec<String>, PolicyError> {
    let mut tables = Vec::new();
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut start = None;

    for (index, character) in input.char_indices() {
        match character {
            '"' => in_string = !in_string,
            '{' if !in_string => {
                if depth == 0 {
                    start = Some(index);
                }
                depth += 1;
            }
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    if let Some(start_index) = start.take() {
                        tables.push(input[start_index..=index].to_owned());
                    }
                }
            }
            _ => {}
        }
    }

    if depth != 0 {
        return Err(PolicyError::Parse(
            "unbalanced inline table braces".to_owned(),
        ));
    }

    Ok(tables)
}

fn parse_requirement_table(table: &str) -> Result<Requirement, PolicyError> {
    let trimmed = table.trim();
    if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
        return Err(PolicyError::Parse(format!(
            "expected inline table, got `{table}`"
        )));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let pairs = split_top_level(inner, ',');
    let mut kind = String::new();
    let mut path = String::new();
    let mut tool = String::new();
    let mut check = String::new();
    let mut name = String::new();
    let mut key = String::new();
    let mut min_count = None;

    for pair in pairs {
        let (field, value) = split_key_value(pair.trim())?;
        match field {
            "kind" => kind = parse_string(value)?,
            "path" => path = parse_string(value)?,
            "tool" => tool = parse_string(value)?,
            "check" => check = parse_string(value)?,
            "name" => name = parse_string(value)?,
            "key" => key = parse_string(value)?,
            "min_count" => min_count = Some(parse_u16(value)? as u8),
            other => {
                return Err(PolicyError::Parse(format!(
                    "unsupported requirement field `{other}`"
                )))
            }
        }
    }

    match kind.as_str() {
        "artifact_exists" => Ok(Requirement::ArtifactExists { path }),
        "receipt_pass" => Ok(Requirement::ReceiptPass { tool, check }),
        "issue_linked" => Ok(Requirement::IssueLinked),
        "ci_check_passed" => Ok(Requirement::CiCheckPassed { name }),
        "review_approved" => Ok(Requirement::ReviewApproved {
            min_count: min_count.unwrap_or(1),
        }),
        "conversations_resolved" => Ok(Requirement::ConversationsResolved),
        "attestation_present" => Ok(Requirement::AttestationPresent { key }),
        other => Err(PolicyError::Parse(format!(
            "unsupported requirement kind `{other}`"
        ))),
    }
}

fn split_top_level(input: &str, separator: char) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut in_string = false;
    let mut brace_depth = 0_i32;
    let mut bracket_depth = 0_i32;
    let mut start = 0usize;

    for (index, character) in input.char_indices() {
        match character {
            '"' => in_string = !in_string,
            '{' if !in_string => brace_depth += 1,
            '}' if !in_string => brace_depth -= 1,
            '[' if !in_string => bracket_depth += 1,
            ']' if !in_string => bracket_depth -= 1,
            _ if !in_string && brace_depth == 0 && bracket_depth == 0 && character == separator => {
                pieces.push(input[start..index].trim());
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }

    let tail = input[start..].trim();
    if !tail.is_empty() {
        pieces.push(tail);
    }

    pieces
}

fn title_case(input: &str) -> String {
    input
        .split(['-', '_'])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_valid_policy_toml_when_parse_then_gates_are_sorted() {
        let policy = parse_policy(
            r#"
                profile = "conveyor-6"

                [gates.verified]
                order = 2
                requires = [{ kind = "artifact_exists", path = "verified.md" }]

                [gates.framed]
                order = 1
                requires = [{ kind = "issue_linked" }]
            "#,
        )
        .expect("policy");

        assert_eq!(policy.gates[0].id, "framed");
        assert_eq!(policy.gates[1].id, "verified");
        assert_eq!(policy.gates[0].name, "Framed");
    }

    #[test]
    fn given_duplicate_order_when_parse_then_error_is_returned() {
        let error = parse_policy(
            r#"
                profile = "conveyor-6"

                [gates.a]
                order = 1
                requires = [{ kind = "issue_linked" }]

                [gates.b]
                order = 1
                requires = [{ kind = "issue_linked" }]
            "#,
        )
        .expect_err("duplicate order");

        assert!(matches!(error, PolicyError::Parse(_)));
    }
}
