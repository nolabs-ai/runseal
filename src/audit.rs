use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct AuditSnapshot {
    sessions: Vec<String>,
}

pub struct AuditExport {
    pub sessions: Vec<String>,
    pub used_latest_fallback: bool,
}

impl AuditSnapshot {
    pub fn capture() -> Self {
        Self {
            sessions: audit_sessions().unwrap_or_default(),
        }
    }

    pub fn new_sessions_since(&self) -> AuditExport {
        let after = audit_sessions().unwrap_or_default();
        let before: BTreeSet<&str> = self.sessions.iter().map(String::as_str).collect();
        let mut sessions = after
            .iter()
            .filter(|session| !before.contains(session.as_str()))
            .cloned()
            .collect::<Vec<_>>();

        let used_latest_fallback = sessions.is_empty();
        if used_latest_fallback {
            if let Some(latest) = after.first() {
                sessions.push(latest.clone());
            }
        }

        AuditExport {
            sessions,
            used_latest_fallback,
        }
    }
}

pub fn export_sessions(export: &AuditExport, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "failed to create audit output dir '{}'",
            output_dir.display()
        )
    })?;

    let mut summary = String::new();
    summary.push_str("# Runseal Audit Export\n\n");

    if export.sessions.is_empty() {
        summary.push_str("No new nono audit sessions were detected.\n");
    }

    if export.used_latest_fallback && !export.sessions.is_empty() {
        summary.push_str(
            "No before/after session diff was detected; exported latest visible session.\n\n",
        );
    }

    for session in &export.sessions {
        validate_session_id(session)?;
        let json = Command::new("nono")
            .arg("audit")
            .arg("show")
            .arg(session)
            .arg("--json")
            .output()
            .with_context(|| format!("failed to run nono audit show {session} --json"))?;

        if json.status.success() {
            fs::write(output_dir.join(format!("{session}.json")), json.stdout)
                .with_context(|| format!("failed to write audit JSON for session {session}"))?;
            summary.push_str(&format!("- `{session}.json`\n"));
        } else {
            let stderr = String::from_utf8_lossy(&json.stderr);
            fs::write(
                output_dir.join(format!("{session}.error.txt")),
                stderr.as_bytes(),
            )
            .with_context(|| format!("failed to write audit error for session {session}"))?;
            summary.push_str(&format!("- `{session}.error.txt`\n"));
        }
    }

    fs::write(output_dir.join("summary.md"), summary).with_context(|| {
        format!(
            "failed to write audit summary in '{}'",
            output_dir.display()
        )
    })?;
    Ok(())
}

fn audit_sessions() -> Result<Vec<String>> {
    let output = Command::new("nono")
        .arg("audit")
        .arg("list")
        .arg("--json")
        .output()
        .context("failed to run nono audit list")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return parse_audit_list_json(&stdout);
    }

    let output = Command::new("nono")
        .arg("audit")
        .arg("list")
        .output()
        .context("failed to run nono audit list fallback")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format!("{stdout}\n{stderr}")
        .lines()
        .filter_map(parse_session_id)
        .map(ToOwned::to_owned)
        .collect())
}

#[derive(Deserialize)]
struct AuditListEntry {
    session_id: String,
}

fn parse_audit_list_json(output: &str) -> Result<Vec<String>> {
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }

    let entries: Vec<AuditListEntry> =
        serde_json::from_str(output).context("failed to parse nono audit list --json output")?;
    let mut sessions = Vec::new();
    for entry in entries {
        if entry.session_id.trim().is_empty() {
            continue;
        }
        validate_session_id(&entry.session_id)?;
        sessions.push(entry.session_id);
    }
    Ok(sessions)
}

fn parse_session_id(line: &str) -> Option<&str> {
    line.split_whitespace()
        .find(|part| is_valid_session_id(part))
}

fn validate_session_id(session: &str) -> Result<()> {
    if !is_valid_session_id(session) {
        bail!("nono audit session id '{session}' is invalid");
    }
    Ok(())
}

fn is_valid_session_id(session: &str) -> bool {
    !session.is_empty() && session.chars().all(|ch| ch.is_ascii_digit() || ch == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_session_id_from_plain_line() {
        assert_eq!(
            parse_session_id("20260511-125727-22312 blocked command"),
            Some("20260511-125727-22312")
        );
    }

    #[test]
    fn parses_session_id_after_prefix_columns() {
        assert_eq!(
            parse_session_id("session 20260511-125727-22312"),
            Some("20260511-125727-22312")
        );
    }

    #[test]
    fn parses_session_ids_from_json_list() {
        let sessions = parse_audit_list_json(
            r#"[
              {
                "session_id": "20260606-184133-1234",
                "command": "bash -c cargo publish"
              },
              {
                "session_id": "20260606-184200-5678",
                "command": "true"
              }
            ]"#,
        )
        .expect("parse json");

        assert_eq!(
            sessions,
            vec!["20260606-184133-1234", "20260606-184200-5678"]
        );
    }

    #[test]
    fn rejects_traversal_session_ids_from_json_list() {
        let err = parse_audit_list_json(
            r#"[
              {
                "session_id": "../../../../tmp/evil",
                "command": "true"
              }
            ]"#,
        )
        .expect_err("traversal session id must fail");

        assert!(
            err.to_string().contains("session id"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn rejects_absolute_session_ids_from_json_list() {
        let err = parse_audit_list_json(
            r#"[
              {
                "session_id": "/tmp/evil",
                "command": "true"
              }
            ]"#,
        )
        .expect_err("absolute session id must fail");

        assert!(
            err.to_string().contains("session id"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn export_rejects_invalid_session_ids_before_writing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let export = AuditExport {
            sessions: vec!["../../evil".to_string()],
            used_latest_fallback: false,
        };

        let err = export_sessions(&export, dir.path()).expect_err("invalid session id must fail");

        assert!(
            err.to_string().contains("session id"),
            "unexpected error: {err:#}"
        );
        assert!(
            !dir.path().join("evil.error.txt").exists(),
            "invalid session id must not be written"
        );
    }

    #[test]
    fn empty_json_list_output_has_no_sessions() {
        assert!(parse_audit_list_json("").unwrap().is_empty());
    }
}
