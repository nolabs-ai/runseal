use anyhow::{Context, Result};
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
        .output()
        .context("failed to run nono audit list")?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter_map(parse_session_id)
        .map(ToOwned::to_owned)
        .collect())
}

fn parse_session_id(line: &str) -> Option<&str> {
    line.split_whitespace()
        .find(|part| part.chars().all(|ch| ch.is_ascii_digit() || ch == '-'))
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
}
