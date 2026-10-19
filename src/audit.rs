//! Export only the audit session explicitly assigned to this invocation.
use anyhow::{bail, Context, Result};
use rustix::fs::{open, openat, Mode, OFlags};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// This is an internal interface of the manifest-pinned nono. Its regular run
/// path reads this variable before creating the audit session:
/// https://github.com/nolabs-ai/nono/blob/v0.75.0/crates/nono-cli/src/launch_runtime.rs#L417
/// A version ignoring it fails export rather than substituting another session.
pub const SESSION_ENV: &str = "NONO_DETACHED_SESSION_ID";

enum ExportFile {
    Evidence,
    Summary,
}

pub struct AuditRun {
    session: String,
    output_base: PathBuf,
    output_dir: PathBuf,
    directory: File,
    directory_identity: (u64, u64),
}

impl AuditRun {
    #[must_use = "audit setup errors must abort the requested audited run"]
    pub fn prepare(base: &Path) -> Result<Self> {
        fs::create_dir_all(base).context("failed to create audit output base")?;
        let base = base
            .canonicalize()
            .context("failed to canonicalize audit output base")?;
        let directory = tempfile::Builder::new()
            .prefix("runseal-audit-")
            .tempdir_in(&base)
            .context("failed to create unique audit output directory")?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let metadata = fs::metadata(directory.path())?;
        let directory_identity = (metadata.dev(), metadata.ino());
        let directory_handle = File::from(open(
            directory.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        let opened = directory_handle.metadata()?;
        if (opened.dev(), opened.ino()) != directory_identity {
            bail!("audit output directory changed during setup");
        }
        let session = directory
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .context("audit output directory name is not UTF-8")?
            .to_string();
        validate_session_id(&session)?;
        let output_dir = directory.keep();
        Ok(Self {
            session,
            output_base: base,
            output_dir,
            directory: directory_handle,
            directory_identity,
        })
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn output_base(&self) -> &Path {
        &self.output_base
    }

    /// Publish before execution, so a failed command still has an upload path.
    #[must_use = "failed action outputs must abort the audited run"]
    pub fn publish_outputs(&self) -> Result<()> {
        if let Some(path) = std::env::var_os("GITHUB_OUTPUT") {
            let path = Path::new(&path)
                .canonicalize()
                .context("failed to canonicalize GITHUB_OUTPUT")?;
            if !path.is_file() {
                bail!("GITHUB_OUTPUT must be an existing regular file");
            }
            let mut output = OpenOptions::new().append(true).open(path)?;
            let directory = self
                .output_dir
                .to_str()
                .context("audit output path is not UTF-8")?;
            if directory.contains(['\r', '\n']) {
                bail!("audit output path contains a newline");
            }
            writeln!(output, "audit-directory={directory}")?;
            writeln!(output, "audit-artifact-name={}", self.session)?;
            writeln!(output, "audit-session-id={}", self.session)?;
        }
        println!("Runseal audit directory: {}", self.output_dir.display());
        Ok(())
    }

    #[must_use = "missing or invalid audit evidence must fail the audited run"]
    pub fn export(&self, command: &str, command_failed: bool) -> Result<()> {
        self.validate_output_directory()?;
        let result = self.export_json(command);
        let outcome = if command_failed {
            "failed"
        } else {
            "succeeded"
        };
        let summary = match &result {
            Ok(()) => format!(
                "# Runseal Audit Export\n\nCommand {outcome}.\n\nExported the explicitly assigned session `{}` to `{}.json`.\n",
                self.session, self.session
            ),
            Err(error) => format!(
                "# Runseal Audit Export\n\nCommand {outcome}.\n\nAudit export failed: {error:#}\n\nNo other session was substituted.\n"
            ),
        };
        let summary_result = self.write_new(ExportFile::Summary, summary.as_bytes());
        // Writes stay anchored to the original directory even if its pathname
        // changes. Refuse success if the action's published path was replaced.
        self.validate_output_directory()?;
        match (result, summary_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(export), Err(summary)) => bail!(
                "audit export failed: {export:#}; writing failure summary also failed: {summary:#}"
            ),
        }
    }

    fn validate_output_directory(&self) -> Result<()> {
        let metadata = fs::symlink_metadata(&self.output_dir)?;
        if !metadata.is_dir()
            || (metadata.dev(), metadata.ino()) != self.directory_identity
            || self.output_dir.canonicalize()? != self.output_dir
        {
            bail!("audit output directory changed during execution");
        }
        Ok(())
    }

    fn export_json(&self, command: &str) -> Result<()> {
        let output = Command::new("nono")
            .args(["audit", "show", &self.session, "--json"])
            .env("NONO_NO_MIGRATE", "1")
            .output()
            .context("failed to run nono audit show for assigned session")?;
        if !output.status.success() {
            bail!(
                "no audit evidence for assigned session '{}': nono audit show exited with {}: {}",
                self.session,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let json: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("nono audit show did not return valid JSON")?;
        validate_evidence(&json, &self.session, command)?;
        self.write_new(ExportFile::Evidence, &output.stdout)
    }

    #[must_use = "audit write failures must be reported"]
    fn write_new(&self, export: ExportFile, bytes: &[u8]) -> Result<()> {
        // Filenames are fixed or derived from our validated session ID; callers
        // cannot supply paths. O_EXCL refuses existing entries and symlinks.
        let name = match export {
            ExportFile::Evidence => format!("{}.json", self.session),
            ExportFile::Summary => "summary.md".to_string(),
        };
        let mut file = File::from(
            openat(
                &self.directory,
                name.as_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .with_context(|| format!("failed to create audit export '{name}'"))?,
        );
        file.write_all(bytes)
            .with_context(|| format!("failed to write audit export '{name}'"))
    }
}

fn validate_evidence(json: &serde_json::Value, session: &str, command: &str) -> Result<()> {
    validate_session_id(session)?;
    if json.get("session_id").and_then(serde_json::Value::as_str) != Some(session) {
        bail!("audit JSON does not identify the assigned session '{session}'");
    }
    let argv = json
        .get("command")
        .and_then(serde_json::Value::as_array)
        .context("audit JSON has no command array")?;
    // nono may resolve bash to an absolute executable path.
    let shell = argv.first().and_then(serde_json::Value::as_str);
    if argv.len() != 3
        || shell
            .and_then(|shell| Path::new(shell).file_name())
            .is_none_or(|shell| shell != "bash")
        || argv.get(1).and_then(serde_json::Value::as_str) != Some("-c")
        || argv.get(2).and_then(serde_json::Value::as_str) != Some(command)
    {
        bail!("audit JSON command does not match this invocation");
    }
    Ok(())
}

fn validate_session_id(session: &str) -> Result<()> {
    if session.is_empty()
        || session.len() > 64
        || !session
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        bail!("nono audit session id '{session}' is invalid");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_escaping_or_unbounded_session_ids() {
        for session in [
            "",
            "../../evil",
            "/tmp/evil",
            "name with spaces",
            &"a".repeat(65),
        ] {
            assert!(validate_session_id(session).is_err(), "{session}");
        }
    }

    #[test]
    fn evidence_must_match_both_assigned_session_and_command() -> Result<()> {
        let good = serde_json::json!({"session_id": "runseal-audit-123", "command": ["/usr/bin/bash", "-c", "exit 3"]});
        validate_evidence(&good, "runseal-audit-123", "exit 3")?;
        assert!(validate_evidence(&good, "runseal-audit-456", "exit 3").is_err());
        assert!(validate_evidence(&good, "runseal-audit-123", "true").is_err());
        assert!(validate_evidence(&serde_json::json!({}), "runseal-audit-123", "true").is_err());
        Ok(())
    }

    #[test]
    fn each_invocation_has_its_own_private_directory() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir()?;
        let one = AuditRun::prepare(base.path())?;
        let two = AuditRun::prepare(base.path())?;
        assert_ne!(one.session(), two.session());
        assert_ne!(one.output_dir, two.output_dir);
        assert!(one.output_dir.starts_with(base.path().canonicalize()?));
        assert_eq!(
            fs::metadata(one.output_dir)?.permissions().mode() & 0o777,
            0o700
        );
        Ok(())
    }

    #[test]
    fn replacing_an_output_directory_at_the_same_path_is_rejected() -> Result<()> {
        let base = tempfile::tempdir()?;
        let audit = AuditRun::prepare(base.path())?;
        fs::rename(&audit.output_dir, base.path().join("original"))?;
        fs::create_dir(&audit.output_dir)?;
        assert!(audit.validate_output_directory().is_err());
        Ok(())
    }

    #[test]
    fn output_files_are_never_replaced_or_followed() -> Result<()> {
        let base = tempfile::tempdir()?;
        let audit = AuditRun::prepare(base.path())?;
        let target = audit.output_dir.join(format!("{}.json", audit.session));
        fs::write(&target, "original")?;
        let link = audit.output_dir.join("summary.md");
        std::os::unix::fs::symlink(&target, &link)?;
        assert!(audit
            .write_new(ExportFile::Summary, b"replacement")
            .is_err());
        assert!(audit
            .write_new(ExportFile::Evidence, b"replacement")
            .is_err());
        assert_eq!(fs::read_to_string(target)?, "original");
        Ok(())
    }

    #[test]
    fn writes_stay_in_the_opened_directory_after_path_replacement() -> Result<()> {
        let base = tempfile::tempdir()?;
        let audit = AuditRun::prepare(base.path())?;
        let original = base.path().join("original");
        let replacement = base.path().join("replacement");
        audit.validate_output_directory()?;
        fs::rename(&audit.output_dir, &original)?;
        fs::create_dir(&replacement)?;
        std::os::unix::fs::symlink(&replacement, &audit.output_dir)?;
        audit.write_new(ExportFile::Summary, b"evidence")?;
        assert_eq!(fs::read(original.join("summary.md"))?, b"evidence");
        assert_eq!(fs::read_dir(&replacement)?.count(), 0);
        assert!(audit.validate_output_directory().is_err());
        assert_eq!(
            fs::metadata(original.join("summary.md"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        Ok(())
    }
}
