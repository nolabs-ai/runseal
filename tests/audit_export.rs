use anyhow::{Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Fixture {
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let fake = directory.path().join("nono");
        fs::write(
            &fake,
            r#"#!/bin/sh
set -eu
case "$1" in
run)
  while [ "$1" != --profile ]; do shift; done
  cp "$2" "$TEST_AUDIT_PROFILE"
  printf '%s' "$NONO_DETACHED_SESSION_ID" > "$TEST_AUDIT_STATE"
  exit "$TEST_RUN_STATUS"
  ;;
audit)
  test "$2" = show
  printf '%s\n' "$3" >> "$TEST_AUDIT_QUERIES"
  case "$TEST_AUDIT_MODE" in
    missing) echo 'assigned session not found; old session still exists' >&2; exit 4;;
    invalid-json) printf 'not json'; exit 0;;
    mismatch) session=old-session;;
    replace-directory)
      directory="$(sed -n 's/^audit-directory=//p' "$GITHUB_OUTPUT")"
      mv "$directory" "$TEST_AUDIT_ORIGINAL"
      mkdir "$TEST_AUDIT_REPLACEMENT"
      ln -s "$TEST_AUDIT_REPLACEMENT" "$directory"
      session="$(cat "$TEST_AUDIT_STATE")"
      ;;
    *) session="$(cat "$TEST_AUDIT_STATE")";;
  esac
  printf '{"session_id":"%s","command":["/usr/bin/bash","-c","%s"],"audit_event_count":2}\n' "$session" "$TEST_COMMAND"
  ;;
*) exit 9;;
esac
"#,
        )?;
        fs::set_permissions(fake, fs::Permissions::from_mode(0o700))?;
        Ok(Self { directory })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    fn run(&self, mode: &str, status: i32) -> Result<(Output, PathBuf, String)> {
        let outputs = self.path("outputs");
        fs::write(&outputs, "")?;
        let path = std::env::join_paths([
            self.directory.path(),
            Path::new("/usr/bin"),
            Path::new("/bin"),
        ])?;
        let output = Command::new(env!("CARGO_BIN_EXE_runseal"))
            .arg("run")
            .current_dir(self.directory.path())
            .env("PATH", path)
            .env("RUNSEAL_RUN", "exit 7")
            .env("TEST_COMMAND", "exit 7")
            .env("RUNSEAL_PROFILE", "")
            .env("RUNSEAL_POLICY", "network:\n  mode: blocked\n")
            .env("RUNSEAL_AUDIT", "artifact")
            .env("RUNSEAL_AUDIT_DIR", self.path("exports"))
            .env("GITHUB_OUTPUT", &outputs)
            .env("TEST_AUDIT_STATE", self.path("state"))
            .env("TEST_AUDIT_PROFILE", self.path("profile.json"))
            .env("TEST_AUDIT_ORIGINAL", self.path("original"))
            .env("TEST_AUDIT_REPLACEMENT", self.path("replacement"))
            .env("TEST_AUDIT_QUERIES", self.path("queries"))
            .env("TEST_AUDIT_MODE", mode)
            .env("TEST_RUN_STATUS", status.to_string())
            .env("GITHUB_WORKSPACE", self.directory.path())
            .output()?;
        let outputs = fs::read_to_string(outputs)?;
        let directory = outputs
            .lines()
            .find_map(|line| line.strip_prefix("audit-directory="))
            .context("no audit directory output")?;
        let session = outputs
            .lines()
            .find_map(|line| line.strip_prefix("audit-session-id="))
            .context("no audit session output")?
            .to_string();
        assert!(outputs
            .lines()
            .any(|line| line == format!("audit-artifact-name={session}")));
        Ok((output, PathBuf::from(directory), session))
    }
}

#[test]
fn repeated_steps_export_only_their_assigned_sessions() -> Result<()> {
    let fixture = Fixture::new()?;
    let (first, first_directory, first_session) = fixture.run("success", 0)?;
    let (second, second_directory, second_session) = fixture.run("success", 0)?;
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    assert_ne!(first_directory, second_directory);
    assert_ne!(first_session, second_session);
    for (directory, session) in [
        (first_directory, first_session.clone()),
        (second_directory, second_session.clone()),
    ] {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(directory.join(format!("{session}.json")))?)?;
        assert_eq!(value["session_id"], session);
        assert_eq!(
            fs::read_dir(directory)?.count(),
            2,
            "only JSON and summary belong in each export"
        );
    }
    assert_eq!(
        fs::read_to_string(fixture.path("queries"))?,
        format!("{first_session}\n{second_session}\n")
    );
    Ok(())
}

#[test]
fn sandbox_profile_denies_the_audit_base() -> Result<()> {
    let fixture = Fixture::new()?;
    let (output, _, _) = fixture.run("success", 0)?;
    assert!(output.status.success(), "{output:?}");
    let profile: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.path("profile.json"))?)?;
    assert_eq!(
        profile["filesystem"]["deny"],
        serde_json::json!([fixture.path("exports").canonicalize()?])
    );
    Ok(())
}

#[test]
fn directory_replaced_during_audit_query_cannot_redirect_export() -> Result<()> {
    let fixture = Fixture::new()?;
    let (output, _, session) = fixture.run("replace-directory", 0)?;
    assert!(!output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("audit output directory changed during execution"));
    assert_eq!(fs::read_dir(fixture.path("replacement"))?.count(), 0);
    assert!(fixture
        .path("original")
        .join(format!("{session}.json"))
        .is_file());
    assert!(fixture.path("original").join("summary.md").is_file());
    Ok(())
}

#[test]
fn failed_command_still_exports_its_evidence_and_remains_failed() -> Result<()> {
    let fixture = Fixture::new()?;
    let (output, directory, session) = fixture.run("success", 7)?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nono run failed"));
    assert!(directory.join(format!("{session}.json")).is_file());
    assert!(fs::read_to_string(directory.join("summary.md"))?.contains("Command failed"));
    Ok(())
}

#[test]
fn missing_malformed_or_wrong_session_evidence_fails_closed() -> Result<()> {
    for mode in ["missing", "invalid-json", "mismatch"] {
        let fixture = Fixture::new()?;
        let (output, directory, session) = fixture.run(mode, 0)?;
        assert!(!output.status.success(), "{mode}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("failed to export nono audit evidence"));
        assert!(!directory.join(format!("{session}.json")).exists());
        let summary = fs::read_to_string(directory.join("summary.md"))?;
        assert!(summary.contains("Audit export failed"));
        assert!(summary.contains("No other session was substituted"));
        assert_eq!(
            fs::read_to_string(fixture.path("queries"))?,
            format!("{session}\n")
        );
    }
    Ok(())
}

#[test]
fn command_and_audit_failures_are_both_reported() -> Result<()> {
    let fixture = Fixture::new()?;
    let (output, directory, _) = fixture.run("missing", 7)?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("nono run failed"), "{stderr}");
    assert!(stderr.contains("exit status: 7"), "{stderr}");
    assert!(stderr.contains("audit export also failed"), "{stderr}");
    assert!(stderr.contains("assigned session not found"), "{stderr}");
    assert!(fs::read_to_string(directory.join("summary.md"))?.contains("Command failed"));
    Ok(())
}

/// Linux-only acceptance, with an isolated unenrolled nono config. No external
/// network requests are needed. Run with the manifest-pinned nono installed.
#[test]
#[ignore = "requires Linux Landlock and the manifest-pinned nono on PATH"]
fn real_nono_exports_exact_failed_session() -> Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!("this acceptance test requires Linux Landlock");
    }
    let pinned = include_str!("../.github/nono-version/Cargo.toml")
        .lines()
        .find_map(|line| line.trim().strip_prefix("nono-cli = "))
        .context("missing nono pin")?
        .trim_matches('"')
        .trim_start_matches('=');
    let version = Command::new("nono").arg("--version").output()?;
    assert!(version.status.success());
    assert_eq!(
        String::from_utf8(version.stdout)?.trim(),
        format!("nono {pinned}")
    );
    let base = tempfile::Builder::new()
        .prefix("runseal-audit-test-")
        .tempdir_in(fs::canonicalize("/var/tmp")?)?;
    let workspace = base.path().join("workspace");
    fs::create_dir(&workspace)?;
    let outputs = base.path().join("outputs");
    fs::write(&outputs, "")?;
    let config = base.path().join("empty-config");
    fs::create_dir(&config)?;
    // nono platform_client::load_state reads enrollment exclusively from
    // config::user_config_dir()/platform.json; keep the test unenrolled.
    let output = Command::new(env!("CARGO_BIN_EXE_runseal"))
        .arg("run")
        .current_dir(&workspace)
        .env("XDG_CONFIG_HOME", config)
        .env("XDG_STATE_HOME", base.path().join("state"))
        .env("NONO_NO_MIGRATE", "1")
        .env("RUNSEAL_RUN", "exit 7")
        .env("RUNSEAL_PROFILE", "")
        .env(
            "RUNSEAL_POLICY",
            "fs:\n  read: [\".\"]\nnetwork:\n  mode: blocked\n",
        )
        .env("RUNSEAL_AUDIT", "artifact")
        .env("RUNSEAL_AUDIT_DIR", base.path().join("exports"))
        .env("GITHUB_OUTPUT", &outputs)
        .env("GITHUB_WORKSPACE", &workspace)
        .output()?;
    assert!(
        !output.status.success(),
        "failed command must remain failed"
    );
    let outputs = fs::read_to_string(outputs)?;
    let directory = outputs
        .lines()
        .find_map(|line| line.strip_prefix("audit-directory="))
        .context("missing directory output")?;
    let session = outputs
        .lines()
        .find_map(|line| line.strip_prefix("audit-session-id="))
        .context("missing session output")?;
    let evidence: serde_json::Value = serde_json::from_slice(
        &fs::read(Path::new(directory).join(format!("{session}.json")))
            .with_context(|| format!("missing real nono evidence: {output:?}"))?,
    )?;
    assert_eq!(evidence["session_id"], session);
    assert_eq!(evidence["exit_code"], 7);
    assert!(fs::read_to_string(Path::new(directory).join("summary.md"))?.contains("Command failed"));
    Ok(())
}
