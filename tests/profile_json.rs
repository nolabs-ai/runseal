use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn blocked_network_with_credentials_emits_block_true_profile_json() {
    let policy = r#"
fs:
  read: ["."]
  write: []
network:
  mode: blocked
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    allow:
      - GET /api/v1/crates
"#;
    let run = run_with_fake_nono(policy);

    assert!(
        run.output.status.success(),
        "runseal failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.output.stdout),
        String::from_utf8_lossy(&run.output.stderr)
    );

    let json = read_profile_json(&run.captured_profile);

    assert_eq!(json["network"]["block"], true);
    assert_eq!(
        json["network"]["custom_credentials"]["cratesio"]["endpoint_rules"][0]["method"],
        "GET"
    );
    assert_eq!(
        json["network"]["custom_credentials"]["cratesio"]["inject_mode"],
        "header"
    );
}

#[test]
fn tmp_read_grant_keeps_credential_file_under_profile_deny() {
    let policy = r#"
fs:
  read: ["/tmp"]
  write: []
network:
  mode: blocked
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    allow:
      - GET /api/v1/crates
"#;
    let run = run_with_fake_nono(policy);

    assert!(
        run.output.status.success(),
        "runseal failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.output.stdout),
        String::from_utf8_lossy(&run.output.stderr)
    );

    let args = fs::read_to_string(&run.captured_args).expect("read captured nono args");
    assert!(
        args.lines()
            .collect::<Vec<_>>()
            .windows(2)
            .any(|pair| pair == ["--read", "/tmp"]),
        "expected broad /tmp read grant in nono args, got:\n{args}"
    );

    let json = read_profile_json(&run.captured_profile);
    let credential_key = json["network"]["custom_credentials"]["cratesio"]["credential_key"]
        .as_str()
        .expect("credential key is present");
    let credential_path = credential_key
        .strip_prefix("file://")
        .expect("credential key uses file://");
    let credential_dir = Path::new(credential_path)
        .parent()
        .expect("credential file has parent");
    let credential_dir = credential_dir.to_string_lossy();

    let denied = json["filesystem"]["deny"]
        .as_array()
        .expect("filesystem.deny is present");
    assert!(
        denied.iter().any(|path| {
            path.as_str()
                .is_some_and(|path| path == credential_dir.as_ref())
        }),
        "credential file must remain unreadable via profile deny; denied={denied:?}, credential={}",
        credential_dir
    );
}

#[test]
fn invalid_inject_mode_fails_before_spawning_nono() {
    let policy = r#"
network:
  mode: blocked
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    inject:
      mode: heder
    allow:
      - GET /api/v1/crates
"#;
    let run = run_with_fake_nono(policy);

    assert!(
        !run.output.status.success(),
        "runseal must reject an invalid inject mode"
    );
    assert!(
        !run.captured_args.exists(),
        "nono must not be spawned when the policy is invalid"
    );
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(
        stderr.contains("not valid runseal policy YAML"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn repo_profile_is_staged_beside_the_generated_profile_and_extended_by_it() {
    let run = run_with_repo_profile(
        r#"{"filesystem":{"read":["./src"]},"network":{"allow_domain":["example.com"]}}"#,
    );

    assert!(
        run.output.status.success(),
        "runseal failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&run.output.stdout),
        String::from_utf8_lossy(&run.output.stderr)
    );

    let generated = read_profile_json(&run.captured_profile);
    assert_eq!(
        generated["extends"],
        serde_json::json!(["default", "runseal-repo"])
    );
    assert!(
        generated["network"].get("block").is_none(),
        "generated profile: {generated}"
    );

    let staged = read_profile_json(&run.captured_sibling);
    assert_eq!(staged["network"]["allow_domain"][0], "example.com");
    assert_eq!(
        staged["filesystem"]["read"][0].as_str(),
        run.workspace.join("src").to_str()
    );
}

#[test]
fn missing_repo_write_target_fails_before_spawning_nono() -> anyhow::Result<()> {
    for field in ["write", "write_file"] {
        let run = run_with_repo_profile(
            &serde_json::json!({"filesystem": {field: ["./missing-output"]}}).to_string(),
        );
        assert!(!run.output.status.success());
        assert!(!run.captured_args.exists(), "nono must not start");
        assert!(!run.workspace.join("missing-output").exists());
        let stderr = String::from_utf8_lossy(&run.output.stderr);
        assert!(
            stderr.contains("create the target before running runseal"),
            "{stderr}"
        );
    }
    Ok(())
}

#[test]
fn repo_profile_without_domains_keeps_the_generated_block() {
    let run = run_with_repo_profile(r#"{"filesystem":{"read":["./src"]}}"#);

    assert!(run.output.status.success(), "runseal failed");
    assert_eq!(
        read_profile_json(&run.captured_profile)["network"]["block"],
        true
    );
}

#[test]
fn profile_mode_disables_nono_registry_lookups() {
    let run = run_with_repo_profile(r#"{"filesystem":{"read":["./src"]}}"#);

    assert_eq!(
        fs::read_to_string(&run.captured_no_migrate).expect("read capture"),
        "1"
    );
}

#[test]
fn a_repo_profile_granting_itself_capabilities_fails_before_spawning_nono() {
    let run = run_with_repo_profile(r#"{"session_hooks":{"before":"/tmp/pwn.sh"}}"#);

    assert!(
        !run.output.status.success(),
        "runseal must reject a profile that runs code outside the sandbox"
    );
    assert!(
        !run.captured_args.exists(),
        "nono must not be spawned when the repo profile is rejected"
    );
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(
        stderr.contains("session_hooks") && stderr.contains("not permitted"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn a_repo_profile_and_a_policy_together_fail_before_spawning_nono() {
    let run = run_runseal(
        &[("runseal.json", r#"{"filesystem":{"read":["./src"]}}"#)],
        &[
            ("RUNSEAL_PROFILE", "runseal.json"),
            ("RUNSEAL_POLICY", "fs:\n  read: [\".\"]\n"),
        ],
    );

    assert!(!run.output.status.success(), "two policy sources must fail");
    assert!(!run.captured_args.exists(), "nono must not be spawned");
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(
        stderr.contains("exactly one policy source"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn a_missing_repo_profile_fails_before_spawning_nono() {
    let run = run_runseal(&[], &[("RUNSEAL_PROFILE", "runseal.json")]);

    assert!(!run.output.status.success(), "a missing profile must fail");
    assert!(!run.captured_args.exists(), "nono must not be spawned");
    let stderr = String::from_utf8_lossy(&run.output.stderr);
    assert!(
        stderr.contains("was not found"),
        "unexpected stderr:\n{stderr}"
    );
}

struct FakeNonoRun {
    output: std::process::Output,
    captured_profile: PathBuf,
    captured_sibling: PathBuf,
    captured_args: PathBuf,
    captured_no_migrate: PathBuf,
    workspace: PathBuf,
    _temp: tempfile::TempDir,
}

fn run_with_fake_nono(policy: &str) -> FakeNonoRun {
    run_runseal(&[], &[("RUNSEAL_POLICY", policy)])
}

fn run_with_repo_profile(profile_json: &str) -> FakeNonoRun {
    run_runseal(
        &[("runseal.json", profile_json)],
        &[("RUNSEAL_PROFILE", "runseal.json")],
    )
}

fn run_runseal(files: &[(&str, &str)], env: &[(&str, &str)]) -> FakeNonoRun {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("create fake bin dir");

    let fake_nono = bin_dir.join("nono");
    fs::write(
        &fake_nono,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$CAPTURED_NONO_ARGS"
printf '%s' "${NONO_NO_MIGRATE:-}" > "$CAPTURED_NO_MIGRATE"
profile=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--profile" ]; then
    shift
    profile="$1"
    break
  fi
  shift
done
cp "$profile" "$CAPTURED_PROFILE"
sibling="$(dirname "$profile")/runseal-repo.json"
if [ -f "$sibling" ]; then
  cp "$sibling" "$CAPTURED_SIBLING"
fi
"#,
    )
    .expect("write fake nono");
    fs::set_permissions(&fake_nono, fs::Permissions::from_mode(0o755))
        .expect("make fake nono executable");

    let old_path = env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![bin_dir];
    paths.extend(env::split_paths(&old_path));
    let path = env::join_paths(paths).expect("join PATH");
    let captured_profile = temp.path().join("profile.json");
    let captured_sibling = temp.path().join("sibling.json");
    let captured_args = temp.path().join("nono-args.txt");
    let captured_no_migrate = temp.path().join("no-migrate.txt");
    let workspace = temp.path().canonicalize().expect("canonical workspace");
    for (name, contents) in files {
        fs::write(workspace.join(name), contents).expect("write workspace file");
    }

    let mut command = Command::new(env!("CARGO_BIN_EXE_runseal"));
    command
        .arg("run")
        .current_dir(&workspace)
        .env("PATH", path)
        .env("RUNSEAL_RUN", "true")
        .env("RUNSEAL_AUDIT", "false")
        .env("CARGO_REGISTRY_TOKEN", "test-token")
        .env("CAPTURED_PROFILE", &captured_profile)
        .env("CAPTURED_SIBLING", &captured_sibling)
        .env("CAPTURED_NONO_ARGS", &captured_args)
        .env("CAPTURED_NO_MIGRATE", &captured_no_migrate)
        .env("GITHUB_WORKSPACE", &workspace);
    for (key, value) in env {
        command.env(key, value);
    }

    FakeNonoRun {
        output: command.output().expect("run runseal"),
        captured_profile,
        captured_sibling,
        captured_args,
        captured_no_migrate,
        workspace,
        _temp: temp,
    }
}

fn read_profile_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).expect("read captured profile"))
        .expect("captured profile is JSON")
}
