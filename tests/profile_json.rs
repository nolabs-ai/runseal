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

struct FakeNonoRun {
    output: std::process::Output,
    captured_profile: PathBuf,
    captured_args: PathBuf,
    _temp: tempfile::TempDir,
}

fn run_with_fake_nono(policy: &str) -> FakeNonoRun {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("create fake bin dir");

    let fake_nono = bin_dir.join("nono");
    fs::write(
        &fake_nono,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$CAPTURED_NONO_ARGS"
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
    let captured_args = temp.path().join("nono-args.txt");

    let output = Command::new(env!("CARGO_BIN_EXE_runseal"))
        .arg("run")
        .current_dir(temp.path())
        .env("PATH", path)
        .env("RUNSEAL_RUN", "true")
        .env("RUNSEAL_POLICY", policy)
        .env("RUNSEAL_AUDIT", "false")
        .env("CARGO_REGISTRY_TOKEN", "test-token")
        .env("CAPTURED_PROFILE", &captured_profile)
        .env("CAPTURED_NONO_ARGS", &captured_args)
        .output()
        .expect("run runseal");

    FakeNonoRun {
        output,
        captured_profile,
        captured_args,
        _temp: temp,
    }
}

fn read_profile_json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).expect("read captured profile"))
        .expect("captured profile is JSON")
}
