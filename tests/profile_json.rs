use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn blocked_network_with_credentials_emits_block_true_profile_json() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("create fake bin dir");

    let fake_nono = bin_dir.join("nono");
    fs::write(
        &fake_nono,
        r#"#!/bin/sh
set -eu
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

    let output = Command::new(env!("CARGO_BIN_EXE_runseal"))
        .arg("run")
        .current_dir(temp.path())
        .env("PATH", path)
        .env("RUNSEAL_RUN", "true")
        .env("RUNSEAL_POLICY", policy)
        .env("RUNSEAL_AUDIT", "false")
        .env("CARGO_REGISTRY_TOKEN", "test-token")
        .env("CAPTURED_PROFILE", &captured_profile)
        .output()
        .expect("run runseal");

    assert!(
        output.status.success(),
        "runseal failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value =
        serde_json::from_slice(&fs::read(captured_profile).expect("read captured profile"))
            .expect("captured profile is JSON");

    assert_eq!(json["network"]["block"], true);
}
