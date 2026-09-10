use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[test]
fn installed_binary_advertises_profile_support() -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_runseal"))
        .arg("capabilities")
        .output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"repo-profile-v1\n");
    Ok(())
}

#[test]
fn launcher_checks_profile_support_before_running() -> anyhow::Result<()> {
    for (capabilities, query_status, profile, should_run) in [
        ("repo-profile-v1", 0, "runseal.json", true),
        ("unknown command", 1, "runseal.json", false),
        ("", 0, "runseal.json", false),
        ("repo-profile-v10", 0, "runseal.json", false),
        ("repo-profile-v1", 1, "runseal.json", false),
        ("unknown command", 1, "", true),
        ("unknown command", 1, " \t\n", true),
    ] {
        let dir = tempfile::tempdir()?;
        let binary = dir.path().join("runseal");
        let marker = dir.path().join("ran");
        fs::write(
            &binary,
            "#!/bin/sh\ncase \"$1\" in\ncapabilities) printf '%s\\n' \"$TEST_CAPABILITIES\"; exit \"$TEST_QUERY_STATUS\";;\nrun) touch \"$TEST_MARKER\";;\n*) exit 2;;\nesac\n",
        )?;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700))?;
        // Modify only the child's environment; parallel tests retain theirs.
        let path = std::env::join_paths(
            std::iter::once(dir.path().to_path_buf())
                .chain(["/usr/bin", "/bin"].map(std::path::PathBuf::from)),
        )?;
        let output = Command::new("bash")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/run-sealed.sh"
            ))
            .env("PATH", path)
            .env("RUNSEAL_PROFILE", profile)
            .env("TEST_CAPABILITIES", capabilities)
            .env("TEST_QUERY_STATUS", query_status.to_string())
            .env("TEST_MARKER", &marker)
            .output()?;
        assert_eq!(output.status.success(), should_run, "{output:?}");
        assert_eq!(marker.exists(), should_run, "{output:?}");
    }
    Ok(())
}
