use crate::config::{RunConfig, SupportedInjectMode};
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[derive(Debug)]
pub struct SealedCredentials {
    pub dir: TempDir,
    pub access: Vec<SealedCredential>,
    pub sanitized_env: BTreeMap<String, String>,
}

#[derive(Debug)]
pub struct SealedCredential {
    pub name: String,
    pub secret_env: String,
    pub upstream: String,
    pub tls_ca: Option<String>,
    pub inject_mode: SupportedInjectMode,
    pub credential_file: std::path::PathBuf,
    pub endpoint_rules: Vec<crate::config::EndpointRule>,
}

pub fn seal_credentials(config: &RunConfig) -> Result<SealedCredentials> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("runseal-creds.");
    let dir = match credential_temp_base_dir() {
        Some(base) => builder.tempdir_in(&base).with_context(|| {
            format!(
                "failed to create credential temp dir under '{}'",
                base.display()
            )
        })?,
        None => builder.tempdir()?,
    };
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;

    let secret_names: HashSet<&str> = config.access.iter().map(|c| c.secret.as_str()).collect();
    let sanitized_env: BTreeMap<String, String> = env::vars_os()
        .filter_map(|(key, value)| {
            let key = key.into_string().ok()?;
            let value = value.into_string().ok()?;
            Some((key, value))
        })
        .filter(|(key, _)| !secret_names.contains(key.as_str()))
        .filter(|(key, _)| !key.starts_with("RUNSEAL_"))
        .filter(|(key, _)| !key.starts_with("NONO_ACTION_"))
        .collect();

    let mut sealed = Vec::new();
    for grant in &config.access {
        validate_access_grant_name(&grant.name)?;

        let secret = read_secret_env(&grant.secret)?;
        if secret.is_empty() {
            bail!("access secret env var '{}' is empty", grant.secret);
        }
        validate_secret_for_inject_mode(&grant.secret, grant.inject_mode, &secret)?;
        emit_secret_masks(&secret);

        let name = grant.name.clone();
        let path = dir.path().join(&name);
        fs::write(&path, secret.as_bytes())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        sealed.push(SealedCredential {
            name,
            secret_env: grant.secret.clone(),
            upstream: grant.upstream.clone(),
            tls_ca: grant.tls_ca.clone(),
            inject_mode: grant.inject_mode,
            credential_file: path,
            endpoint_rules: grant.endpoint_rules.clone(),
        });
    }

    Ok(SealedCredentials {
        dir,
        access: sealed,
        sanitized_env,
    })
}

// The credential dir is protected by a `filesystem.deny` rule in the
// generated profile, and Landlock cannot carve a deny out of an already
// allowed ancestor -- nono refuses to start on such a conflict. So the dir has
// to sit outside everything nono's `default` profile allows, which rules out
// the OS temp dir: `system_write_linux`/`system_write_macos` allow `/tmp` and
// `$TMPDIR`, and `system_read_macos` additionally allows `/var` and `/private`
// (covering the macOS `/var/folders` temp root).
//
// Preference order:
//   1. `RUNNER_TEMP` -- GitHub Actions' per-job temp dir, wiped with the job.
//   2. `$XDG_STATE_HOME/runseal` (default `~/.local/state/runseal`) -- the
//      same convention nono uses for its own session secret material. No
//      built-in group covers `~/.local/state` (`user_tools` grants only
//      `~/.local/bin` and a few `~/.local/share` subdirs).
//
// Returning `None` leaves the caller on the OS temp dir. That keeps runseal
// working for policies with no access grant (which emit no deny rule at all),
// and for a grant nono reports the conflict explicitly rather than degrading.
fn credential_temp_base_dir() -> Option<std::path::PathBuf> {
    if let Some(runner_temp) = absolute_env_path("RUNNER_TEMP") {
        return Some(runner_temp);
    }

    let state_home = absolute_env_path("XDG_STATE_HOME")
        .or_else(|| absolute_env_path("HOME").map(|home| home.join(".local/state")))?;
    let base = state_home.join("runseal");

    // Owner-only, and created before `tempdir_in` needs it. The per-run
    // subdir `seal_credentials` puts inside it is 0700 in its own right.
    fs::create_dir_all(&base).ok()?;
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).ok()?;
    Some(base)
}

// Env-var-supplied paths are untrusted: a relative or empty value would
// resolve against the process cwd, which is exactly the tree the caller's
// `fs.read` policy tends to allow.
fn absolute_env_path(key: &str) -> Option<std::path::PathBuf> {
    let value = env::var_os(key)?;
    if value.is_empty() {
        return None;
    }
    let path = std::path::PathBuf::from(value);
    if path.is_absolute() {
        Some(path)
    } else {
        None
    }
}

fn read_secret_env(secret_env: &str) -> Result<String> {
    let value = env::var_os(secret_env)
        .with_context(|| format!("access secret env var '{secret_env}' is not set"))?;
    decode_secret_env_value(secret_env, value)
}

fn decode_secret_env_value(secret_env: &str, value: std::ffi::OsString) -> Result<String> {
    match value.into_string() {
        Ok(value) => Ok(value),
        Err(_) => bail!("access secret env var '{secret_env}' is not valid UTF-8"),
    }
}

fn validate_access_grant_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains('/')
        || name.contains("..")
        || name.contains('\0')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!(
            "access grant name '{name}' is invalid; use only [a-zA-Z0-9_-] and no path separators"
        );
    }
    Ok(())
}

fn validate_secret_for_inject_mode(
    secret_env: &str,
    inject_mode: SupportedInjectMode,
    secret: &str,
) -> Result<()> {
    let secret_lands_in_header_verbatim = match inject_mode {
        SupportedInjectMode::Header => true,
        // nono base64-encodes basic_auth secrets, so a newline never reaches
        // the header.
        SupportedInjectMode::BasicAuth => false,
    };
    if secret_lands_in_header_verbatim && secret.contains(['\r', '\n']) {
        bail!(
            "access secret env var '{secret_env}' contains a newline, which cannot be injected as an HTTP header"
        );
    }
    Ok(())
}

fn emit_secret_masks(secret: &str) {
    for line in secret_mask_lines(secret) {
        println!("::add-mask::{line}");
    }
}

fn secret_mask_lines(secret: &str) -> impl Iterator<Item = &str> {
    secret.split(['\r', '\n']).filter(|line| !line.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccessConfig, AuditConfig, NetworkPolicy, SupportedInjectMode};
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn credential_temp_base_dir_prefers_runner_temp_when_set() {
        // Point RUNNER_TEMP at a directory that really exists: tests holding
        // no `EnvVarGuard` still read this var through `seal_credentials`, and
        // a bogus path would make their temp dir creation fail instead.
        let runner_temp = tempfile::tempdir().expect("tempdir");
        let _guard = crate::test_env::EnvVarGuard::set("RUNNER_TEMP", runner_temp.path());

        let base = credential_temp_base_dir();

        assert_eq!(base, Some(runner_temp.path().to_path_buf()));
    }

    #[test]
    fn credential_temp_base_dir_rejects_relative_runner_temp() {
        // A relative RUNNER_TEMP would resolve against the cwd, which is the
        // tree `fs.read` policies typically allow.
        let _guard = crate::test_env::EnvVarGuard::set("RUNNER_TEMP", "relative/temp");

        assert_eq!(absolute_env_path("RUNNER_TEMP"), None);
    }

    #[test]
    fn credential_temp_base_dir_falls_back_to_xdg_state_home() {
        let state_home = tempfile::tempdir().expect("tempdir");
        // Nested so the mode assertion below observes a dir runseal created.
        let xdg = state_home.path().join("state");
        let _guard =
            crate::test_env::EnvVarGuard::remove("RUNNER_TEMP").with_set("XDG_STATE_HOME", &xdg);

        let base = credential_temp_base_dir().expect("XDG_STATE_HOME fallback");

        assert_eq!(base, xdg.join("runseal"));
        assert!(base.is_dir(), "fallback base must be created");
        let mode = fs::metadata(&base).expect("metadata").permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "fallback base must be owner-only");
    }

    #[test]
    fn credential_temp_base_dir_is_none_without_runner_temp_or_home() {
        let _guard = crate::test_env::EnvVarGuard::remove("RUNNER_TEMP")
            .with_remove("XDG_STATE_HOME")
            .with_remove("HOME");

        assert_eq!(credential_temp_base_dir(), None);
    }

    #[test]
    fn credential_dir_avoids_os_temp_root_when_runseal_picks_the_base() {
        // Regression test for the nono >= 0.74 deny-overlap check. The OS temp
        // root is exactly what `system_write_linux`/`system_write_macos` allow
        // as `/tmp` and `$TMPDIR`, so a credential dir sitting directly in it
        // makes the generated deny rule unenforceable and nono refuse to
        // start. Whether a caller-supplied RUNNER_TEMP escapes the allowed set
        // is the caller's business; this pins the base runseal picks itself.
        let state_home = tempfile::tempdir().expect("tempdir");
        let _guard = crate::test_env::EnvVarGuard::remove("RUNNER_TEMP")
            .with_set("XDG_STATE_HOME", state_home.path());

        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: AuditConfig::Disabled,
        };
        let sealed = seal_credentials(&config).expect("seal_credentials");

        let parent = sealed.dir.path().parent().expect("credential dir parent");
        assert_ne!(
            parent,
            env::temp_dir(),
            "credential dir must not sit in the OS temp root"
        );
        assert_eq!(parent, state_home.path().join("runseal"));
    }

    #[test]
    fn seal_credentials_places_tempdir_under_runner_temp_when_set() {
        let runner_temp = tempfile::tempdir().expect("tempdir");
        let _guard = crate::test_env::EnvVarGuard::set("RUNNER_TEMP", runner_temp.path());

        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: AuditConfig::Disabled,
        };
        let sealed = seal_credentials(&config).expect("seal_credentials");

        assert!(
            sealed.dir.path().starts_with(runner_temp.path()),
            "expected credential dir '{}' under RUNNER_TEMP '{}'",
            sealed.dir.path().display(),
            runner_temp.path().display()
        );
    }

    #[test]
    fn validates_safe_access_grant_names() {
        for name in ["npm", "crates_io", "deploy-123", "A_B-C9"] {
            validate_access_grant_name(name).expect("valid access grant name");
        }
    }

    #[test]
    fn rejects_access_grant_names_that_can_escape_or_break_profile_keys() {
        for name in [
            "",
            "../profile",
            "profile/secret",
            "profile\\secret",
            "profile.secret",
            "profile secret",
            "profile\0secret",
            "ümlaut",
        ] {
            assert!(
                validate_access_grant_name(name).is_err(),
                "expected {name:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_invalid_access_grant_name_before_secret_lookup() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: vec![AccessConfig {
                name: "../profile.json".to_string(),
                secret: "RUNSEAL_TEST_SECRET_THAT_IS_NOT_SET".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: SupportedInjectMode::Header,
                endpoint_rules: Vec::new(),
            }],
            audit: AuditConfig::Disabled,
        };

        let err = seal_credentials(&config).expect_err("invalid grant name must fail");
        assert!(
            err.to_string().contains("access grant name"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn non_utf8_secret_error_does_not_include_raw_value() {
        let name = "RUNSEAL_TEST_NON_UTF8_SECRET";
        let value = OsString::from_vec(b"TOPSECRET-\xFF\xFE-RAWKEY".to_vec());

        let err = decode_secret_env_value(name, value).expect_err("non-UTF-8 secret must fail");

        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("not valid UTF-8"),
            "unexpected error: {rendered}"
        );
        assert!(
            !rendered.contains("TOPSECRET"),
            "error leaked secret prefix: {rendered}"
        );
        assert!(
            !rendered.contains("RAWKEY"),
            "error leaked secret suffix: {rendered}"
        );
    }

    #[test]
    fn masks_each_non_empty_line_of_multiline_secret() {
        let lines: Vec<_> = secret_mask_lines("first\n\nsecond\r\nthird\r").collect();

        assert_eq!(lines, vec!["first", "second", "third"]);
    }

    #[test]
    fn header_injection_rejects_newline_secrets() {
        let err = validate_secret_for_inject_mode(
            "RUNSEAL_TEST_SECRET",
            SupportedInjectMode::Header,
            "first\nsecond",
        )
        .expect_err("header secrets with newlines must fail");

        assert!(
            err.to_string()
                .contains("cannot be injected as an HTTP header"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn basic_auth_injection_allows_newline_secrets() {
        validate_secret_for_inject_mode(
            "RUNSEAL_TEST_SECRET",
            SupportedInjectMode::BasicAuth,
            "first\nsecond",
        )
        .expect("basic_auth multiline secret");
    }
}
