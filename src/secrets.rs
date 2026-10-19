//! Credential sealing for sandboxed runs.

use crate::config::{RunConfig, SupportedInjectMode};
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;
use zeroize::Zeroizing;

const MASK_PREFIX: &str = "::add-mask::";

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
    let dir = credential_directory(!config.access.is_empty())?;

    let secret_names: HashSet<&str> = config.access.iter().map(|c| c.secret.as_str()).collect();
    let sanitized_env = sanitize_env(&secret_names);

    let mut sealed = Vec::new();
    for grant in &config.access {
        validate_access_grant_name(&grant.name)?;

        let secret = read_secret_env(&grant.secret)?;
        if secret.is_empty() {
            bail!("access secret env var '{}' is empty", grant.secret);
        }
        validate_secret_for_inject_mode(&grant.secret, grant.inject_mode, &secret)?;
        emit_secret_masks(&secret)?;

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

/// Keep Linux credentials outside nono's inherited `/tmp` and `$TMPDIR` grants.
/// Landlock cannot subtract a private child directory from a broader grant.
/// nono correctly refuses such overlapping policies. Retain the explicit deny
/// as well, so a user grant overlapping this directory still fails closed.
#[must_use = "credential storage failures must abort the run"]
fn credential_directory(has_access: bool) -> Result<TempDir> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("runseal-creds.");
    let dir = if cfg!(target_os = "linux") && has_access {
        // Deliberately ignore TMPDIR for secret storage. Do not fall back to
        // the shared /tmp grant if this separate location is unavailable.
        let base = fs::canonicalize("/var/tmp")
            .context("failed to canonicalize Linux credential storage /var/tmp")?;
        builder
            .tempdir_in(base)
            .context("failed to create private Linux credential storage in /var/tmp")?
    } else {
        builder
            .tempdir()
            .context("failed to create runseal staging directory")?
    };
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

/// Sanitize the environment, discarding secrets and internal inputs.
fn sanitize_env(secret_names: &HashSet<&str>) -> BTreeMap<String, String> {
    let mut sanitized = BTreeMap::new();
    for (key, value) in env::vars_os() {
        let Ok(key) = key.into_string() else {
            discard_secret_bytes(value);
            continue;
        };
        if !is_forwarded_env_key(&key, secret_names) {
            discard_secret_bytes(value);
            continue;
        }
        match value.into_string() {
            Ok(value) => {
                sanitized.insert(key, value);
            }
            Err(value) => discard_secret_bytes(value),
        }
    }
    sanitized
}

/// Whether an environment variable may be forwarded into the sandbox.
///
/// Secrets are withheld because the credential proxy injects them instead, and
/// runseal's own inputs are withheld because the sandboxed command has no
/// business reading the policy it is confined by.
fn is_forwarded_env_key(key: &str, secret_names: &HashSet<&str>) -> bool {
    !secret_names.contains(key) && !key.starts_with("RUNSEAL_") && !key.starts_with("NONO_ACTION_")
}

/// Zeroize the provided OsString.
fn discard_secret_bytes(value: OsString) {
    drop(Zeroizing::new(value.into_vec()));
}

fn read_secret_env(secret_env: &str) -> Result<Zeroizing<String>> {
    let value = env::var_os(secret_env)
        .with_context(|| format!("access secret env var '{secret_env}' is not set"))?;
    decode_secret_env_value(secret_env, value)
}

/// Read and decode a secret environment variable.
fn decode_secret_env_value(secret_env: &str, value: OsString) -> Result<Zeroizing<String>> {
    match value.into_string() {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(value) => {
            discard_secret_bytes(value);
            bail!("access secret env var '{secret_env}' is not valid UTF-8")
        }
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

fn emit_secret_masks(secret: &str) -> Result<()> {
    let mut stdout = io::stdout().lock();
    for line in secret_mask_lines(secret) {
        let masked = mask_line(line);
        stdout
            .write_all(masked.as_bytes())
            .context("failed to write secret mask")?;
    }
    // Masks must reach the log before the secret can appear anywhere else.
    stdout.flush().context("failed to flush secret masks")?;
    Ok(())
}

/// Render a newline-terminated mask command.
fn mask_line(line: &str) -> Zeroizing<String> {
    let mut masked = Zeroizing::new(String::with_capacity(
        MASK_PREFIX
            .len()
            .saturating_add(line.len())
            .saturating_add(1),
    ));
    masked.push_str(MASK_PREFIX);
    masked.push_str(line);
    masked.push('\n');
    masked
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
    fn credential_storage_is_private_and_outside_linux_shared_tmp() -> Result<()> {
        let dir = credential_directory(true)?;
        assert_eq!(
            fs::metadata(dir.path())?.permissions().mode() & 0o777,
            0o700
        );
        if cfg!(target_os = "linux") {
            assert_eq!(
                dir.path().parent(),
                Some(fs::canonicalize("/var/tmp")?.as_path())
            );
            assert!(!dir.path().starts_with(fs::canonicalize("/tmp")?));
        }
        let path = dir.path().to_path_buf();
        drop(dir);
        assert!(!path.exists(), "credentials must be removed after use");
        Ok(())
    }

    /// Run on Linux with the manifest-pinned nono installed
    #[test]
    #[ignore = "requires Linux Landlock and the manifest-pinned nono on PATH"]
    fn linux_sealed_credentials_with_real_nono() -> Result<()> {
        use crate::config::{AccessConfig, EndpointRule};
        use std::io::Read;
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::time::{Duration, Instant};

        if !cfg!(target_os = "linux") {
            bail!("this regression requires Linux Landlock");
        }
        let version = std::process::Command::new("nono")
            .arg("--version")
            .output()?;
        assert!(
            version.status.success(),
            "nono --version failed: {version:?}"
        );
        let pinned = include_str!("../.github/nono-version/Cargo.toml");
        let pinned = pinned
            .lines()
            .find_map(|line| line.trim().strip_prefix("nono-cli = "))
            .context("missing pinned nono version")?
            .trim_matches('"')
            .trim_start_matches('=');
        assert_eq!(
            String::from_utf8(version.stdout)?.trim(),
            format!("nono {pinned}")
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let upstream = format!("http://{}", listener.local_addr()?);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let server = std::thread::spawn(move || -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(30);
            while !server_stop.load(std::sync::atomic::Ordering::Relaxed)
                && Instant::now() < deadline
            {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                        let mut request = Vec::new();
                        let mut byte = [0];
                        while !request.ends_with(b"\r\n\r\n") {
                            if stream.read(&mut byte)? == 0 || request.len() >= 16 * 1024 {
                                bail!("incomplete upstream request");
                            }
                            request.push(byte[0]);
                        }
                        captured
                            .lock()
                            .map_err(|_| anyhow::anyhow!("request lock poisoned"))?
                            .push(String::from_utf8(request)?);
                        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(())
        });

        // Construct a sealed fixture without modifying this process's environment.
        // Expose its location deliberately: hiding the random name is not the boundary.
        let dir = credential_directory(true)?;
        let credential_file = dir.path().join("api");
        let secret = "runseal-regression-canary";
        fs::write(&credential_file, secret)?;
        fs::set_permissions(&credential_file, fs::Permissions::from_mode(0o600))?;
        // An empty config root prevents reading a developer's platform enrollment
        // and shipping this local canary audit to a configured cloud service.
        let config_root = tempfile::tempdir()?;
        let mut sanitized_env: BTreeMap<String, String> = env::vars().collect();
        sanitized_env.insert(
            "XDG_CONFIG_HOME".to_string(),
            config_root.path().display().to_string(),
        );
        sanitized_env.remove("API_TOKEN");
        sanitized_env.insert(
            "SEALED_FILE".to_string(),
            credential_file.display().to_string(),
        );
        // Exercise the inherited /tmp grant which caused the original failure.
        sanitized_env.insert("TMPDIR".to_string(), "/tmp".to_string());
        let rules = vec![EndpointRule {
            method: "GET".parse()?,
            path: "/allowed".to_string(),
        }];
        let sealed = SealedCredentials {
            dir,
            access: vec![SealedCredential {
                name: "api".to_string(),
                secret_env: "API_TOKEN".to_string(),
                upstream: upstream.clone(),
                tls_ca: None,
                inject_mode: SupportedInjectMode::Header,
                credential_file,
                endpoint_rules: rules.clone(),
            }],
            sanitized_env,
        };
        let config = RunConfig {
            command: r#"set -eu
if cat "$SEALED_FILE" >/dev/null 2>&1; then
    echo 'sandbox read a sealed credential' >&2
    exit 1
fi
test -n "$API_TOKEN"
test "$API_TOKEN" != runseal-regression-canary
curl --max-time 10 -fsS -H "Authorization: Bearer $API_TOKEN" "$API_BASE_URL/allowed"
if curl --max-time 10 -fsS -H "Authorization: Bearer $API_TOKEN" "$API_BASE_URL/denied"; then
    echo 'denied route unexpectedly succeeded' >&2
    exit 1
fi
"#
            .to_string(),
            fs_read: vec!["/tmp".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::AllowDomains(Vec::new()),
            access: vec![AccessConfig {
                name: "api".to_string(),
                secret: "API_TOKEN".to_string(),
                upstream,
                tls_ca: None,
                inject_mode: SupportedInjectMode::Header,
                endpoint_rules: rules,
            }],
            audit: AuditConfig::Disabled,
            repo_profile: None,
        };
        let profile_path = sealed.dir.path().join("profile.json");
        crate::profile::write_profile(
            &profile_path,
            &crate::profile::build_profile(&config, &sealed)?,
        )?;
        let result = crate::runner::run_nono(&config, &sealed, &profile_path);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        server
            .join()
            .map_err(|_| anyhow::anyhow!("upstream thread panicked"))??;
        result?;
        let requests = requests
            .lock()
            .map_err(|_| anyhow::anyhow!("request lock poisoned"))?;
        assert_eq!(
            requests.len(),
            1,
            "denied requests must not reach upstream: {requests:?}"
        );
        assert!(requests[0].starts_with("GET /allowed HTTP/1.1\r\n"));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains(&format!("authorization: bearer {secret}\r\n")));
        Ok(())
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
            repo_profile: None,
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
    fn utf8_secret_decodes_into_scrubbing_string() {
        let value = OsString::from("s3cret-value");

        let secret = decode_secret_env_value("RUNSEAL_TEST_SECRET", value).expect("utf-8 secret");

        assert_eq!(&*secret, "s3cret-value");
    }

    #[test]
    fn forwards_ordinary_env_keys_to_the_sandbox() {
        let secret_names = HashSet::from(["CARGO_REGISTRY_TOKEN"]);

        for key in ["PATH", "HOME", "GITHUB_WORKSPACE", "RUNSEALED", "NONO_HOME"] {
            assert!(
                is_forwarded_env_key(key, &secret_names),
                "expected {key} to be forwarded"
            );
        }
    }

    #[test]
    fn withholds_secret_and_runseal_env_keys_from_the_sandbox() {
        let secret_names = HashSet::from(["CARGO_REGISTRY_TOKEN"]);

        for key in [
            "CARGO_REGISTRY_TOKEN",
            "RUNSEAL_ACCESS",
            "RUNSEAL_",
            "NONO_ACTION_PROFILE",
        ] {
            assert!(
                !is_forwarded_env_key(key, &secret_names),
                "expected {key} to be withheld"
            );
        }
    }

    #[test]
    fn mask_line_is_newline_terminated_and_exactly_sized() {
        let masked = mask_line("s3cret-value");

        assert_eq!(&*masked, "::add-mask::s3cret-value\n");
        // An exact capacity means no reallocation left a copy of the secret
        // behind in a buffer nothing scrubs.
        assert_eq!(masked.capacity(), masked.len());
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
