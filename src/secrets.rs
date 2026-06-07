use crate::config::RunConfig;
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
    pub inject_mode: String,
    pub credential_file: std::path::PathBuf,
    pub endpoint_rules: Vec<crate::config::EndpointRule>,
}

pub fn seal_credentials(config: &RunConfig) -> Result<SealedCredentials> {
    let dir = tempfile::Builder::new()
        .prefix("runseal-creds.")
        .tempdir()?;
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
        validate_secret_for_inject_mode(&grant.secret, &grant.inject_mode, &secret)?;
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
            inject_mode: grant.inject_mode.clone(),
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

fn read_secret_env(secret_env: &str) -> Result<String> {
    let value = env::var_os(secret_env)
        .with_context(|| format!("access secret env var '{secret_env}' is not set"))?;
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
    inject_mode: &str,
    secret: &str,
) -> Result<()> {
    if inject_mode == "header" && secret.contains(['\r', '\n']) {
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
    use crate::config::{AccessConfig, AuditConfig, NetworkPolicy};
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

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
                inject_mode: "header".to_string(),
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
        env::set_var(name, &value);

        let err = read_secret_env(name).expect_err("non-UTF-8 secret must fail");
        env::remove_var(name);

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
        let err = validate_secret_for_inject_mode("RUNSEAL_TEST_SECRET", "header", "first\nsecond")
            .expect_err("header secrets with newlines must fail");

        assert!(
            err.to_string()
                .contains("cannot be injected as an HTTP header"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn non_header_injection_allows_newline_secrets() {
        validate_secret_for_inject_mode("RUNSEAL_TEST_SECRET", "body", "first\nsecond")
            .expect("non-header multiline secret");
    }
}
