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
    let sanitized_env: BTreeMap<String, String> = env::vars()
        .filter(|(key, _)| !secret_names.contains(key.as_str()))
        .filter(|(key, _)| !key.starts_with("RUNSEAL_"))
        .filter(|(key, _)| !key.starts_with("NONO_ACTION_"))
        .collect();

    let mut sealed = Vec::new();
    for grant in &config.access {
        validate_access_grant_name(&grant.name)?;

        let secret = env::var(&grant.secret)
            .with_context(|| format!("access secret env var '{}' is not set", grant.secret))?;
        if secret.is_empty() {
            bail!("access secret env var '{}' is empty", grant.secret);
        }
        println!("::add-mask::{secret}");

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AccessConfig, AuditConfig, NetworkPolicy};

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
}
