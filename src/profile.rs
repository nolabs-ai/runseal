use crate::config::{NetworkPolicy, RunConfig, SupportedInjectMode};
use crate::secrets::SealedCredentials;
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct NonoProfile {
    extends: Vec<String>,
    meta: Meta,
    groups: Groups,
    #[serde(skip_serializing_if = "Filesystem::is_empty")]
    filesystem: Filesystem,
    network: Network,
}

#[derive(Debug, Serialize)]
struct Meta {
    name: &'static str,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct Groups {
    exclude: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct Filesystem {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny: Vec<String>,
}

impl Filesystem {
    fn is_empty(&self) -> bool {
        self.deny.is_empty()
    }
}

#[derive(Debug, Serialize)]
struct Network {
    #[serde(skip_serializing_if = "Option::is_none")]
    block: Option<bool>,
    #[serde(rename = "allow_domain", skip_serializing_if = "Vec::is_empty")]
    allow_domain: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    credentials: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    custom_credentials: BTreeMap<String, CustomCredential>,
}

#[derive(Debug, Serialize)]
struct CustomCredential {
    upstream: String,
    credential_key: String,
    inject_mode: SupportedInjectMode,
    inject_header: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_format: Option<&'static str>,
    env_var: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_ca: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoint_rules: Vec<crate::config::EndpointRule>,
}

pub fn build_profile(config: &RunConfig, sealed: &SealedCredentials) -> Result<NonoProfile> {
    let mut allow_domains: BTreeSet<String> = match &config.network {
        NetworkPolicy::Blocked | NetworkPolicy::FromRepoProfile => Vec::new(),
        NetworkPolicy::AllowDomains(domains) => domains.clone(),
    }
    .into_iter()
    .collect();
    let mut credentials = Vec::new();
    let mut custom_credentials = BTreeMap::new();

    for credential in &sealed.access {
        if let Some(host) = upstream_host(&credential.upstream) {
            allow_domains.insert(host.to_string());
        }
        credentials.push(credential.name.clone());

        let credential_format = match credential.inject_mode {
            SupportedInjectMode::Header => Some("Bearer {}"),
            SupportedInjectMode::BasicAuth => None,
        };
        custom_credentials.insert(
            credential.name.clone(),
            CustomCredential {
                upstream: credential.upstream.clone(),
                credential_key: format!("file://{}", credential.credential_file.display()),
                inject_mode: credential.inject_mode,
                inject_header: "Authorization",
                credential_format,
                env_var: credential.secret_env.clone(),
                tls_ca: credential.tls_ca.clone(),
                endpoint_rules: credential.endpoint_rules.clone(),
            },
        );
    }

    Ok(NonoProfile {
        extends: extends(config),
        meta: Meta {
            name: "runseal-generated",
            version: env!("CARGO_PKG_VERSION"),
        },
        groups: Groups {
            exclude: excluded_groups(),
        },
        filesystem: Filesystem {
            deny: credential_deny_paths(sealed)?,
        },
        network: Network {
            block: match config.network {
                NetworkPolicy::Blocked => Some(true),
                NetworkPolicy::AllowDomains(_) | NetworkPolicy::FromRepoProfile => None,
            },
            allow_domain: allow_domains.into_iter().collect(),
            credentials,
            custom_credentials,
        },
    })
}

/// Merge default, then the repo sibling, beneath the generated profile.
fn extends(config: &RunConfig) -> Vec<String> {
    let mut extends = vec!["default".to_string()];
    if config.repo_profile.is_some() {
        extends.push(crate::repo_profile::BASE_NAME.to_string());
    }
    extends
}

fn credential_deny_paths(sealed: &SealedCredentials) -> Result<Vec<String>> {
    if sealed.access.is_empty() {
        return Ok(Vec::new());
    }

    let mut paths = BTreeSet::new();
    paths.insert(sealed.dir.path().display().to_string());

    let canonical = sealed
        .dir
        .path()
        .canonicalize()
        .with_context(|| format!("failed to canonicalize '{}'", sealed.dir.path().display()))?;
    paths.insert(canonical.display().to_string());

    Ok(paths.into_iter().collect())
}

fn upstream_host(url: &str) -> Option<&str> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = without_scheme.split('/').next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| host.split(':').next().unwrap_or_default());
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(target_os = "linux")]
fn excluded_groups() -> Vec<&'static str> {
    vec!["system_write_macos"]
}

#[cfg(target_os = "macos")]
fn excluded_groups() -> Vec<&'static str> {
    vec!["system_write_linux"]
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn excluded_groups() -> Vec<&'static str> {
    vec!["system_write_linux", "system_write_macos"]
}

pub fn write_profile(path: &Path, profile: &NonoProfile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(profile)?;
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkPolicy, RunConfig, SupportedInjectMode};
    use crate::secrets::{SealedCredential, SealedCredentials};
    use std::collections::BTreeMap;

    #[test]
    fn generated_profile_excludes_only_other_platform_system_write_groups() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
            repo_profile: None,
        };
        let sealed = SealedCredentials {
            dir: tempfile::tempdir().expect("tempdir"),
            access: Vec::new(),
            sanitized_env: BTreeMap::new(),
        };

        let profile = build_profile(&config, &sealed).expect("profile");
        let json = serde_json::to_string(&profile).expect("json");

        if cfg!(target_os = "linux") {
            assert!(!json.contains("system_write_linux"));
            assert!(json.contains("system_write_macos"));
        } else if cfg!(target_os = "macos") {
            assert!(json.contains("system_write_linux"));
            assert!(!json.contains("system_write_macos"));
        } else {
            assert!(json.contains("system_write_linux"));
            assert!(json.contains("system_write_macos"));
        }
    }

    #[test]
    fn generated_profile_exposes_phantom_on_original_secret_env_var() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
            repo_profile: None,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = SealedCredentials {
            access: vec![SealedCredential {
                name: "cratesio".to_string(),
                secret_env: "CARGO_REGISTRY_TOKEN".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: SupportedInjectMode::Header,
                credential_file: dir.path().join("cratesio"),
                endpoint_rules: Vec::new(),
            }],
            dir,
            sanitized_env: BTreeMap::new(),
        };

        let profile = build_profile(&config, &sealed).expect("profile");
        let json = serde_json::to_string(&profile).expect("json");

        assert!(json.contains(r#""env_var":"CARGO_REGISTRY_TOKEN""#));
        assert!(!json.contains("RUNSEAL_ACCESS_CRATESIO_TOKEN"));
    }

    #[test]
    fn generated_profile_blocks_network_when_credentials_are_configured() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
            repo_profile: None,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = SealedCredentials {
            access: vec![SealedCredential {
                name: "cratesio".to_string(),
                secret_env: "CARGO_REGISTRY_TOKEN".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: SupportedInjectMode::Header,
                credential_file: dir.path().join("cratesio"),
                endpoint_rules: Vec::new(),
            }],
            dir,
            sanitized_env: BTreeMap::new(),
        };

        let profile = build_profile(&config, &sealed).expect("profile");
        let json: serde_json::Value =
            serde_json::to_value(&profile).expect("profile serializes as JSON");

        assert_eq!(json["network"]["block"], true);
    }

    #[test]
    fn generated_profile_denies_credential_tempdir() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
            repo_profile: None,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let credential_file = dir.path().join("cratesio");
        let sealed = SealedCredentials {
            access: vec![SealedCredential {
                name: "cratesio".to_string(),
                secret_env: "CARGO_REGISTRY_TOKEN".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: SupportedInjectMode::Header,
                credential_file,
                endpoint_rules: Vec::new(),
            }],
            dir,
            sanitized_env: BTreeMap::new(),
        };

        let profile = build_profile(&config, &sealed).expect("profile");
        let json: serde_json::Value =
            serde_json::to_value(&profile).expect("profile serializes as JSON");
        let denied = json["filesystem"]["deny"]
            .as_array()
            .expect("filesystem.deny is present");

        assert!(denied.iter().any(|path| {
            path.as_str()
                .is_some_and(|path| path == sealed.dir.path().to_string_lossy())
        }));
    }

    #[test]
    fn generated_profile_allows_access_upstream_hosts() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::AllowDomains(vec!["index.crates.io".to_string()]),
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
            repo_profile: None,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = SealedCredentials {
            access: vec![SealedCredential {
                name: "cratesio".to_string(),
                secret_env: "CARGO_REGISTRY_TOKEN".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: SupportedInjectMode::Header,
                credential_file: dir.path().join("cratesio"),
                endpoint_rules: Vec::new(),
            }],
            dir,
            sanitized_env: BTreeMap::new(),
        };

        let profile = build_profile(&config, &sealed).expect("profile");
        let json = serde_json::to_string(&profile).expect("json");

        assert!(json.contains(r#""allow_domain":["crates.io","index.crates.io"]"#));
    }

    fn repo_profile(json: &str) -> (tempfile::TempDir, crate::repo_profile::RepoProfile) {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("runseal.json"), json).expect("write profile");
        let profile =
            crate::repo_profile::load("runseal.json", dir.path()).expect("repo profile loads");
        (dir, profile)
    }

    fn profile_mode_config(
        network: NetworkPolicy,
        repo_profile: crate::repo_profile::RepoProfile,
    ) -> RunConfig {
        RunConfig {
            command: "true".to_string(),
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            network,
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
            repo_profile: Some(repo_profile),
        }
    }

    fn empty_sealed() -> SealedCredentials {
        SealedCredentials {
            dir: tempfile::tempdir().expect("tempdir"),
            access: Vec::new(),
            sanitized_env: BTreeMap::new(),
        }
    }

    /// CI installs the manifest-pinned nono before explicitly running this test.
    #[test]
    #[ignore = "requires an installed nono; run in the profile integration CI job"]
    fn staged_profiles_validate_with_real_nono() -> Result<()> {
        for input in [
            r#"{"meta":{"description":"Build sandbox"},"filesystem":{"read":["."]}}"#,
            r#"{"meta":{}}"#,
            r#"{"network":{"allow_domain":["example.com"]}}"#,
            r#"{"network":{"block":true}}"#,
        ] {
            let workspace = tempfile::tempdir()?;
            std::fs::write(workspace.path().join("runseal.json"), input)?;
            let repo = crate::repo_profile::load("runseal.json", workspace.path())?;
            let network = if repo.allows_domains() {
                NetworkPolicy::FromRepoProfile
            } else {
                NetworkPolicy::Blocked
            };
            let sealed = SealedCredentials {
                dir: tempfile::tempdir()?,
                access: Vec::new(),
                sanitized_env: BTreeMap::new(),
            };
            let sibling = repo.write_sibling(sealed.dir.path())?;
            let config = profile_mode_config(network, repo);
            let generated = sealed.dir.path().join("profile.json");
            write_profile(&generated, &build_profile(&config, &sealed)?)?;
            for path in [&sibling, &generated] {
                let output = std::process::Command::new("nono")
                    .args(["profile", "validate"])
                    .arg(path)
                    .env("NONO_NO_MIGRATE", "1")
                    .output()?;
                assert!(output.status.success(), "{}: {output:?}", path.display());
            }
        }
        Ok(())
    }

    #[test]
    fn generated_profile_extends_only_default_without_a_repo_profile() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
            repo_profile: None,
        };

        let profile = build_profile(&config, &empty_sealed()).expect("profile");
        let json: serde_json::Value = serde_json::to_value(&profile).expect("json");

        assert_eq!(json["extends"], serde_json::json!(["default"]));
    }

    #[test]
    fn generated_profile_extends_the_repo_profile_last_so_runseal_stays_the_child() {
        let (_dir, repo) = repo_profile(r#"{"filesystem":{"read":["/usr"]}}"#);
        let config = profile_mode_config(NetworkPolicy::Blocked, repo);

        let profile = build_profile(&config, &empty_sealed()).expect("profile");
        let json: serde_json::Value = serde_json::to_value(&profile).expect("json");

        assert_eq!(
            json["extends"],
            serde_json::json!(["default", "runseal-repo"])
        );
    }

    #[test]
    fn profile_mode_without_domains_still_blocks_the_network() {
        let (_dir, repo) = repo_profile(r#"{"filesystem":{"read":["/usr"]}}"#);
        let config = profile_mode_config(NetworkPolicy::Blocked, repo);

        let profile = build_profile(&config, &empty_sealed()).expect("profile");
        let json: serde_json::Value = serde_json::to_value(&profile).expect("json");

        assert_eq!(json["network"]["block"], true);
    }

    #[test]
    fn profile_mode_with_domains_omits_block_entirely() {
        let (_dir, repo) = repo_profile(r#"{"network":{"allow_domain":["example.com"]}}"#);
        let config = profile_mode_config(NetworkPolicy::FromRepoProfile, repo);

        let profile = build_profile(&config, &empty_sealed()).expect("profile");
        let json: serde_json::Value = serde_json::to_value(&profile).expect("json");

        assert!(
            json["network"].get("block").is_none(),
            "network.block must be absent: {json}"
        );
        assert!(
            json["network"].get("allow_domain").is_none(),
            "the repo profile owns the domain list: {json}"
        );
    }

    #[test]
    fn upstream_host_parses_hosts() {
        assert_eq!(upstream_host("https://crates.io"), Some("crates.io"));
        assert_eq!(
            upstream_host("https://user@example.com:8443/path"),
            Some("example.com")
        );
        assert_eq!(upstream_host("http://[::1]:8080"), Some("::1"));
        assert_eq!(upstream_host("file:///tmp/secret"), None);
    }
}
