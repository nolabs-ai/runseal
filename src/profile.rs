use crate::config::{NetworkPolicy, RunConfig};
use crate::secrets::SealedCredentials;
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct NonoProfile {
    extends: &'static str,
    meta: Meta,
    groups: Groups,
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
struct Network {
    #[serde(skip_serializing_if = "is_false")]
    block: bool,
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
    inject_mode: String,
    inject_header: &'static str,
    credential_format: &'static str,
    env_var: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_ca: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoint_rules: Vec<crate::config::EndpointRule>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

pub fn build_profile(config: &RunConfig, sealed: &SealedCredentials) -> Result<NonoProfile> {
    let mut allow_domains: BTreeSet<String> = match &config.network {
        NetworkPolicy::Blocked => Vec::new(),
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
        custom_credentials.insert(
            credential.name.clone(),
            CustomCredential {
                upstream: credential.upstream.clone(),
                credential_key: format!("file://{}", credential.credential_file.display()),
                inject_mode: credential.inject_mode.clone(),
                inject_header: "Authorization",
                credential_format: "Bearer {}",
                env_var: credential.secret_env.clone(),
                tls_ca: credential.tls_ca.clone(),
                endpoint_rules: credential.endpoint_rules.clone(),
            },
        );
    }

    Ok(NonoProfile {
        extends: "default",
        meta: Meta {
            name: "runseal-generated",
            version: env!("CARGO_PKG_VERSION"),
        },
        groups: Groups {
            exclude: excluded_groups(),
        },
        network: Network {
            block: matches!(config.network, NetworkPolicy::Blocked),
            allow_domain: allow_domains.into_iter().collect(),
            credentials,
            custom_credentials,
        },
    })
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
    use crate::config::{NetworkPolicy, RunConfig};
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
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = SealedCredentials {
            access: vec![SealedCredential {
                name: "cratesio".to_string(),
                secret_env: "CARGO_REGISTRY_TOKEN".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: "header".to_string(),
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
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = SealedCredentials {
            access: vec![SealedCredential {
                name: "cratesio".to_string(),
                secret_env: "CARGO_REGISTRY_TOKEN".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: "header".to_string(),
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
    fn generated_profile_allows_access_upstream_hosts() {
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![".".to_string()],
            fs_write: Vec::new(),
            network: NetworkPolicy::AllowDomains(vec!["index.crates.io".to_string()]),
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sealed = SealedCredentials {
            access: vec![SealedCredential {
                name: "cratesio".to_string(),
                secret_env: "CARGO_REGISTRY_TOKEN".to_string(),
                upstream: "https://crates.io".to_string(),
                tls_ca: None,
                inject_mode: "header".to_string(),
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
