use crate::config::{NetworkPolicy, RunConfig};
use crate::secrets::SealedCredentials;
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
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
    let allow_domain = match &config.network {
        NetworkPolicy::Blocked => Vec::new(),
        NetworkPolicy::AllowDomains(domains) => domains.clone(),
    };
    let mut credentials = Vec::new();
    let mut custom_credentials = BTreeMap::new();

    for credential in &sealed.access {
        credentials.push(credential.name.clone());
        custom_credentials.insert(
            credential.name.clone(),
            CustomCredential {
                upstream: credential.upstream.clone(),
                credential_key: format!("file://{}", credential.credential_file.display()),
                inject_mode: credential.inject_mode.clone(),
                inject_header: "Authorization",
                credential_format: "Bearer {}",
                env_var: format!("RUNSEAL_ACCESS_{}_TOKEN", env_name(&credential.name)),
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
            exclude: vec!["system_write_linux", "system_write_macos"],
        },
        network: Network {
            block: matches!(config.network, NetworkPolicy::Blocked) && credentials.is_empty(),
            allow_domain,
            credentials,
            custom_credentials,
        },
    })
}

fn env_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
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
    use crate::secrets::SealedCredentials;
    use std::collections::BTreeMap;

    #[test]
    fn generated_profile_excludes_broad_system_write_groups() {
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

        assert!(json.contains("system_write_linux"));
        assert!(json.contains("system_write_macos"));
    }
}
