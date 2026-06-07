use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub command: String,
    pub fs_read: Vec<String>,
    pub fs_write: Vec<String>,
    pub network: NetworkPolicy,
    pub access: Vec<AccessConfig>,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkPolicy {
    Blocked,
    AllowDomains(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditConfig {
    Disabled,
    Artifact { dir: String },
}

#[derive(Debug, Clone)]
pub struct AccessConfig {
    pub name: String,
    pub secret: String,
    pub upstream: String,
    pub tls_ca: Option<String>,
    pub inject_mode: String,
    pub endpoint_rules: Vec<EndpointRule>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct EndpointRule {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyInput {
    fs: Option<FsInput>,
    network: Option<NetworkInput>,
    access: Option<std::collections::BTreeMap<String, AccessInput>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FsInput {
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    write: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkInput {
    #[serde(default = "default_blocked")]
    mode: String,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessInput {
    secret: String,
    url: String,
    #[serde(default)]
    tls_ca: Option<String>,
    #[serde(default)]
    inject: InjectInput,
    #[serde(default)]
    allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectInput {
    #[serde(default = "default_header_mode")]
    mode: String,
}

impl Default for InjectInput {
    fn default() -> Self {
        Self {
            mode: default_header_mode(),
        }
    }
}

fn default_blocked() -> String {
    "blocked".to_string()
}
fn default_header_mode() -> String {
    "header".to_string()
}
impl RunConfig {
    pub fn from_action_env() -> Result<Self> {
        let command = env_value("RUNSEAL_RUN")
            .or_else(|| env_value("NONO_ACTION_COMMAND"))
            .context("RUNSEAL_RUN is required")?;

        if let Some(policy_yaml) = env_value("RUNSEAL_POLICY") {
            let policy: PolicyInput = serde_yaml::from_str(&policy_yaml)
                .context("RUNSEAL_POLICY is not valid runseal policy YAML")?;
            return Self::from_policy(command, policy);
        }

        let fs_read = split_csv(
            env_value("RUNSEAL_FS_READ")
                .or_else(|| env_value("NONO_ACTION_FS_READ"))
                .as_deref(),
        );
        let fs_write = split_csv(
            env_value("RUNSEAL_FS_WRITE")
                .or_else(|| env_value("NONO_ACTION_FS_WRITE"))
                .as_deref(),
        );
        let network = parse_network(
            env_value("RUNSEAL_NETWORK")
                .or_else(|| env_value("NONO_ACTION_NETWORK"))
                .as_deref(),
        );
        let audit = parse_audit(
            env_value("RUNSEAL_AUDIT").as_deref(),
            env_value("RUNSEAL_AUDIT_DIR").as_deref(),
        )?;
        Ok(Self {
            command,
            fs_read,
            fs_write,
            network,
            access: Vec::new(),
            audit,
        })
    }

    fn from_policy(command: String, policy: PolicyInput) -> Result<Self> {
        let (fs_read, fs_write) = policy.fs.map(|fs| (fs.read, fs.write)).unwrap_or_default();
        let network = match policy.network {
            Some(network)
                if matches!(network.mode.as_str(), "blocked" | "filtered")
                    && network.allow.is_empty() =>
            {
                NetworkPolicy::Blocked
            }
            Some(network) if matches!(network.mode.as_str(), "blocked" | "filtered") => {
                NetworkPolicy::AllowDomains(network.allow)
            }
            Some(network) => bail!(
                "unsupported network.mode '{}'; expected 'blocked' or 'filtered'",
                network.mode
            ),
            None => NetworkPolicy::Blocked,
        };
        let mut access = Vec::new();
        for (name, grant) in policy.access.unwrap_or_default() {
            access.push(AccessConfig {
                name,
                secret: grant.secret,
                upstream: validate_url(&grant.url)?,
                tls_ca: grant.tls_ca,
                inject_mode: grant.inject.mode,
                endpoint_rules: parse_allow_rules(&grant.allow)?,
            });
        }
        Ok(Self {
            command,
            fs_read,
            fs_write,
            network,
            access,
            audit: parse_audit(
                env_value("RUNSEAL_AUDIT").as_deref(),
                env_value("RUNSEAL_AUDIT_DIR").as_deref(),
            )?,
        })
    }
}

fn env_value(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn split_csv(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_network(value: Option<&str>) -> NetworkPolicy {
    let raw = value.unwrap_or("blocked").trim();
    if raw.is_empty() || raw == "blocked" {
        NetworkPolicy::Blocked
    } else {
        NetworkPolicy::AllowDomains(split_csv(Some(raw)))
    }
}

fn parse_audit(value: Option<&str>, dir: Option<&str>) -> Result<AuditConfig> {
    match value.unwrap_or("false").trim() {
        "" | "false" | "off" | "none" => Ok(AuditConfig::Disabled),
        "true" | "artifact" => {
            let dir = dir
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("runseal-audit");
            Ok(AuditConfig::Artifact {
                dir: dir.to_string(),
            })
        }
        value => bail!("unsupported audit mode '{value}'; expected 'false' or 'artifact'"),
    }
}

fn validate_url(url: &str) -> Result<String> {
    if url.starts_with("http://") || url.starts_with("https://") {
        Ok(url.trim_end_matches('/').to_string())
    } else {
        bail!("access url '{url}' must start with 'https://' or 'http://'")
    }
}

fn parse_allow_rules(allow: &[String]) -> Result<Vec<EndpointRule>> {
    if allow.is_empty() {
        bail!("access grants require at least one allow rule; add allow entries for each permitted METHOD /path");
    }

    allow
        .iter()
        .map(|rule| {
            let mut parts = rule.splitn(2, char::is_whitespace);
            let method = parts.next().unwrap_or_default().trim();
            let path = parts.next().unwrap_or_default().trim();
            if method.is_empty() || path.is_empty() {
                bail!("access allow rule '{rule}' must be formatted as 'METHOD /path'");
            }
            Ok(EndpointRule {
                method: method.to_string(),
                path: path.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_grant_without_allow_rules_fails_closed() {
        let policy: PolicyInput = serde_yaml::from_str(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
"#,
        )
        .expect("policy yaml");

        let err = RunConfig::from_policy("true".to_string(), policy)
            .expect_err("missing allow rules must fail");

        assert!(
            err.to_string()
                .contains("access grants require at least one allow rule"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn access_grant_with_empty_allow_rules_fails_closed() {
        let policy: PolicyInput = serde_yaml::from_str(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    allow: []
"#,
        )
        .expect("policy yaml");

        let err = RunConfig::from_policy("true".to_string(), policy)
            .expect_err("empty allow rules must fail");

        assert!(
            err.to_string()
                .contains("access grants require at least one allow rule"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn access_grant_with_allow_rules_parses() {
        let policy: PolicyInput = serde_yaml::from_str(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    allow:
      - GET /api/v1/crates
"#,
        )
        .expect("policy yaml");

        let config = RunConfig::from_policy("true".to_string(), policy).expect("policy parses");

        assert_eq!(config.access.len(), 1);
        assert_eq!(config.access[0].endpoint_rules.len(), 1);
        assert_eq!(config.access[0].endpoint_rules[0].method, "GET");
        assert_eq!(config.access[0].endpoint_rules[0].path, "/api/v1/crates");
    }
}
