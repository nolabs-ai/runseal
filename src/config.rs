use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::env;

const MAX_POLICY_YAML_BYTES: usize = 64 * 1024;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NetworkMode {
    Blocked,
    Filtered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditConfig {
    Disabled,
    Artifact { dir: String },
}

/// Secret injection modes in nono's wire format
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InjectMode {
    #[default]
    Header,
    UrlPath,
    QueryParam,
    BasicAuth,
}

impl InjectMode {
    fn wire_name(self) -> &'static str {
        match self {
            InjectMode::Header => "header",
            InjectMode::UrlPath => "url_path",
            InjectMode::QueryParam => "query_param",
            InjectMode::BasicAuth => "basic_auth",
        }
    }
}

/// The inject modes runseal can emit a complete nono credential entry for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportedInjectMode {
    Header,
    BasicAuth,
}

#[derive(Debug, Clone)]
pub struct AccessConfig {
    pub name: String,
    pub secret: String,
    pub upstream: String,
    pub tls_ca: Option<String>,
    pub inject_mode: SupportedInjectMode,
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
    #[serde(default, deserialize_with = "explicit_network_mode")]
    mode: Option<NetworkMode>,
    #[serde(default)]
    allow: Vec<String>,
}

/// An omitted `mode` key means "infer from the allow list", but a present key
/// must carry a real mode: an explicit null (`mode:` / `mode: ~`) is rejected
/// rather than silently aliased to the omitted case.
fn explicit_network_mode<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<NetworkMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    NetworkMode::deserialize(deserializer).map(Some)
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct InjectInput {
    #[serde(default)]
    mode: InjectMode,
}

impl RunConfig {
    pub fn from_action_env() -> Result<Self> {
        let command = env_value("RUNSEAL_RUN")
            .or_else(|| env_value("NONO_ACTION_COMMAND"))
            .context("RUNSEAL_RUN is required")?;

        if let Some(policy_yaml) = env_value("RUNSEAL_POLICY") {
            let policy = parse_policy_yaml(&policy_yaml)?;
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
            Some(network) if network.allow.is_empty() => NetworkPolicy::Blocked,
            Some(network) => match network.mode {
                Some(NetworkMode::Blocked) => bail!(
                    "network.mode 'blocked' cannot be combined with network.allow; use mode 'filtered' or remove the allow list"
                ),
                // An allow list without an explicit mode has always meant a
                // domain allowlist; only a stated 'blocked' contradicts it.
                Some(NetworkMode::Filtered) | None => NetworkPolicy::AllowDomains(network.allow),
            },
            None => NetworkPolicy::Blocked,
        };
        let mut access = Vec::new();
        for (name, grant) in policy.access.unwrap_or_default() {
            let inject_mode = match grant.inject.mode {
                InjectMode::Header => SupportedInjectMode::Header,
                InjectMode::BasicAuth => SupportedInjectMode::BasicAuth,
                mode @ (InjectMode::UrlPath | InjectMode::QueryParam) => bail!(
                    "access grant '{name}' uses inject.mode '{}', which is not yet supported by runseal; use 'header' or 'basic_auth'",
                    mode.wire_name()
                ),
            };
            access.push(AccessConfig {
                name,
                secret: grant.secret,
                upstream: validate_url(&grant.url)?,
                tls_ca: grant.tls_ca,
                inject_mode,
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

fn parse_policy_yaml(policy_yaml: &str) -> Result<PolicyInput> {
    if policy_yaml.len() > MAX_POLICY_YAML_BYTES {
        bail!(
            "RUNSEAL_POLICY is too large ({} bytes); maximum is {} bytes",
            policy_yaml.len(),
            MAX_POLICY_YAML_BYTES
        );
    }

    serde_yaml_ng::from_str(policy_yaml).context("RUNSEAL_POLICY is not valid runseal policy YAML")
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
    match value.unwrap_or_default().trim() {
        "" | "false" | "off" | "none" => Ok(AuditConfig::Disabled),
        "true" | "artifact" => {
            let dir = dir
                .filter(|value| !value.trim().is_empty())
                .unwrap_or("runseal-audit");
            Ok(AuditConfig::Artifact {
                dir: dir.to_string(),
            })
        }
        value => bail!(
            "unsupported audit mode '{value}'; expected one of 'false', 'off', 'none', 'true', 'artifact'"
        ),
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
        let policy = parse_policy_yaml(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
"#,
        )
        .expect("Valid policy yaml");

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
        let policy = parse_policy_yaml(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    allow: []
"#,
        )
        .expect("Valid policy yaml");

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
        let policy = parse_policy_yaml(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    allow:
      - GET /api/v1/crates
"#,
        )
        .expect("Valid policy yaml");

        let config = RunConfig::from_policy("true".to_string(), policy)
            .expect("Policy should parse correctly");

        assert_eq!(config.access.len(), 1);
        assert_eq!(config.access[0].endpoint_rules.len(), 1);
        assert_eq!(config.access[0].endpoint_rules[0].method, "GET");
        assert_eq!(config.access[0].endpoint_rules[0].path, "/api/v1/crates");
    }

    #[test]
    fn audit_mode_aliases_parse() {
        for value in ["", "false", "off", "none", " false "] {
            assert_eq!(
                parse_audit(Some(value), None).expect("disabled alias"),
                AuditConfig::Disabled,
                "value {value:?}"
            );
        }
        assert_eq!(
            parse_audit(None, None).expect("unset"),
            AuditConfig::Disabled
        );
        for value in ["true", "artifact"] {
            assert_eq!(
                parse_audit(Some(value), None).expect("artifact alias"),
                AuditConfig::Artifact {
                    dir: "runseal-audit".to_string()
                },
                "value {value:?}"
            );
        }
    }

    #[test]
    fn audit_artifact_uses_configured_dir() {
        assert_eq!(
            parse_audit(Some("artifact"), Some("/tmp/audit")).expect("artifact"),
            AuditConfig::Artifact {
                dir: "/tmp/audit".to_string()
            }
        );
    }

    #[test]
    fn unknown_network_mode_fails_to_parse() {
        let err = parse_policy_yaml(
            r#"
network:
  mode: open
"#,
        )
        .expect_err("unknown network mode must fail");

        assert!(
            format!("{err:#}").contains("not valid runseal policy YAML"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn explicit_null_network_mode_fails_to_parse() {
        for policy in [
            "network:\n  mode:\n  allow:\n    - api.github.com\n",
            "network:\n  mode: ~\n  allow:\n    - api.github.com\n",
        ] {
            let err = parse_policy_yaml(policy).expect_err("null network mode must fail");

            assert!(
                format!("{err:#}").contains("not valid runseal policy YAML"),
                "unexpected error: {err:#}"
            );
        }
    }

    #[test]
    fn blocked_network_mode_with_allow_list_fails_closed() {
        let policy = parse_policy_yaml(
            r#"
network:
  mode: blocked
  allow:
    - api.github.com
"#,
        )
        .expect("policy yaml");

        let err = RunConfig::from_policy("true".to_string(), policy)
            .expect_err("blocked mode with allow list must fail");

        assert!(
            err.to_string()
                .contains("network.mode 'blocked' cannot be combined with network.allow"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn filtered_network_mode_with_allow_list_allows_domains() {
        let policy = parse_policy_yaml(
            r#"
network:
  mode: filtered
  allow:
    - api.github.com
"#,
        )
        .expect("policy yaml");

        let config = RunConfig::from_policy("true".to_string(), policy).expect("policy parses");

        assert_eq!(
            config.network,
            NetworkPolicy::AllowDomains(vec!["api.github.com".to_string()])
        );
    }

    #[test]
    fn allow_list_without_mode_allows_domains() {
        let policy = parse_policy_yaml(
            r#"
network:
  allow:
    - api.github.com
"#,
        )
        .expect("policy yaml");

        let config = RunConfig::from_policy("true".to_string(), policy).expect("policy parses");

        assert_eq!(
            config.network,
            NetworkPolicy::AllowDomains(vec!["api.github.com".to_string()])
        );
    }

    #[test]
    fn filtered_network_mode_without_allow_list_blocks_network() {
        let policy = parse_policy_yaml(
            r#"
network:
  mode: filtered
"#,
        )
        .expect("policy yaml");

        let config = RunConfig::from_policy("true".to_string(), policy).expect("policy parses");

        assert_eq!(config.network, NetworkPolicy::Blocked);
    }

    #[test]
    fn access_grant_defaults_to_header_inject_mode() {
        let policy = parse_policy_yaml(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    allow:
      - GET /api/v1/crates
"#,
        )
        .expect("Valid policy yaml");

        let config = RunConfig::from_policy("true".to_string(), policy)
            .expect("Policy should parse correctly");

        assert_eq!(config.access[0].inject_mode, SupportedInjectMode::Header);
    }

    #[test]
    fn basic_auth_inject_mode_maps_and_serializes_as_snake_case() {
        let policy = parse_policy_yaml(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    inject:
      mode: basic_auth
    allow:
      - GET /api/v1/crates
"#,
        )
        .expect("Valid policy yaml");

        let config = RunConfig::from_policy("true".to_string(), policy)
            .expect("Policy should parse correctly");

        assert_eq!(config.access[0].inject_mode, SupportedInjectMode::BasicAuth);
        assert_eq!(
            serde_json::to_string(&config.access[0].inject_mode).expect("Valid json"),
            r#""basic_auth""#
        );
    }

    #[test]
    fn unsupported_inject_mode_fails_closed() {
        let policy = parse_policy_yaml(
            r#"
access:
  cratesio:
    secret: CARGO_REGISTRY_TOKEN
    url: https://crates.io
    inject:
      mode: url_path
    allow:
      - GET /api/v1/crates
"#,
        )
        .expect("Valid policy yaml");

        let err = RunConfig::from_policy("true".to_string(), policy)
            .expect_err("unsupported inject mode must fail");

        assert!(
            err.to_string()
                .contains("inject.mode 'url_path', which is not yet supported"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn policy_yaml_over_size_limit_fails_before_parsing() {
        let yaml = " ".repeat(MAX_POLICY_YAML_BYTES + 1);

        let err = parse_policy_yaml(&yaml).expect_err("oversized policy must fail");

        assert!(
            err.to_string().contains("RUNSEAL_POLICY is too large"),
            "unexpected error: {err:#}"
        );
    }
}
