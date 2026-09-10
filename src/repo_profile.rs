//! Validate and stage a repo profile beneath runseal's generated profile.

use crate::config::validate_domain_allowlist;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

const MAX_PROFILE_JSON_BYTES: u64 = 64 * 1024;

/// nono resolves this to a sibling `<name>.json`.
pub const BASE_NAME: &str = "runseal-repo";

/// Validated, normalized profile.
#[derive(Debug, Clone)]
pub struct RepoProfile {
    source: PathBuf,
    profile: BaseProfile,
}

impl RepoProfile {
    /// The canonical path the profile was read from.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Whether domain grants prevent the generated profile setting `network.block`.
    pub fn allows_domains(&self) -> bool {
        self.profile
            .network
            .as_ref()
            .is_some_and(|network| !network.allow_domain.is_empty())
    }

    /// The validated profile serialized as JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.profile)
            .context("failed to serialize the validated repo profile")
    }

    /// Stage the validated profile as a sibling for resolution.
    #[must_use = "the sibling profile must exist before nono is spawned"]
    pub fn write_sibling(&self, dir: &Path) -> Result<PathBuf> {
        let path = dir.join(format!("{BASE_NAME}.json"));
        fs::write(&path, self.to_json()?)
            .with_context(|| format!("failed to write '{}'", path.display()))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to restrict '{}'", path.display()))?;
        Ok(path)
    }
}

/// Allowed profile fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BaseProfile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    meta: Option<Meta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filesystem: Option<Filesystem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<Network>,
}

/// Informational metadata.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Meta {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Filesystem {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    write: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    read_file: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    write_file: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Network {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    allow_domain: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    block: Option<bool>,
}

/// Load and normalize a workspace-relative profile.
#[must_use = "a repo profile is only enforced once it reaches the generated profile"]
pub fn load(input: &str, workspace: &Path) -> Result<RepoProfile> {
    let input = input.trim();
    if input.is_empty() {
        bail!("profile input is empty; name a profile file such as 'runseal.json'");
    }

    let requested = Path::new(input);
    if requested.is_absolute() {
        bail!("profile '{input}' must be a path relative to the workspace, not an absolute path");
    }
    for component in requested.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                bail!("profile '{input}' must not traverse out of the workspace with '..'")
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("profile '{input}' must be a path relative to the workspace")
            }
        }
    }

    let workspace = workspace
        .canonicalize()
        .with_context(|| format!("failed to resolve the workspace '{}'", workspace.display()))?;
    let path = workspace.join(requested).canonicalize().with_context(|| {
        format!(
            "profile '{input}' was not found in '{}'",
            workspace.display()
        )
    })?;
    if !path.starts_with(&workspace) {
        bail!(
            "profile '{input}' resolves to '{}', which is outside the workspace '{}'",
            path.display(),
            workspace.display()
        );
    }

    let metadata = fs::metadata(&path)
        .with_context(|| format!("failed to stat profile '{}'", path.display()))?;
    if !metadata.is_file() {
        bail!("profile '{}' is not a regular file", path.display());
    }
    if metadata.len() > MAX_PROFILE_JSON_BYTES {
        bail!(
            "profile '{}' is too large ({} bytes); maximum is {MAX_PROFILE_JSON_BYTES} bytes",
            path.display(),
            metadata.len()
        );
    }

    let text = fs::read_to_string(&path)
        .with_context(|| format!("failed to read profile '{}'", path.display()))?;
    let profile = parse(&text, &workspace)
        .with_context(|| format!("profile '{}' was rejected", path.display()))?;

    Ok(RepoProfile {
        source: path,
        profile,
    })
}

fn parse(text: &str, workspace: &Path) -> Result<BaseProfile> {
    let value: serde_json::Value =
        serde_json::from_str(text).context("not valid JSON; runseal requires strict JSON")?;
    let serde_json::Value::Object(mut object) = value else {
        bail!("a nono profile must be a JSON object");
    };

    reject_disallowed_keys(object.keys().map(String::as_str), None)?;
    for section in ["meta", "filesystem", "network"] {
        if let Some(nested) = object.get(section).and_then(serde_json::Value::as_object) {
            reject_disallowed_keys(nested.keys().map(String::as_str), Some(section))?;
        }
    }

    // Only used as a hint.
    object.remove("$schema");

    let mut profile: BaseProfile = serde_json::from_value(serde_json::Value::Object(object))?;
    normalize(&mut profile, workspace)?;
    Ok(profile)
}

/// Keys runseal accepts.
fn allowed_keys(section: Option<&str>) -> &'static [&'static str] {
    match section {
        None => &["$schema", "meta", "filesystem", "network"],
        Some("meta") => &["name", "description"],
        Some("filesystem") => &["read", "write", "read_file", "write_file", "deny"],
        Some("network") => &["allow_domain", "block"],
        Some(_) => &[],
    }
}

/// Explain common unsupported keys and their security implications.
fn rejection_reason(section: Option<&str>, key: &str) -> Option<&'static str> {
    Some(match (section, key) {
        (None, "extends") => "runseal supplies the base profile",
        (None, "binary") => "it would replace the command the workflow asked runseal to run",
        (None, "command_args") => "it would append arguments to the sandboxed command",
        (None, "session_hooks") => {
            "session hooks run outside the sandbox with host privileges"
        }
        (None, "hooks") => "hook configuration is not part of a runseal sandbox policy",
        (None, "unsafe_macos_seatbelt_rules") => {
            "raw Seatbelt rules can grant unrestricted access"
        }
        (None, "command_policies") => {
            "command policies merge base-first, overriding runseal's own policy"
        }
        (None, "commands") => "runseal does not delegate command allow/deny to the repo",
        (None, "groups") => {
            "group exclusions are sticky and could drop a nono deny group runseal relies on"
        }
        (None, "security") => "security settings are runseal's to set",
        (None, "environment" | "env_credentials" | "secrets") => {
            "runseal controls the sandboxed environment and credential injection"
        }
        (None, "credential_capture" | "credential_providers" | "credential_routes")
        | (Some("network"), "credentials" | "custom_credentials" | "proxy_credentials") => {
            "profile mode has no credential input; use 'policy' with an 'access' block instead of 'profile'"
        }
        (None, "packs") => "pack references are not resolved in a CI sandbox",
        (None, "platform_overrides") => "platform overrides can reintroduce any rejected key",
        (None, "policy") => "this legacy nono section is not supported",
        (None, "workdir") => "runseal runs the command in the workspace",
        (Some("filesystem"), "allow" | "allow_file") => {
            "grant read and write separately with 'read'/'read_file' and 'write'/'write_file'"
        }
        (Some("filesystem"), "bypass_protection") => "it removes nono's own deny rules",
        (Some("network"), "proxy_allow" | "allow_proxy") => {
            "use the canonical key 'allow_domain'"
        }
        _ => return None,
    })
}

fn reject_disallowed_keys<'a>(
    keys: impl Iterator<Item = &'a str>,
    section: Option<&str>,
) -> Result<()> {
    let allowed = allowed_keys(section);
    for key in keys {
        if allowed.contains(&key) {
            continue;
        }
        let path = match section {
            Some(section) => format!("{section}.{key}"),
            None => key.to_string(),
        };
        match rejection_reason(section, key) {
            Some(reason) => bail!("profile key '{path}' is not permitted: {reason}"),
            None => bail!(
                "profile key '{path}' is not permitted; runseal accepts only {}",
                allowed.join(", ")
            ),
        }
    }
    Ok(())
}

fn normalize(profile: &mut BaseProfile, workspace: &Path) -> Result<()> {
    if let Some(meta) = profile.meta.as_mut() {
        meta.name.get_or_insert_with(|| BASE_NAME.to_string());
    }
    if let Some(filesystem) = profile.filesystem.as_mut() {
        for (field, paths) in [
            ("read", &mut filesystem.read),
            ("write", &mut filesystem.write),
            ("read_file", &mut filesystem.read_file),
            ("write_file", &mut filesystem.write_file),
            ("deny", &mut filesystem.deny),
        ] {
            for path in paths.iter_mut() {
                *path = normalize_path(path, workspace)
                    .with_context(|| format!("filesystem.{field} entry '{path}' is not usable"))?;
                if matches!(field, "write" | "write_file") {
                    *path = validate_write_target(path, field)?;
                }
            }
        }
    }

    if let Some(network) = profile.network.as_mut() {
        network.allow_domain = validate_domain_allowlist(std::mem::take(&mut network.allow_domain))
            .context("network.allow_domain is not usable")?;
        match network.block {
            Some(false) => bail!(
                "network.block 'false' has no effect: nono keeps a block once any layer sets it. Grant network access by listing hosts in network.allow_domain"
            ),
            Some(true) if !network.allow_domain.is_empty() => bail!(
                "network.block 'true' cannot be combined with network.allow_domain; domain filtering requires the proxy"
            ),
            _ => {}
        }
    }

    Ok(())
}

/// Profile grants to missing targets are silently skipped by nono.
fn validate_write_target(entry: &str, field: &str) -> Result<String> {
    if entry.starts_with('~') || entry.contains(['$', '*', '?', '[']) {
        bail!(
            "filesystem.{field} entry '{entry}' must be a concrete path without variables, '~', or glob patterns; use an existing workspace-relative or absolute path"
        );
    }
    let path = Path::new(entry).canonicalize().with_context(|| {
        format!(
            "filesystem.{field} entry '{entry}' could not be resolved; create the target before running runseal (nono skips missing profile write targets)"
        )
    })?;
    let metadata = fs::metadata(&path)
        .with_context(|| format!("failed to inspect filesystem.{field} entry '{entry}'"))?;
    if (field == "write" && !metadata.is_dir()) || (field == "write_file" && !metadata.is_file()) {
        bail!(
            "filesystem.{field} entry '{entry}' must name an existing {}",
            if field == "write" {
                "directory"
            } else {
                "regular file"
            }
        );
    }
    path.into_os_string().into_string().map_err(|_| {
        anyhow::anyhow!("filesystem.{field} entry '{entry}' resolves to a non-UTF-8 path")
    })
}

/// Anchor relative paths to the workspace.
fn normalize_path(entry: &str, workspace: &Path) -> Result<String> {
    let entry = entry.trim();
    if entry.is_empty() {
        bail!("filesystem entries must not be empty");
    }
    if entry.contains("${") {
        bail!("'${{VAR}}' is not expanded by nono; write '$VAR' instead");
    }
    // Defer '~' and '$VAR' expansion to nono's environment.
    if entry.starts_with('/') || entry.starts_with('~') || entry.starts_with('$') {
        return Ok(entry.to_string());
    }

    let resolved = resolve_relative_path(workspace, Path::new(entry))?;
    resolved
        .into_os_string()
        .into_string()
        .map_err(|path| anyhow::anyhow!("'{}' is not valid UTF-8", Path::new(&path).display()))
}

/// Resolve existing components before interpreting subsequent `..` components.
fn resolve_relative_path(workspace: &Path, relative: &Path) -> Result<PathBuf> {
    let mut resolved = workspace.to_path_buf();
    for component in relative.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => {
                if part.to_string_lossy().contains(['*', '?', '[']) {
                    bail!("relative glob paths are not supported; write an absolute path if that is intended");
                }
                resolved.push(part);
                match fs::symlink_metadata(&resolved) {
                    Ok(_) => {
                        resolved = resolved.canonicalize().with_context(|| {
                            format!("failed to resolve '{}'", resolved.display())
                        })?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error).context("failed to inspect filesystem entry"),
                }
            }
            Component::ParentDir => {
                resolved = resolved
                    .join("..")
                    .canonicalize()
                    .context("failed to resolve parent traversal in filesystem entry")?;
            }
            Component::RootDir | Component::Prefix(_) => bail!("expected a relative path"),
        }
        if !resolved.starts_with(workspace) {
            bail!(
                "'{}' resolves outside the workspace '{}'; write an absolute path if that is intended",
                relative.display(), workspace.display()
            );
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn workspace() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn write_profile(dir: &Path, contents: &str) -> PathBuf {
        let path = dir.join("runseal.json");
        fs::write(&path, contents).expect("write profile");
        path
    }

    fn load_contents(contents: &str) -> Result<RepoProfile> {
        let dir = workspace();
        write_profile(dir.path(), contents);
        load("runseal.json", dir.path())
    }

    fn rejection(contents: &str) -> String {
        let err = load_contents(contents).expect_err("profile must be rejected");
        format!("{err:#}")
    }

    #[test]
    fn minimal_profile_loads() {
        let profile = load_contents(r#"{"network":{"allow_domain":["example.com"]}}"#)
            .expect("profile loads");

        assert!(profile.allows_domains());
    }

    #[test]
    fn metadata_without_a_name_gets_a_nono_compatible_default() -> Result<()> {
        for input in [
            r#"{"meta":{}}"#,
            r#"{"meta":{"description":"Build sandbox"}}"#,
        ] {
            let profile = load_contents(input)?;
            let json: serde_json::Value = serde_json::from_str(&profile.to_json()?)?;
            assert_eq!(json["meta"]["name"], BASE_NAME);
            let original: serde_json::Value = serde_json::from_str(input)?;
            assert_eq!(json["meta"]["description"], original["meta"]["description"]);
        }
        let profile = load_contents(r#"{"meta":{"name":"my-build"}}"#)?;
        let json: serde_json::Value = serde_json::from_str(&profile.to_json()?)?;
        assert_eq!(json["meta"]["name"], "my-build");
        let profile = load_contents("{}")?;
        let json: serde_json::Value = serde_json::from_str(&profile.to_json()?)?;
        assert!(json.get("meta").is_none());
        Ok(())
    }

    #[test]
    fn profile_without_domains_does_not_allow_domains() {
        let profile = load_contents(r#"{"filesystem":{"read":["/usr"]}}"#).expect("profile loads");

        assert!(!profile.allows_domains());
    }

    #[test]
    fn capability_granting_keys_are_rejected_with_a_reason() {
        for (key, fragment) in [
            (r#""binary":"/bin/sh""#, "replace the command"),
            (
                r#""session_hooks":{"before":"/tmp/hook.sh"}"#,
                "outside the sandbox",
            ),
            (r#""command_args":["--yolo"]"#, "append arguments"),
            (
                r#""unsafe_macos_seatbelt_rules":["(allow default)"]"#,
                "unrestricted access",
            ),
            (r#""command_policies":{}"#, "merge base-first"),
            (r#""groups":{"exclude":["deny_credentials"]}"#, "sticky"),
            (r#""hooks":{}"#, "hook configuration"),
            (r#""packs":["a/b"]"#, "pack references"),
            (r#""platform_overrides":{}"#, "reintroduce any rejected key"),
            (r#""security":{}"#, "runseal's to set"),
            (r#""workdir":{}"#, "runs the command in the workspace"),
            (r#""extends":"claude-code""#, "supplies the base profile"),
        ] {
            let error = rejection(&format!("{{{key}}}"));
            assert!(
                error.contains("is not permitted") && error.contains(fragment),
                "unexpected error for {key}: {error}"
            );
        }
    }

    #[test]
    fn unknown_top_level_key_is_rejected() {
        let error = rejection(r#"{"nonsense":true}"#);

        assert!(
            error.contains("profile key 'nonsense' is not permitted"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn filesystem_allow_points_at_read_and_write() {
        for key in ["allow", "allow_file"] {
            let error = rejection(&format!(r#"{{"filesystem":{{"{key}":["/tmp"]}}}}"#));

            assert!(
                error.contains(&format!("profile key 'filesystem.{key}' is not permitted"))
                    && error.contains("separately"),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn filesystem_bypass_protection_is_rejected() {
        let error = rejection(r#"{"filesystem":{"bypass_protection":["/etc"]}}"#);

        assert!(
            error.contains("removes nono's own deny rules"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn network_credential_keys_are_rejected() {
        for key in ["credentials", "custom_credentials", "proxy_credentials"] {
            let error = rejection(&format!(r#"{{"network":{{"{key}":{{}}}}}}"#));

            assert!(
                error.contains("instead of 'profile'"),
                "unexpected error for {key}: {error}"
            );
        }
    }

    #[test]
    fn network_allow_domain_aliases_are_rejected() {
        for key in ["proxy_allow", "allow_proxy"] {
            let error = rejection(&format!(r#"{{"network":{{"{key}":["example.com"]}}}}"#));

            assert!(
                error.contains("canonical key 'allow_domain'"),
                "unexpected error for {key}: {error}"
            );
        }
    }

    #[test]
    fn network_block_false_is_rejected_because_it_is_a_no_op() {
        let error = rejection(r#"{"network":{"block":false}}"#);

        assert!(error.contains("has no effect"), "unexpected error: {error}");
    }

    #[test]
    fn network_block_true_with_allow_domain_fails_closed() {
        let error = rejection(r#"{"network":{"block":true,"allow_domain":["example.com"]}}"#);

        assert!(
            error.contains("cannot be combined"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn network_block_true_alone_is_accepted() {
        let profile = load_contents(r#"{"network":{"block":true}}"#).expect("profile loads");

        assert!(!profile.allows_domains());
    }

    #[test]
    fn allow_domain_rejects_mode_keywords() {
        let error = rejection(r#"{"network":{"allow_domain":["blocked"]}}"#);

        assert!(
            error.contains("is not a domain"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn relative_filesystem_entries_are_rewritten_against_the_workspace() -> Result<()> {
        let dir = workspace();
        fs::create_dir(dir.path().join("dist"))?;
        write_profile(
            dir.path(),
            r#"{"filesystem":{"read":["./src"],"write":["dist"],"deny":["./src/secret.txt"]}}"#,
        );
        let canonical = dir.path().canonicalize().expect("canonical workspace");

        let profile = load("runseal.json", dir.path()).expect("profile loads");
        let json = profile.to_json().expect("json");

        assert!(
            json.contains(&canonical.join("src").display().to_string()),
            "read entry was not rewritten: {json}"
        );
        assert!(
            json.contains(&canonical.join("dist").display().to_string()),
            "write entry was not rewritten: {json}"
        );
        assert!(
            json.contains(&canonical.join("src/secret.txt").display().to_string()),
            "deny entry was not rewritten: {json}"
        );
        Ok(())
    }

    #[test]
    fn write_targets_must_exist_and_match_the_declared_type() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let workspace = dir.path().canonicalize()?;
        fs::create_dir(workspace.join("dist"))?;
        fs::write(workspace.join("result.txt"), "keep")?;
        for (field, target) in [("write", "dist"), ("write_file", "result.txt")] {
            for entry in [
                target.to_string(),
                workspace.join(target).display().to_string(),
            ] {
                let profile = parse(
                    &serde_json::json!({"filesystem": {field: [entry]}}).to_string(),
                    &workspace,
                )?;
                let json = serde_json::to_value(profile)?;
                assert_eq!(
                    json["filesystem"][field][0],
                    workspace.join(target).display().to_string()
                );
            }
            for entry in [
                "missing".to_string(),
                workspace.join("missing").display().to_string(),
            ] {
                let result = parse(
                    &serde_json::json!({"filesystem": {field: [entry]}}).to_string(),
                    &workspace,
                );
                let error = match result {
                    Err(error) => format!("{error:#}"),
                    Ok(_) => anyhow::bail!("accepted missing {field} target"),
                };
                assert!(
                    error.contains("create the target before running runseal"),
                    "{error}"
                );
            }
        }
        for (field, entry) in [("write", "result.txt"), ("write_file", "dist")] {
            assert!(parse(
                &serde_json::json!({"filesystem": {field: [entry]}}).to_string(),
                &workspace
            )
            .is_err());
        }
        assert!(!workspace.join("missing").exists());
        assert_eq!(fs::read_to_string(workspace.join("result.txt"))?, "keep");
        Ok(())
    }

    #[test]
    fn write_targets_cannot_defer_validation_to_nono() -> Result<()> {
        let dir = tempfile::tempdir()?;
        for field in ["write", "write_file"] {
            for entry in ["$HOME/dist", "~/dist", "/tmp/*", "/tmp/$OUTPUT"] {
                assert!(parse(
                    &serde_json::json!({"filesystem": {field: [entry]}}).to_string(),
                    dir.path()
                )
                .is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn relative_entry_escaping_the_workspace_fails_closed() {
        let error = rejection(r#"{"filesystem":{"read":["../../etc"]}}"#);

        assert!(
            error.contains("outside the workspace"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn relative_symlink_grants_cannot_escape_workspace() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let workspace = dir.path().canonicalize()?;
        symlink(outside.path(), workspace.join("external"))?;
        for entry in ["external", "external/new/file", "external/../file"] {
            assert!(
                normalize_path(entry, &workspace).is_err(),
                "accepted {entry}"
            );
        }
        Ok(())
    }

    #[test]
    fn relative_symlink_parent_uses_resolved_target() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let workspace = dir.path().canonicalize()?;
        fs::create_dir_all(workspace.join("actual/child"))?;
        symlink(workspace.join("actual/child"), workspace.join("alias"))?;
        assert_eq!(
            normalize_path("alias/../new", &workspace)?,
            workspace.join("actual/new").to_string_lossy()
        );
        assert_eq!(
            normalize_path("alias/new/file", &workspace)?,
            workspace.join("actual/child/new/file").to_string_lossy()
        );
        Ok(())
    }

    #[test]
    fn unresolved_relative_paths_fail_closed() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let workspace = dir.path().canonicalize()?;
        symlink(workspace.join("missing"), workspace.join("dangling"))?;
        for entry in [
            "dangling/new",
            "missing/../new",
            "*/new",
            "dir?/new",
            "[ab]/new",
        ] {
            assert!(
                normalize_path(entry, &workspace).is_err(),
                "accepted {entry}"
            );
        }
        Ok(())
    }

    #[test]
    fn absolute_and_expandable_entries_pass_through_verbatim() {
        let profile =
            load_contents(r#"{"filesystem":{"read":["/usr","~/.cache/tool","$HOME/.npm"]}}"#)
                .expect("profile loads");
        let json = profile.to_json().expect("json");

        assert!(json.contains("\"/usr\""), "json: {json}");
        assert!(json.contains("~/.cache/tool"), "json: {json}");
        assert!(json.contains("$HOME/.npm"), "json: {json}");
    }

    #[test]
    fn braced_variables_are_rejected() {
        let error = rejection(r#"{"filesystem":{"read":["${HOME}/.cache"]}}"#);

        assert!(
            error.contains("is not expanded by nono"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn empty_filesystem_entry_is_rejected() {
        let error = rejection(r#"{"filesystem":{"read":["  "]}}"#);

        assert!(
            error.contains("must not be empty"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn jsonc_is_rejected_with_a_pointed_error() {
        let error = rejection("{\n  // a comment\n  \"network\": {}\n}");

        assert!(error.contains("strict JSON"), "unexpected error: {error}");
    }

    #[test]
    fn non_object_profile_is_rejected() {
        let error = rejection("[]");

        assert!(
            error.contains("must be a JSON object"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn missing_profile_is_an_error() {
        let dir = workspace();

        let err = load("runseal.json", dir.path()).expect_err("missing profile must fail");

        assert!(
            format!("{err:#}").contains("was not found"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn absolute_profile_input_is_rejected() {
        let dir = workspace();

        let err = load("/etc/passwd", dir.path()).expect_err("absolute input must fail");

        assert!(
            format!("{err:#}").contains("relative to the workspace"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn traversing_profile_input_is_rejected() {
        let dir = workspace();

        let err = load("../runseal.json", dir.path()).expect_err("traversal must fail");

        assert!(
            format!("{err:#}").contains("must not traverse"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn symlink_out_of_the_workspace_is_rejected() {
        let outside = workspace();
        let target = outside.path().join("evil.json");
        fs::write(&target, r#"{"filesystem":{"read":["/"]}}"#).expect("write target");
        let dir = workspace();
        symlink(&target, dir.path().join("runseal.json")).expect("symlink");

        let err = load("runseal.json", dir.path()).expect_err("symlink escape must fail");

        assert!(
            format!("{err:#}").contains("outside the workspace"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn directory_profile_is_rejected() {
        let dir = workspace();
        fs::create_dir(dir.path().join("runseal.json")).expect("create dir");

        let err = load("runseal.json", dir.path()).expect_err("directory must fail");

        assert!(
            format!("{err:#}").contains("not a regular file"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn oversized_profile_is_rejected() {
        let dir = workspace();
        let padding = "x".repeat(MAX_PROFILE_JSON_BYTES as usize);
        write_profile(
            dir.path(),
            &format!(r#"{{"meta":{{"description":"{padding}"}}}}"#),
        );

        let err = load("runseal.json", dir.path()).expect_err("oversized profile must fail");

        assert!(
            format!("{err:#}").contains("too large"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn schema_hint_is_accepted_and_dropped() {
        let profile =
            load_contents(r#"{"$schema":"https://nono.sh/schema.json"}"#).expect("profile loads");
        let json = profile.to_json().expect("json");

        assert!(!json.contains("$schema"), "json: {json}");
    }

    #[test]
    fn sibling_is_written_under_the_extended_name_and_is_private() {
        let profile = load_contents(r#"{"filesystem":{"read":["/usr"]}}"#).expect("profile loads");
        let dir = workspace();

        let path = profile.write_sibling(dir.path()).expect("write sibling");

        assert_eq!(path, dir.path().join("runseal-repo.json"));
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "sibling profile must not be readable by others"
        );
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read sibling")).expect("json");
        assert_eq!(written["filesystem"]["read"][0], "/usr");
    }
}
