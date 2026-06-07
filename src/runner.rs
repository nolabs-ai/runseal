use crate::config::{NetworkPolicy, RunConfig};
use crate::secrets::SealedCredentials;
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn run_nono(config: &RunConfig, sealed: &SealedCredentials, profile_path: &Path) -> Result<()> {
    let trusted_system_reads = trusted_system_read_paths();
    println!("::group::runseal sandbox configuration");
    println!(
        "  filesystem read:  {}",
        display_list(&config.fs_read, "<workspace>")
    );
    println!(
        "  system read:      {}",
        display_list(&trusted_system_reads, "<nono defaults>")
    );
    println!(
        "  filesystem write: {}",
        display_list(&config.fs_write, "<none>")
    );
    let fs_args = fs_args(config, &trusted_system_reads)?;
    println!("  nono fs args:     {}", display_fs_args(&fs_args));
    println!("  direct network:   {}", display_network(&config.network));
    println!(
        "  credential proxy: {}",
        display_credential_proxy(sealed.access.len())
    );
    println!("  access grants:    {} configured", sealed.access.len());
    println!("  nono profile:     {}", profile_path.display());
    println!("::endgroup::");

    let mut command = Command::new("nono");
    command
        .arg("run")
        .arg("--no-rollback")
        .arg("--no-diagnostics")
        .arg("--profile")
        .arg(profile_path);

    for (flag, path) in &fs_args {
        command.arg(flag).arg(path);
    }

    command.arg("--").arg("bash").arg("-c").arg(&config.command);
    command.env_clear().envs(&sealed.sanitized_env);

    let status = command.status().context("failed to spawn nono")?;
    if !status.success() {
        bail!("nono exited with status {status}");
    }
    Ok(())
}

fn fs_args(
    config: &RunConfig,
    trusted_system_reads: &[String],
) -> Result<Vec<(&'static str, String)>> {
    let mut args = Vec::new();
    let mut seen = BTreeSet::new();
    for path in &config.fs_read {
        push_fs_arg(&mut args, &mut seen, path, FsAccess::Read)?;
    }
    for path in trusted_system_reads {
        push_fs_arg(&mut args, &mut seen, path, FsAccess::Read)?;
    }
    for path in &config.fs_write {
        push_fs_arg(&mut args, &mut seen, path, FsAccess::Write)?;
    }
    Ok(args)
}

fn push_fs_arg(
    args: &mut Vec<(&'static str, String)>,
    seen: &mut BTreeSet<(FsAccess, String)>,
    path: &str,
    access: FsAccess,
) -> Result<()> {
    let normalized = path.to_string();
    if !seen.insert((access, normalized.clone())) {
        return Ok(());
    }
    args.push((fs_flag(path, access)?, normalized));
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FsAccess {
    Read,
    Write,
}

#[cfg(target_os = "linux")]
fn trusted_system_read_paths() -> Vec<String> {
    [
        "/bin", "/lib", "/lib64", "/sbin", "/usr", "/etc/ssl", "/etc/pki",
    ]
    .iter()
    .filter(|path| Path::new(path).exists())
    .map(|path| (*path).to_string())
    .collect()
}

#[cfg(not(target_os = "linux"))]
fn trusted_system_read_paths() -> Vec<String> {
    Vec::new()
}

fn fs_flag(path: &str, access: FsAccess) -> Result<&'static str> {
    let path = PathBuf::from(path);
    if path.exists() {
        if path.is_dir() {
            return Ok(match access {
                FsAccess::Read => "--read",
                FsAccess::Write => "--write",
            });
        }
        if path.is_file() {
            return Ok(match access {
                FsAccess::Read => "--read-file",
                FsAccess::Write => "--write-file",
            });
        }
        bail!(
            "filesystem policy path '{}' exists but is neither a regular file nor directory",
            path.display()
        );
    }

    match access {
        FsAccess::Read => bail!(
            "filesystem read path '{}' does not exist; create it first or allow an existing parent directory",
            path.display()
        ),
        FsAccess::Write => Ok("--write"),
    }
}

fn display_list(values: &[String], empty: &str) -> String {
    if values.is_empty() {
        empty.to_string()
    } else {
        values.join(", ")
    }
}

fn display_fs_args(args: &[(&'static str, String)]) -> String {
    if args.is_empty() {
        return "<none>".to_string();
    }

    args.iter()
        .map(|(flag, path)| format!("{flag} {path}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn display_network(network: &NetworkPolicy) -> String {
    match network {
        NetworkPolicy::Blocked => "blocked".to_string(),
        NetworkPolicy::AllowDomains(domains) => domains.join(", "),
    }
}

fn display_credential_proxy(credential_count: usize) -> &'static str {
    if credential_count == 0 {
        "disabled"
    } else {
        "enabled for sealed credential routes"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn read_directory_uses_read_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            fs_flag(path_str(dir.path()), FsAccess::Read).unwrap(),
            "--read"
        );
    }

    #[test]
    fn read_file_uses_read_file_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("allowed.txt");
        fs::write(&file, "allowed").expect("write file");

        assert_eq!(
            fs_flag(path_str(&file), FsAccess::Read).unwrap(),
            "--read-file"
        );
    }

    #[test]
    fn write_directory_uses_write_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            fs_flag(path_str(dir.path()), FsAccess::Write).unwrap(),
            "--write"
        );
    }

    #[test]
    fn write_file_uses_write_file_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("result.txt");
        fs::write(&file, "old").expect("write file");

        assert_eq!(
            fs_flag(path_str(&file), FsAccess::Write).unwrap(),
            "--write-file"
        );
    }

    #[test]
    fn missing_read_path_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing.txt");

        let err = fs_flag(path_str(&missing), FsAccess::Read).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn fs_args_adds_trusted_system_reads_without_duplication() {
        let dir = tempfile::tempdir().expect("tempdir");
        let trusted = dir.path().join("trusted");
        fs::create_dir(&trusted).expect("trusted dir");
        let trusted = path_str(&trusted).to_string();
        let config = RunConfig {
            command: "true".to_string(),
            fs_read: vec![trusted.clone()],
            fs_write: Vec::new(),
            network: NetworkPolicy::Blocked,
            access: Vec::new(),
            audit: crate::config::AuditConfig::Disabled,
        };

        let args = fs_args(&config, std::slice::from_ref(&trusted)).expect("fs args");
        let matching = args.iter().filter(|(_, path)| path == &trusted).count();

        assert_eq!(matching, 1);
        assert_eq!(args[0], ("--read", trusted));
    }

    fn path_str(path: &Path) -> &str {
        path.to_str().expect("test path utf-8")
    }
}
