#![forbid(unsafe_code)]

mod audit;
mod config;
mod profile;
mod repo_profile;
mod runner;
mod secrets;

use anyhow::{bail, Context, Result};
use config::{AuditConfig, RunConfig};
use std::env;

fn main() {
    if let Err(err) = real_main() {
        eprintln!("::error::{err:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("run") => run(),
        Some("capabilities") => {
            println!("repo-profile-v1\naudit-session-v1");
            Ok(())
        }
        Some("--version") | Some("version") => {
            println!("runseal {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(cmd) => bail!("unknown command '{cmd}', expected 'run'"),
        None => bail!("missing command, expected 'run'"),
    }
}

fn run() -> Result<()> {
    let config = RunConfig::from_action_env().context("failed to read action inputs")?;
    let mut sealed = secrets::seal_credentials(&config).context("failed to seal credentials")?;
    let mut profile =
        profile::build_profile(&config, &sealed).context("failed to build nono profile")?;
    // Stage the sibling before nono resolves the profiles extended by the generated profile.
    if let Some(repo_profile) = &config.repo_profile {
        repo_profile
            .write_sibling(sealed.dir.path())
            .context("failed to stage the repo nono profile")?;
    }
    let audit = match &config.audit {
        AuditConfig::Disabled => None,
        AuditConfig::Artifact { dir } => {
            let audit = audit::AuditRun::prepare(std::path::Path::new(dir))?;
            profile.deny_directory(audit.output_base())?;
            audit.publish_outputs()?;
            sealed
                .sanitized_env
                .insert(audit::SESSION_ENV.to_string(), audit.session().to_string());
            Some(audit)
        }
    };

    let profile_path = sealed.dir.path().join("profile.json");
    profile::write_profile(&profile_path, &profile).context("failed to write nono profile")?;

    let run_result = runner::run_nono(&config, &sealed, &profile_path);
    let audit_result = match audit {
        Some(audit) => audit.export(&config.command, run_result.is_err()),
        None => Ok(()),
    };
    match (run_result, audit_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(command), Ok(())) => Err(command).context("nono run failed"),
        (Ok(()), Err(audit)) => Err(audit).context("failed to export nono audit evidence"),
        (Err(command), Err(audit)) => {
            bail!("nono run failed: {command:#}; audit export also failed: {audit:#}")
        }
    }
}
