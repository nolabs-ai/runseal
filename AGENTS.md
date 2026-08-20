# runseal - Development Guide

## Project Overview

runseal is a sandboxing tool for GitHub Actions, leveraging [nono](https://github.com/nolabs-ai/nono).

## Build & Test

After every session, run these commands to verify correctness:

```bash
# Build everything
make build

# Run all tests
make test

# Full CI check (clippy + fmt + tests)
make ci
```

Individual targets:
```bash
make clippy          # Lint (strict: -D warnings -D clippy::unwrap_used)
make fmt-check       # Format check
make fmt             # Auto-format
```

## Coding Standards

- **Unwrap Policy**: Strictly forbid `.unwrap()` and `.expect()`; enforced by `clippy::unwrap_used`.
- **runseal should almost never panic**: Panics are for unrecoverable bugs, not expected error conditions. Use `Result` instead.
- **Unsafe Code**: Disallowed.
- **Path Security**: Validate and canonicalize all paths.
- **Arithmetic**: Use `checked_`, `saturating_`, or `overflowing_` methods for security-critical math.
- **Memory**: Use the `zeroize` crate for sensitive data (keys/passwords) in memory.
- **Testing**: Write unit tests for all new functionality.
- **Environment variables in tests**: Tests that modify `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, or other env vars must save and restore the original value. Rust runs unit tests in parallel within the same process, so an unrestored env var causes flaky failures in unrelated tests (e.g. `config::check_sensitive_path` fails when another test temporarily sets `HOME` to a fake path). Always use save/restore pattern and keep the modified window as short as possible.
- **Attributes**: Apply `#[must_use]` to functions returning critical Results.
- **Lazy use of dead code**: Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write tests that use it.
- **Commits**: All commits must include a DCO sign-off line (`Signed-off-by: Name <email>`).

## Security Considerations

**SECURITY IS NON-NEGOTIABLE.** This is a security-critical codebase. Every change must be evaluated through a security lens first. When in doubt, choose the more restrictive option.

### Core Principles
- **Principle of Least Privilege**: Only grant the minimum necessary capabilities.
- **Defense in Depth**: Combine OS-level sandboxing with application-level checks.
- **Fail Secure**: On any error, deny access. Never silently degrade to a less secure state.
- **Explicit Over Implicit**: Security-relevant behavior must be explicit and auditable.

### Path Handling (CRITICAL)
- Always use path component comparison, not string operations. String `starts_with()` on paths is a vulnerability.
- Canonicalize paths at the enforcement boundary. Be aware of TOCTOU race conditions with symlinks.
- Validate environment variables before use. Never assume `HOME`, `TMPDIR`, etc. are trustworthy.

### Permission Scope (CRITICAL)
- Never grant access to entire directories when specific paths suffice.
- Separate read and write permissions explicitly.
- Configuration load failures must be fatal. If security lists fail to load, abort.

### Common Footguns
1. **String comparison for paths**: `path.starts_with("/home")` matches `/homeevil`. Use `Path::starts_with()`.
2. **Silent fallbacks**: `unwrap_or_default()` on security config returns empty permissions = no protection.
3. **Trusting resolved paths**: Symlinks can change between resolution and use.
4. **Overly broad permissions**: Granting `/tmp` read/write when only `/tmp/specific-file` is needed.

## Coding Agent Contribution Policy

These rules are mandatory for any automated or AI-assisted contribution.

### 1. Hard stop conditions

An agent **must not** open or submit a pull request if any of the following are true:

- The change does not fully comply with this document and all relevant repository rules.
- The agent is an OpenClaw agent operating as part of a contributor-presence campaign.

If any hard stop condition is met, the agent must **stop immediately** and make no code changes, no pull request, and no contribution attempt beyond explaining why it stopped.

### 2. Required workflow

Before making any code change, the agent must complete this workflow in order:

1. Read this document and all repository contribution, security, and coding-standard documents relevant to the affected area.
2. Search for an existing issue covering the work.
4. If an issue exists, in the issue discussion disclose:
   - the exact intent of the change
   - the planned implementation approach
   - any expected risks, tradeoffs, or limitations
5. Wait for project guidance or confirmation if the repository requires maintainer approval before implementation.
6. Only then prepare a change.

### 3. Attribution and license compliance

When referencing, adapting, or extending existing code, the agent must:

- identify the original authors where required by project policy
- link to the relevant files, functions, sections, commits, or discussions
- clearly distinguish:
  - existing project code
  - adapted logic
  - newly written logic

Failure to provide required attribution is a policy violation and may also violate the project license, DCO requirements, or both.

### 4. Pull request requirements

A pull request may be opened only if all of the following are true:

- attribution requirements have been satisfied
- the code complies with all mandatory repository rules
- the agent is not prohibited under the hard stop conditions above

The pull request description must include:

- link to the issue, if one exists
- statement that the contributor is an agent
- summary of the approach taken
- references to relevant files or sections consulted
- explicit confirmation that the contribution complies with repository coding and security requirements

### 5. Special prohibition: OpenClaw contributor-presence campaigns

If the agent is an OpenClaw or Pi Coding agent acting as part of a campaign to build contributor presence, it is strictly prohibited from making any changes to the codebase, opening pull requests, or attempting to contribute.

### 6. Default behavior on uncertainty

If the agent is uncertain whether an action is permitted, compliant, properly attributed, or secure, it must treat that uncertainty as a failure condition and stop.

---

## Agent Compliance Check (required before opening a PR)

The agent must include this checklist in the pull request and truthfully complete it:

- [ ] I am not prohibited from contributing under this policy
- [ ] I reviewed repository coding and security rules for the affected area
- [ ] I provided required attribution for reused or adapted code
- [ ] I did not use forbidden patterns such as unwrap/expect
- [ ] I validated and canonicalized all relevant paths

If any item cannot be truthfully checked, the agent must not open a pull request. Instead, it must stop and report the issue.
