# Security Policy

## Reporting a Vulnerability

**Do not report security issues publicly.**

* ❌ Do **not** open public GitHub issues for security vulnerabilities
* ❌ Do **not** disclose vulnerabilities in discussions, PRs, or social channels

Instead, report vulnerabilities **privately** via GitHub Security Advisories:

👉 https://github.com/nolabs-ai/runseal/security/advisories/new

This ensures:

* Coordinated disclosure
* Time to assess and remediate
* Protection for users and contributors

When submitting a report, include:

* Runseal and nono versions
* Runner OS and kernel version
* A minimal policy and reproduction using fake credentials
* Expected and actual behaviour
* The effective permission or documented security guarantee that was exceeded

Redact tokens, private repository data, and sensitive audit output.

Issues entirely within nono can be reported through [nono's private reporting
form](https://github.com/nolabs-ai/nono/security/advisories/new). If the
affected component is unclear, include that uncertainty in the report.

---

## Understand Runseal’s security model

Before reporting a security vulnerability, read the configuration and security
behaviour described in the [README](README.md).

A sandbox escape occurs when an untrusted process exceeds the authority granted
by its effective policy. Access explicitly granted by policy is not an escape.
Protected credential disclosure, policy bypass, or enforcement that fails open
may also constitute security vulnerabilities.

When submitting a report, identify the specific policy or documented security
guarantee that is bypassed.

## LLM-Generated Findings

If a vulnerability is identified by a Large Language Model (LLM):

* ❌ Do **not** report it blindly
* ✅ Ensure you **fully understand and can explain** the issue — humans with a
  security background will be corresponding with you.
* ✅ Validate the impact and reproducibility

Low-quality or speculative reports slow down response time and reduce overall
security effectiveness.

---

## Supported Versions

Security fixes target the latest published Runseal release. Older releases are
not maintained as separate security branches. Upgrade to the latest release and
its tested nono pin; overriding nono selects a combination that may not have
been tested together.

---

## Disclosure Policy

We aim to:

* Acknowledge reports promptly
* Investigate and validate findings
* Provide fixes or mitigations where possible
* Coordinate disclosure with reporters

### Safe Harbor

When conducting security research in good faith and in accordance with this policy, we consider your research to be authorized. We will not initiate legal action against you for research that adheres to these guidelines.

---

## Thank You

Responsible disclosure helps make this project safer for everyone.
