# Block npm Preinstall And Postinstall Exfiltration

Malicious npm packages often use lifecycle scripts such as `preinstall`,
`install`, and `postinstall` to run code during dependency installation. In CI,
that code can try to read repository files, environment variables, or generated
artifacts and send them to an attacker-controlled endpoint.

This recipe runs dependency installation with direct network access blocked, so
unexpected lifecycle-script network calls fail inside the sandbox.

## Workflow File

Use [workflow.yml](workflow.yml) as the copyable workflow example for this
recipe.

For a released version of Runseal, replace:

```yaml
uses: nolabs-ai/runseal@main
```

with the current release tag.

## Minimal Workflow

```yaml
name: npm install with Runseal

on:
  workflow_dispatch:
  pull_request:

permissions:
  contents: read

jobs:
  install:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v6
        with:
          persist-credentials: false

      - name: Install dependencies without lifecycle scripts
        uses: nolabs-ai/runseal@main
        with:
          run: npm ci --ignore-scripts
          policy: |
            fs:
              read: ["."]
              write: ["./node_modules"]
            network:
              mode: filtered
              allow:
                - registry.npmjs.org
```

## What This Defends Against

This blocks the most common lifecycle-script path entirely by using:

```bash
npm ci --ignore-scripts
```

That means package `preinstall`, `install`, and `postinstall` scripts do not
run during dependency installation.

Runseal also limits the install step:

- repository files can be read
- only `./node_modules` can be written
- direct network is blocked
- only `registry.npmjs.org` is allowed for package downloads
- the GitHub checkout token is not persisted into `.git/config`

## Stronger Two-Phase Pattern

Some projects need lifecycle scripts for native builds or generated assets. In
that case, split dependency fetching from script execution.

```yaml
- name: Fetch npm dependencies
  uses: nolabs-ai/runseal@main
  with:
    run: npm ci --ignore-scripts
    policy: |
      fs:
        read: ["."]
        write: ["./node_modules"]
      network:
        mode: filtered
        allow:
          - registry.npmjs.org

- name: Run required package scripts without network
  uses: nolabs-ai/runseal@main
  with:
    run: npm rebuild
    policy: |
      fs:
        read: [".", "./node_modules"]
        write: ["./node_modules"]
      network:
        mode: blocked
```

The second step allows build scripts to run, but gives them no network. If a
dependency script tries to exfiltrate data with `curl`, `node fetch`, DNS, or a
package-specific telemetry client, the request should fail.

## What This Does Not Solve

This recipe does not prove a package is safe. It reduces the blast radius of
dependency installation in CI.

It also does not replace lockfile review, dependency pinning, provenance checks,
or package-manager audit tooling. Use those controls alongside Runseal.

## Expected Result

For normal installs, the first workflow should complete successfully.

If a package lifecycle script attempts a network call during the blocked phase,
the Runseal/nono step should fail with a sandbox or network denial rather than
allowing the request to leave the runner.
