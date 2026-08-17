# Security Policy

## Supported versions

Procrustes is currently a preview built from source rather than a stable product release line.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Older commits or forks | Best effort only |

Security fixes may be made on `main` without backporting them to older commits.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for a suspected security vulnerability.

Use GitHub Private Vulnerability Reporting if it is available for this repository. Otherwise, report the issue by email to:

`contact@mb3r-lab.ru`

Please include, when possible:

- the affected commit;
- the affected command, parser, input type, or workflow;
- a minimal proof of concept or reproduction steps;
- the expected and observed behavior;
- your assessment of impact and attacker prerequisites.

Do not send production telemetry, credentials, private keys, customer data, or other sensitive material unless it is strictly necessary to reproduce the issue. Prefer a minimized synthetic fixture.

We will review security reports as promptly as practical and coordinate remediation and disclosure with the reporter. Please avoid public disclosure until a fix or mitigation has been coordinated.

## Security-sensitive areas

Procrustes is a deterministic local preflight that inspects deployment, tracing, operation-scenario, configuration, module, and source artifacts before Bering model discovery. Security-sensitive areas therefore include:

- recursive discovery and reading of files supplied through `--source`;
- parsing of rendered Kubernetes and Docker Compose artifacts;
- parsing of OpenTelemetry, tracing-backend, and Tracetest-related configuration;
- parsing and validation of the Procrustes goal contract;
- environment and configuration reference resolution;
- handling of secret-backed references;
- path, symlink, and output-directory handling;
- generation of `report.json`, `summary.md`, `collection-plan.json`, and `bering.overlay.yaml`;
- exit-code behavior when Procrustes is used as a CI preflight;
- GitHub Actions and release/build workflows.

## Security expectations

The following are intended security properties of Procrustes:

1. Input files are treated as data and must never be executed as a consequence of analysis.
2. Secret-backed values remain unavailable to Procrustes and must not be resolved, read, or printed by the analyzer.
3. A source path, scenario reference, manifest field, or other untrusted value must not permit access outside the intended input/output scope through path traversal or symlink confusion.
4. Malformed or adversarial input must fail safely rather than cause code execution, uncontrolled resource consumption, or unintended filesystem access.
5. Static evidence must not be silently upgraded into runtime proof. `UNKNOWN`, `ABSENT`, `CONFLICT`, and blocked capability states must remain distinguishable from confirmed evidence.
6. `bering.overlay.yaml` must remain a conservative static handoff and must not invent runtime topology edges.
7. Invalid input or execution failure must not be converted into a successful CI result merely because a normal diagnostic can report `BLOCKED` with exit code 0.
8. For fixed inputs and options, security-relevant contract behavior should be deterministic.

## What counts as a security issue

Examples include, but are not limited to:

- arbitrary file read or write;
- path traversal or unsafe symlink handling;
- unintended disclosure of secrets or sensitive configuration;
- parser-triggered code execution or panic with security impact;
- algorithmic denial of service from adversarial repository contents;
- crafted input that changes the meaning of evidence or bypasses a required capability check;
- CI result manipulation across a documented trust boundary;
- compromise of release artifacts, build workflows, or credentials.

A disagreement about whether Procrustes correctly models a particular deployment is normally a correctness issue rather than a security vulnerability unless an attacker can use it to cross a trust boundary, bypass a required check, disclose data, or deny service.
