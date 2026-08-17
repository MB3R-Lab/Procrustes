# Threat Model

## 1. Scope

This threat model covers the current Procrustes preview and its role at the beginning of the MB3R toolchain:

```text
repository / deployment / tracing / scenario artifacts
                    |
                    v
               Procrustes
                    |
          +---------+----------+
          |                    |
          v                    v
 collection-plan.json   bering.overlay.yaml
          |                    |
          +---------+----------+
                    |
                    v
                  Bering
```

Procrustes is a **local static eligibility preflight**. It does not accept traces, logs, or metrics, does not discover runtime edges, does not simulate failures, and does not produce a release verdict.

The primary security question is therefore:

> Can untrusted or compromised repository/deployment artifacts make Procrustes read or disclose data it should not access, consume unreasonable resources, corrupt its evidence classification, or emit a misleading handoff to Bering or CI?

## 2. Security-relevant behavior

Procrustes currently:

- accepts one or more `--source <alias>=<path>` inputs;
- accepts a goal contract through `--goal`;
- inspects supported manifests, configuration, modules, source files, or directories;
- resolves deployable services, images, identities, entrypoints, and replica counts from rendered Kubernetes or Docker Compose artifacts;
- checks tracing prerequisites without collecting telemetry;
- matches a requested HTTP operation to a reproducible Tracetest scenario;
- classifies evidence using explicit states such as `CONFIRMED`, `DECLARED`, `UNKNOWN`, `ABSENT`, and `CONFLICT`;
- emits `report.json`, `summary.md`, `collection-plan.json`, and `bering.overlay.yaml`;
- can return a non-zero code for blocked selected capabilities when `--fail-on-blocked` is enabled.

Secret-backed and unavailable values are intentionally left `UNKNOWN` rather than read or printed.

## 3. Assets

The assets to protect are:

1. **Confidentiality of the analyzed workspace** — source files, manifests, configuration, environment-derived values, and any secrets that are referenced but not intended to be read.
2. **Integrity of evidence classification** — a malicious input must not silently turn `UNKNOWN`, `ABSENT`, or `CONFLICT` into confirmed evidence.
3. **Integrity of the Bering handoff** — `collection-plan.json` and `bering.overlay.yaml` must represent only the permitted static facts.
4. **CI decision integrity** — when Procrustes is used in automation, malformed input must not accidentally produce a trusted success state.
5. **Availability of the analysis process** — a repository or manifest should not trivially cause unbounded CPU, memory, filesystem, or output growth.
6. **Integrity of release/build artifacts and workflows**.

## 4. Trust boundaries

### TB1 — Repository or artifact tree -> Procrustes

A source directory may contain files controlled by an untrusted contributor, compromised dependency, generated deployment pipeline, or malicious pull request.

Treat filenames, paths, symlinks, file sizes, nesting depth, YAML/JSON values, environment references, service names, image names, annotations, and scenario references as untrusted.

### TB2 — Goal contract -> Procrustes

The goal contract controls the scope, operation, entry service, mandatory targets, and optional scenario reference. A crafted goal can attempt to trigger excessive work, path confusion, or semantic ambiguity.

### TB3 — Procrustes -> local filesystem

`--out-dir` causes Procrustes to write multiple artifacts. Output creation must not overwrite unintended files, follow unsafe symlinks, or escape the intended output root.

### TB4 — Procrustes -> CI

A normal diagnostic may legitimately return exit code 0 even when a capability is `BLOCKED`; `--fail-on-blocked` changes this behavior. CI integrations must not confuse a completed diagnostic with a positive eligibility result.

### TB5 — Procrustes -> Bering

`collection-plan.json` and `bering.overlay.yaml` cross from static preflight into runtime discovery. Bering must continue to validate runtime evidence independently; the handoff must not be capable of asserting discovered runtime edges that Procrustes does not own.

### TB6 — Source/build pipeline -> distributed Procrustes binary

GitHub Actions, Go dependencies, release automation, checksums, and any future package distribution form the software supply-chain boundary.

## 5. Threat actors

Relevant actors include:

- an attacker submitting a malicious pull request to a repository where Procrustes runs in CI;
- a compromised build or deployment system producing crafted Kubernetes or Compose artifacts;
- a malicious local user able to choose analysis inputs or output paths;
- a compromised dependency or CI action;
- accidental pathological input with the same effect as an attack.

The model does not assume that ordinary source or deployment artifacts are trustworthy merely because they are syntactically valid.

## 6. Threats and abuse cases

### T1 — Arbitrary file read through path traversal

A crafted source path, `scenario_ref`, included configuration reference, or discovered path may attempt to escape the intended source root and read arbitrary local files.

**Desired controls:** canonical path checks, explicit root ownership, safe handling of relative paths, rejection of path escapes.

### T2 — Symlink or filesystem-race escape

A malicious source tree may use symlinks, hard links, or replacement races to make a scanner read files outside the analyzed workspace or overwrite unintended files under `--out-dir`.

**Desired controls:** documented symlink policy, canonicalization before access, safe output creation, and tests covering link/race cases where applicable.

### T3 — Secret disclosure through reference resolution

Kubernetes manifests may reference Secrets or unavailable environment values. A regression could attempt to resolve or print values that should remain `UNKNOWN`.

**Desired controls:** explicit tests that secret-backed references are never dereferenced or rendered; log/output redaction for sensitive fields.

### T4 — Parser denial of service

Deeply nested, very large, highly repetitive, or otherwise adversarial YAML/JSON/source trees may cause excessive CPU, memory, recursion, or output growth.

**Desired controls:** practical size/count/depth limits, streaming or bounded parsing where appropriate, cancellation/timeouts in CI contexts, fuzzing, and resource-regression tests.

### T5 — Evidence-state confusion

Crafted artifacts may exploit duplicate definitions, conflicting service identities, ambiguous references, or parser edge cases so that uncertain evidence is incorrectly treated as confirmed.

**Desired controls:** explicit conflict semantics, deterministic precedence rules, duplicate detection, property tests around evidence-state transitions.

### T6 — Static-to-runtime authority escalation

A crafted source may try to make Procrustes emit runtime topology as if it had been observed, bypassing Bering's responsibility for runtime discovery.

**Desired controls:** schema-level constraints and tests ensuring the overlay contains only confirmed static facts and never discovered runtime edges.

### T7 — CI bypass through exit-code semantics

An integration may treat exit code 0 as “eligible” even though Procrustes uses 0 for a completed diagnostic that may contain `BLOCKED` results.

**Desired controls:** clear documentation, `--fail-on-blocked` for enforcing pipelines, machine-readable final capability state, integration tests for exit codes.

### T8 — Terminal/log/Markdown injection

User-controlled service names, paths, annotations, or configuration values may be copied into logs or `summary.md`, potentially creating terminal escape sequences, misleading CI annotations, or unsafe rendered output.

**Desired controls:** context-appropriate escaping, sanitization, and tests for control characters and markup-sensitive content.

### T9 — Output overwrite or path collision

A crafted alias, goal value, or output configuration could cause generated files to collide with existing files or escape the intended output directory.

**Desired controls:** fixed filenames under a validated output root, safe create/replace semantics, clear overwrite policy.

### T10 — Supply-chain compromise

A compromised Go dependency, GitHub Action, release credential, or build workflow could alter the analyzer or distributed artifact.

**Desired controls:** pinned/reviewed Actions, dependency scanning, least-privilege workflow permissions, reproducible build practices where feasible, provenance/checksum strategy.

## 7. Security invariants

The following invariants should remain true across releases:

1. Procrustes never needs runtime telemetry to make a static eligibility decision.
2. Secret-backed values remain `UNKNOWN` and are never read or printed by design.
3. Untrusted input is never executed.
4. Static evidence cannot silently become runtime-discovered topology.
5. Conflicting or missing evidence stays explicit rather than being coerced into confirmation.
6. Output paths remain inside the intended output scope.
7. A malformed input cannot silently produce a trusted eligibility result.
8. The Bering handoff remains deterministic for fixed valid inputs.
9. A blocked selected capability can be made enforceable in CI with `--fail-on-blocked`.

## 8. Recommended security testing

High-value work includes:

- Go fuzz targets for YAML/JSON/Compose/Kubernetes/goal/scenario parsers;
- property tests for evidence-state monotonicity and conflict handling;
- filesystem tests for `..`, absolute paths, symlinks, broken links, and output collisions;
- fixtures proving that Secret references are never dereferenced;
- pathological-depth/cardinality/size tests;
- tests for terminal and Markdown control characters;
- `govulncheck`, static analysis, and dependency review in CI;
- GitHub Actions permission and third-party action pinning review.

## 9. Out of scope

The following are not security vulnerabilities by themselves:

- Procrustes reporting that static evidence is insufficient for Bering;
- disagreement over whether a particular topology can be inferred at runtime;
- model-discovery or resilience-simulation accuracy after the handoff;
- unsupported deployment formats documented as outside the preview scope.

They become security-relevant only when an attacker can use them to violate confidentiality, integrity, availability, or a documented trust boundary.
