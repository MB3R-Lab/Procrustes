# Contracts

Procrustes currently exposes three preview JSON/YAML contracts at `0.1.0`.
An explicit `ebpf-obi` collection selection emits the backward-compatible
report and collection-plan `0.2.0` contracts; the goal remains `0.1.0`.

## Goal

`io.mb3r.procrustes.goal@0.1.0` selects namespaces, scoped service identities, one HTTP operation, mandatory targets, and an optional scenario reference.

## Report

Both `io.mb3r.procrustes.report@0.1.0` (native) and `@0.2.0` (explicit OBI) contain:

- source fingerprint and normalized goal
- per-service facts and detected tracing systems
- operation facts and capability decisions
- blockers, remediation, owners, evidence, and limitations
- the embedded collection plan

The report is diagnostic evidence, not a release verdict.

## Collection plan

The native `io.mb3r.procrustes.collection-plan@0.1.0` tells Bering what runtime evidence to collect:

- selected operation and expected services
- reproducible scenarios
- backend-specific trace source and required adapter, when applicable
- required and recommended telemetry attributes
- known static limitations
- the adjacent Bering overlay filename

The explicit OBI `io.mb3r.procrustes.collection-plan@0.2.0` keeps those fields
and selects `bering_input: ebpf-obi`, adding the deployment `domain` shared by
its agents. These values record operator intent, not observed coverage. The
corresponding report keeps runtime collection facts `UNKNOWN` until measured.

## Bering overlay

The overlay contains only statically confirmed service identities, positive replica counts, and selected HTTP endpoint semantics. Procrustes never creates static edges and labels them as observed topology.

See [VERSIONING.md](../VERSIONING.md) for compatibility rules.
