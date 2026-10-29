# Contracts

Procrustes exposes three preview JSON/YAML contract families.
An explicit `ebpf-obi` collection selection emits the backward-compatible
report and collection-plan `0.2.0` contracts; the goal remains `0.1.0`.
A named `ebpf-otlp` collection selection emits report and collection-plan
`0.3.0` contracts.

## Goal

`io.mb3r.procrustes.goal@0.1.0` selects namespaces, scoped service identities, one HTTP operation, mandatory targets, and an optional scenario reference.

## Report

The `io.mb3r.procrustes.report@0.1.0` (native), `@0.2.0` (explicit OBI), and
`@0.3.0` (named eBPF OTLP collector) contracts contain:

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

The named collector `io.mb3r.procrustes.collection-plan@0.3.0` selects
`bering_input: ebpf-otlp`, records the validated collector name as `system`, and
adds the same deployment `domain`. The name states provenance only. Kernel
compatibility, protocol support, target coverage, delivery, and context remain
runtime unknowns.

## Bering overlay

The overlay contains only statically confirmed service identities, positive replica counts, and selected HTTP endpoint semantics. Procrustes never creates static edges and labels them as observed topology.

See [VERSIONING.md](../VERSIONING.md) for compatibility rules.
