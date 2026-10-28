# Procrustes

[![checks](https://img.shields.io/github/actions/workflow/status/MB3R-Lab/Procrustes/ci.yml?branch=main&label=checks)](https://github.com/MB3R-Lab/Procrustes/actions/workflows/ci.yml)
[![contracts](https://img.shields.io/badge/preview%20contracts-0.1.0-blue)](VERSIONING.md)

## Related MB3R repositories

Procrustes prepares a static eligibility handoff for [Bering](https://github.com/MB3R-Lab/Bering), which owns runtime model discovery and publishes topology artifacts. [Sheaft v1.3.1](https://github.com/MB3R-Lab/Sheaft/releases/tag/v1.3.1) consumes Bering artifacts for resilience analysis and CI/CD decisions.

[mb3r-stack](https://github.com/MB3R-Lab/mb3r-stack) packages a source-pinned Procrustes preflight launcher alongside the Bering/Sheaft integration bundle; Procrustes is not a persistent Kubernetes service. The [separate reproduction repository](https://github.com/MB3R-Lab/mb3r-software-complex-repro) contains the versioned three-tool demonstration, experiment inputs, and reference results.

Procrustes is a deterministic local preflight. It checks whether deployment, tracing, and reproducible-operation artifacts provide enough static evidence for Bering to attempt an operation-specific, replica-aware model.

## Research and evidence

- DeathStarBench empirical anchor: [Model Discovery and Graph Simulation: A Lightweight Gateway to Chaos Engineering](https://www.alphaxiv.org/abs/2506.11176)
- Formal model: [Stochastic Connectivity as the Foundation of a Runtime Model for Microservice Availability Analysis](https://www.alphaxiv.org/abs/2607.00740)
- OpenTelemetry Demo case study: [Evaluating Asynchronous Semantics in Trace-Discovered Resilience Models](https://www.alphaxiv.org/abs/2512.12314v1)

## What Procrustes does

- resolves deployable services, images, identities, entrypoints, and replica counts from rendered Kubernetes or Docker Compose artifacts
- checks OpenTelemetry and backend-specific tracing prerequisites without collecting telemetry
- matches an exact HTTP operation to a reproducible Tracetest scenario
- reports evidence as `CONFIRMED`, `DECLARED`, `UNKNOWN`, `ABSENT`, or `CONFLICT`
- evaluates `service_inventory`, `candidate_topology`, `operation_specific_model`, and `replica_aware_model`
- emits a deterministic collection plan and a conservative Bering overlay

## Where Procrustes stops

Procrustes never accepts traces, logs, or metrics. It does not discover runtime edges, estimate coverage or sampling quality, reconcile topology, simulate failures, or produce a release verdict.

- Bering owns runtime evidence, topology discovery, signal quality, and reconciliation.
- Sheaft owns resilience simulation, diagnostics, and gating.

## Installation

The current preview is built from source:

```bash
go build -trimpath -o bin/procrustes ./cmd/procrustes
```

On Windows, the binary is `bin/procrustes.exe`.

## Quickstart

```bash
go run ./cmd/procrustes analyze \
  --source ready=testdata/ready \
  --goal testdata/ready/goal.yaml \
  --out-dir out/preflight \
  --fail-on-blocked
```

General form:

```text
procrustes analyze --source <alias>=<path> [--source ...] --goal <goal.yaml> --out-dir <dir> [--collection-source native|ebpf-obi] [--source-domain <deployment>] [--fail-on-blocked]
```

A source can be a directory or a supported manifest, configuration, module, or source file. Explicit aliases keep evidence paths stable across machines.

### Explicit OBI eBPF collection

Select `--collection-source ebpf-obi` when an external OBI installation will
export OTLP traces. This option does not deploy OBI, require an application SDK,
or certify that the kernel, processes, protocols, and trace context are covered.
Procrustes records these runtime questions as `UNKNOWN`; the selected capability
remains `PARTIAL` when deployment and operation facts are otherwise valid.
Confirmed workload identities and real conflicts remain visible. The default
`native` selection keeps its existing SDK, exporter, and propagation checks.

```text
procrustes analyze --source deployment=./manifests --goal goal.yaml \
  --collection-source ebpf-obi --source-domain production --out-dir preflight

bering discover --input ./obi-capture --input-type ebpf-obi \
  --source-domain production --overlay preflight/bering.overlay.yaml \
  --out model.json --snapshot-out snapshot.json
```

The collection plan records `bering_input: ebpf-obi` and `domain: production`.
For continuous ingest, configure Bering 1.1.0 with a declared source, then point
the external OBI OTLP/HTTP exporter at its source-scoped endpoint:

```yaml
sources:
  - id: obi-main
    type: ebpf-obi
    domain: production
    capture_directory: /var/lib/bering/obi-capture
```

`POST /sources/obi-main/v1/traces` is the Bering endpoint. Use the same domain
for agents in one collection deployment; it is not a host or replica label.
The collection plan is a handoff instruction. Only Bering's accepted exports,
observed identities, and signal quality can establish actual coverage.

## Outputs

- `report.json` — facts, capability decisions, blockers, remediation, evidence, and limitations
- `summary.md` — concise operator-facing result
- `collection-plan.json` — operation, expected services, scenario, trace source, and required attributes for Bering
- `bering.overlay.yaml` — confirmed service identities, replicas, and HTTP endpoint semantics; never static topology edges

A completed diagnostic returns `0`, including a `BLOCKED` result. `--fail-on-blocked` returns `2` for a blocked selected capability. Invalid input and execution errors return `1`.

## Goal contract

```yaml
contract:
  name: io.mb3r.procrustes.goal
  version: 0.1.0
scope:
  namespaces: [default]
  services: [frontend, checkout]
operation:
  id: checkout
  entry_service: frontend
  method: GET
  path: /checkout
  mandatory_targets: [checkout]
  scenario_ref: checkout.yaml
```

`scenario_ref` is optional. Without it, any Tracetest HTTP scenario with the exact method and path is eligible. The entry service and mandatory targets must be listed in `scope.services`.

The preview contracts are documented in [VERSIONING.md](VERSIONING.md) and [docs/contracts.md](docs/contracts.md).

## Supported evidence

### Deployment

- rendered Kubernetes `Deployment`, `StatefulSet`, `DaemonSet`, `Service`, and `ConfigMap`
- OpenTelemetry Operator `Instrumentation`
- rendered Docker Compose services, images, published ports, mounted tracing configuration, and default or declared replicas

Kubernetes environment resolution supports literals, downward API `fieldRef`, available `configMapKeyRef`, and `$(VAR)` references. Secret-backed and unavailable values remain `UNKNOWN` and are never read or printed.

### Tracing

- OpenTelemetry identity, SDK or Operator instrumentation basis, OTLP exporter, Collector traces pipeline, and W3C propagation
- explicit OBI collection selection with static deployment and operation checks; runtime eBPF coverage remains unknown
- Jaeger/OpenTracing backend, configuration, literal service identity, initialization, and propagation
- conservative inventory evidence for Zipkin, Grafana Tempo, and Apache SkyWalking

Source evidence is not runtime proof. A complete backend-specific path can be `EXPECTED`, while the collection plan still records the adapter Bering needs for normalization.

### Operation

The preview supports one synchronous HTTP operation and an exact Tracetest method/path match.

## Status model

- `EXPECTED` — mandatory static conditions are present; Bering can attempt the requested capability
- `PARTIAL` — no hard contradiction, but at least one required value or link remains unknown
- `BLOCKED` — a mandatory condition is absent or conflicting
- `NOT_ASSESSED` — the available evidence cannot distinguish absence from missing input

There is intentionally no aggregate readiness score. Each finding identifies evidence, affected capability, minimum remediation, and action owner.

## Acceptance fixtures

- OpenTelemetry Demo checkout over rendered Kubernetes/OpenTelemetry artifacts
- DeathStarBench Hotel Reservation over Kubernetes/Jaeger/OpenTracing
- DeathStarBench Social Network compose-post over Docker Compose/Jaeger/OpenTracing

Runtime coverage and discovered topology remain Bering-stage checks in every fixture.

## Development

```bash
make run-checks
```

Direct equivalents:

```bash
gofmt -l ./cmd ./internal
go vet ./...
go test ./...
go build -trimpath ./cmd/procrustes
```

## Documentation

- [Architecture](docs/architecture.md)
- [Contracts](docs/contracts.md)
- [Scope and limitations](docs/scope-and-limitations.md)
- [Versioning](VERSIONING.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## License

MIT (see [LICENSE](LICENSE)).
