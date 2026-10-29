# Scope and limitations

## Current preview scope

- rendered Kubernetes and Docker Compose deployment evidence
- OpenTelemetry and Jaeger/OpenTracing paths
- explicit OBI eBPF collection handoff without application SDK requirements
- named eBPF OTLP collector handoff without static kernel or protocol claims
- conservative inventory for Zipkin, Grafana Tempo, and Apache SkyWalking
- one synchronous HTTP operation
- exact Tracetest method/path matching
- current service inventory, operation-specific eligibility, and replica-aware eligibility

## Not currently assessed

- gRPC operation selection
- messaging and asynchronous workflows
- baseline/candidate release identity
- failure domains and placement groups
- runtime sampling, coverage, trace completeness, and reconciliation
- resilience policies such as retries, timeouts, circuit breakers, and fallback semantics
- release-gate eligibility

## Interpretation boundaries

`EXPECTED` means the required static path is present and Bering can attempt the requested discovery. It does not mean the eventual model is complete or trustworthy.

Backend-specific tracing can require an adapter in the collection stage. The adapter requirement is recorded in the collection plan. A missing application-to-backend link remains `UNKNOWN`, `ABSENT`, or `CONFLICT` and lowers the affected capability.

With `--collection-source ebpf-obi`, application SDK/exporter absence is not a
collection blocker. Static analysis cannot confirm OBI kernel access, process or
protocol coverage, OTLP delivery, observed service identity, or distributed
context. These remain `UNKNOWN`; Bering must inspect actual exports and signal
quality. Workload identity conflicts and missing deployment evidence still block
the corresponding capability.

With `--collection-source ebpf-otlp`, the required collector name identifies
the selected source but does not establish its capabilities. Static analysis
does not prove kernel compatibility, protocol or target support, actual process
coverage, OTLP delivery, service identity, or distributed context. These remain
`UNKNOWN` and require retained Bering runtime evidence.

Secret values are never resolved or printed. Their dependent facts remain `UNKNOWN`.
