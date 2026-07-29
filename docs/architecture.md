# Architecture

## Position in the toolchain

```text
static repositories and rendered deployment artifacts
                        |
                        v
                   Procrustes
             report + collection plan
                 + static overlay
                        |
                        v
                     Bering
          runtime topology/model artifact
                        |
                        v
                     Sheaft
        resilience analysis and CI/CD decision
```

Procrustes is a pre-discovery compiler for applicability evidence. It does not duplicate Bering discovery or Sheaft analysis.

## Analyze flow

1. Load and validate one goal contract.
2. Read aliased sources and compute a byte-derived deterministic fingerprint.
3. Parse supported deployment, tracing, configuration, and Tracetest evidence.
4. Join workload, image, observability identity, entrypoint, and replicas.
5. Evaluate capability-specific facts without an aggregate score.
6. Emit the report, summary, collection plan, and conservative Bering overlay atomically.

## Determinism

Input sources, facts, findings, services, evidence, and output collections are sorted before serialization. Identical goal and source bytes must produce byte-identical outputs.

## Trust boundary

Static source evidence can prove that a setting is present or declared; it cannot prove runtime coverage, sampling quality, successful propagation, or an observed dependency. Those checks remain downstream.
