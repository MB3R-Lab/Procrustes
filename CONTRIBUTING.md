# Contributing

Thanks for contributing to Procrustes.

## Development

1. Install the Go version declared in `go.mod`.
2. Run `make run-checks` before opening a pull request.
3. Keep output deterministic for identical goal and source bytes.
4. Preserve the product boundary: Procrustes analyzes static evidence and never accepts telemetry.
5. Do not emit static dependency edges as discovered runtime topology.

## Contract compatibility

The current preview contracts are:

- `io.mb3r.procrustes.goal@0.1.0`
- `io.mb3r.procrustes.report@0.1.0`
- `io.mb3r.procrustes.collection-plan@0.1.0`

Contract fields and status semantics must not change silently. Follow [VERSIONING.md](VERSIONING.md).

## Pull request checklist

- [ ] New behavior is covered by tests.
- [ ] `go test ./...` and `go vet ./...` pass.
- [ ] Generated outputs remain byte-stable.
- [ ] Evidence uses stable aliased paths rather than machine-specific absolute paths.
- [ ] Documentation is updated for changed flags, contracts, heuristics, or limitations.
