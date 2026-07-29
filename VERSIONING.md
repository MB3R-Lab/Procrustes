# Versioning

Procrustes separates the product release version from its public preview contract versions.

## Product version

- Product releases use SemVer tags in the form `vX.Y.Z`.
- The CLI product version describes executable behavior and packaging.
- No stable product release is claimed by the current preview branch.

## Preview contracts

The current emitted and accepted contracts are:

- `io.mb3r.procrustes.goal@0.1.0`
- `io.mb3r.procrustes.report@0.1.0`
- `io.mb3r.procrustes.collection-plan@0.1.0`

These versions are independent from Bering model and snapshot schema versions. `bering.overlay.yaml` follows Bering's overlay input rather than defining a separate Procrustes topology contract.

Rules:

- Contract versions never change meaning in place.
- Breaking field or semantic changes require a new contract major version.
- Backward-compatible fields require a contract minor version.
- Clarifications or fixes that do not alter meaning require a patch version.
- Product tags do not imply a contract-version change.

The `0.x` contracts are preview surfaces. Consumers should pin the exact contract version and reject unknown versions.
