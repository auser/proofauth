# Changelog

## Unreleased

- Bound identity commitments and presentations to official UOR identity and
  normalized-policy digest bytes.
- Added fail-closed lowercase bundle decoding, full-claims local RBAC
  recomputation, epoch and revocation-issuer binding, and resealed-tamper tests.
- Added policy-aware `authorize` and `registry-sign` CLI commands, deterministic
  request/presentation vectors, and allowed/denied offline consumer output.
- Disabled unused `uor-addr` model-format features and added a repeatable
  RustSec audit recipe.
- Added end-to-end coverage for authorization, dual-signed presentation
  issuance, JCS encoding/decoding, and offline verification.
- Added identity and policy schema validation before authorization evaluation.
- Added the v1.0 release contract, UOR JSON reference vector, CLI examples,
  and CI configuration.

## v1.0.0

This section will be finalized when the v1.0.0 tag is created. The release
must satisfy every item in `RELEASE.md`.
