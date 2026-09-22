# v1.0 Release Contract

ProofAuth v1.0 is released only when all of the following are true:

- `cargo fmt --all -- --check` passes;
- `cargo clippy --all-targets --all-features -- -D warnings` passes;
- `cargo test --all-features` passes;
- UOR identity-address golden vectors are committed;
- UOR JSON reference vectors pass byte-for-byte;
- request and presentation canonicalization vectors are committed;
- end-to-end issue, encode, decode, and offline-verify coverage passes;
- the offline bundle content hash detects any modified embedded JSON;
- issuer-signed identity commitments bind claims hashes to subject keys;
- signed trust registries verify against an independently pinned root key;
- registry-backed offline verification rejects an untrusted issuer key;
- when disclosed, identity claims recompute to the committed identity root;
- the consumer can evaluate the local policy and compare it with the signed decision;
- issuer and subject signature negative tests pass;
- expired and revoked keys are rejected;
- stale revocation snapshots are rejected;
- replayed authorization identifiers are rejected;
- role inheritance and deny-overrides-allow are tested;
- malformed requests and snapshots are rejected before cryptographic work;
- malformed identities and policies are rejected before authorization;
- the CLI and library produce identical addresses;
- the CLI issue and verify lifecycle passes against the library vectors;
- the CLI bundle-seal, bundle-verify, and registry-verify commands pass;
- the public API and wire format are documented;
- the dependency lockfile is committed;
- a security review has been completed;
- the release is tagged `v1.0.0`.

The v1.0 protocol does not claim zero-knowledge selective disclosure. That is
a future protocol extension. v1.0 provides privacy by minimizing disclosed
claims and binding each signed presentation to its recipient and request.
