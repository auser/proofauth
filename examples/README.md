# Creator and consumer example

This is the smallest complete ProofAuth flow.

The creator has the identity, policy, and signing keys. It evaluates the
request, creates a recipient-bound presentation, signs it, and writes the
transport artifacts under `target/proofauth-demo/`. It also creates an
issuer-signed identity commitment binding the canonical identity root to the
subject public key.

The producer seals those JSON objects into one lowercase-hex
`offline-bundle.hex` token. The consumer receives that one token and an
independently provisioned trusted issuer registry. The current demo discloses
the identity claims inside the token, but no separate identity file is a
consumer input. It decodes the token, recomputes its content hash,
and verifies the signatures, request binding, expiry, issuer epoch, revocation
status, proof of possession, identity-key binding, and RBAC decision offline.

Run it from the project root:

```sh
cargo run --example creator
cargo run --example registry_creator
cargo run --example consumer
```

The registry is a signed document. The consumer pins the root public key and
rejects any registry document whose signature is invalid. A registry server
can distribute that document:

```sh
cargo run -- serve-registry @target/proofauth-demo/registry.json
```

The output includes the identity root and UOR identity/policy addresses. The
identity root is an encoded hash of normalized identity content; the
presentation is the decodable signed envelope that a consumer actually uses.

The token is not a one-way hash: it is a decodable JCS envelope whose
`content_hash` commits to every embedded object. The trust registry remains
outside the token so an attacker cannot make an arbitrary issuer trusted by
including a public key in the token.

This demo includes `identity_claims` so the consumer can inspect and verify
the complete claims, and it prints both an allowed request and a resource-
scoped denial. A privacy-preserving deployment can omit full claims and rely
only on the issuer-committed root plus disclosed roles; in that mode the
consumer authenticates both issuer statements but cannot independently prove
that a disclosed role was a member of the opaque claims, and must not claim
that undisclosed attributes were verified. A future zero-knowledge proof is
required to prove predicates over undisclosed claims.
