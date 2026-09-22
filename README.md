# ProofAuth

ProofAuth is a Rust implementation of recipient-bound, offline-verifiable
authorization for people, agents, services, and workloads. It combines an
issuer-signed identity commitment, subject proof-of-possession, hierarchical
RBAC, scoped requests, revocation snapshots, and a signed issuer registry.

## What ProofAuth proves

Given trusted inputs, a verifier can establish offline that:

- a trusted issuer signed an identity commitment and bound it to a subject key;
- the subject possessed that key when the presentation was issued;
- the presentation is bound to the expected recipient and exact request;
- the disclosed role was authorized for the requested action by the supplied
  policy within its tenant, workflow, resource, and time constraints;
- the issuer and subject key satisfy the supplied registry and revocation
  snapshot; and
- the authorization identifier has not already appeared in the verifier's
  replay cache.

ProofAuth does not establish that an issuer's real-world identity assertions
are true, that keys were stored safely, or that an offline revocation snapshot
is newer than the verifier's copy. It is not an identity provider, online
policy service, confidentiality layer, or zero-knowledge proof system.

## Content addresses, digests, and bundles

ProofAuth uses the `uor-addr` crate for canonical identity and policy content
addresses. The UOR JSON realization canonicalizes JSON, and ProofAuth also
normalizes schema fields that behave like sets. Equivalent content therefore
does not acquire a different address merely because JSON object keys were
written in a different order. UOR addresses have this form:

```text
sha256:<64 lowercase hexadecimal characters>
```

A digest is one-way: its hexadecimal encoding can be decoded back to the 32
digest bytes, but not to the object that was hashed. An `offline-bundle.hex`
file is different. It is the lowercase hexadecimal encoding of a complete,
decodable JCS JSON envelope. That envelope contains the identity commitment,
policy, request, signed presentation, signed revocation snapshot, public keys,
an optional identity-claims object, and an internal `content_hash` covering the
embedded material. The bundle is data plus verification material, not merely a
hash.

## Roles, policy, and disclosure

A `Role` has a name and parent roles. In the starter policy,
`finance.approver` inherits `finance`; the `finance` role maps to the
`invoice.approve` permission. A `PermissionRule` can constrain tenant,
workflow, and resource, while the permission is matched against the request's
action. Empty scope lists or `"*"` act as wildcards.

All matching rules are evaluated across the inherited role set. Any matching
`Deny` rule overrides matching `Allow` rules. The identity must also include
the request tenant, and the request may not outlive the identity.

The presentation discloses the roles that matched the decision, not arbitrary
identity attributes such as `clearance`. The `OfflineBundle` supports omitting
full identity claims. The current complete demo intentionally includes them as
`identity_claims: Some(...)` so the consumer can recompute and check the claims
commitment. Thus the demo consumer receives no separate identity file, but its
hex token does contain the claims. Proving predicates about undisclosed claims
would require a future zero-knowledge extension. When full claims are omitted,
the verifier authenticates the opaque issuer commitment and the separately
issuer-signed disclosed roles; it cannot independently prove that those roles
were members of the hidden claims.

## Issuer trust and offline verification

The issuer signs an `IdentityCommitment` that binds the canonical identity root,
policy hash, subject key, key identifier, validity, and issuer epoch. The
subject signs the recipient-bound presentation to prove possession of its
private key.

Issuer keys are distributed in a `SignedTrustRegistry`. The consumer pins the
registry-root public key independently and verifies the registry signature
before trusting any issuer entry. The registry and a sufficiently fresh signed
revocation snapshot can be provisioned ahead of time; bundle verification then
contacts no identity, policy, registry, or revocation server.

## Start here: the Acme payment desk

Imagine that Priya works in Acme's accounts-payable team. She needs to view a
payment before approving it, but she must not approve payments outside her
assigned workflow. If her account is suspended, an explicit deny must win even
though she still has the approver role.

ProofAuth represents that story with five pieces:

| Piece | In this story |
| --- | --- |
| Identity claims | Acme's issuer says Priya belongs to tenant `acme` and has role `finance.approver`. |
| Role hierarchy | `finance.approver` inherits `finance.viewer`, so approvers can also view. |
| Policy rules | View and approve rules are limited to workflow `ap-2026` and resource `payment-8472`. |
| Request | The payment API asks whether Priya may perform `payment.view` or `payment.approve`. |
| Decision | Matching allow rules grant access, but a matching `finance.suspended` deny overrides them. |

Run the story:

```sh
just payment-demo
# equivalent: cargo run --example payment_workflow
```

The program narrates each step and prints formatted, syntax-colored JSON for
the exact `AuthorizationRequest` delivered to the `payment-api` consumer.
Colors are enabled on an interactive terminal and disabled when output is
redirected or `NO_COLOR` is set. For example, the first decision includes:

```text
=== Acme payment desk ===
Acme's issuer identifies Priya as a finance.approver for tenant acme.
The policy lets approvers inherit payment viewing permission.

1. Priya opens payment-8472 before deciding whether to approve it.
   Payload delivered to consumer `payment-api`:
   {
     "recipient": "payment-api",
     "tenant": "acme",
     "workflow": "ap-2026",
     "resource": "payment-8472",
     "action": "payment.view",
     "nonce": [9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],
     "issued_at": 1000,
     "expires_at": 1100
   }
   Decision: ALLOW through inherited role finance.viewer.
```

It continues with the approve, out-of-scope, and suspended-user cases, printing
the real request payload and decision for each one. It then signs the allowed
approval using the existing ProofAuth commitment and presentation APIs, seals
an `OfflineBundle`, verifies that it decodes, and prints the complete lowercase
hex token sent to the offline consumer. That consumer must separately possess a
trusted registry and independently pinned registry-root public key.

The action names are application-defined strings, not built-in ProofAuth
permissions. Your application chooses names such as `payment.view` and
`payment.approve`; ProofAuth checks them against `PermissionRule.permission`
along with the tenant, workflow, resource, identity lifetime, and role graph.

The first four steps isolate the local RBAC decision. The fifth performs the
producer-side signing and bundling. The complete creator/consumer flow below
then verifies this kind of bundle using a signed registry, pinned registry-root
key, and local trust material.

## Generate starter JSON

From the project root, generate all three producer inputs in `./demo-data`:

```sh
cargo run -- generate-example --output ./demo-data
```

This creates:

```text
demo-data/identity.json
demo-data/policy.json
demo-data/request.json
```

The command creates the directory when needed and replaces those three files
when they already exist. Other files in the output directory are left alone.
CLI file arguments use `@path` syntax.

Inspect the official UOR addresses, validate request structure, and evaluate
the policy without issuing a presentation:

```sh
cargo run -- identity-address @demo-data/identity.json
cargo run -- policy-address @demo-data/policy.json
cargo run -- validate-request @demo-data/request.json
cargo run -- authorize \
  @demo-data/identity.json \
  @demo-data/policy.json \
  @demo-data/request.json
```

The last two commands print `valid` and `allowed`, respectively. Validation is
structural; `authorize` performs the hierarchical, scoped RBAC decision.

## Allowed request

The generated request asks `payment-control` to approve `invoice-8472` for
tenant `acme` in workflow `ap-2026`. These deterministic keys are only for the
local demo:

```sh
export PROOFAUTH_DEMO_ISSUER_SECRET=0101010101010101010101010101010101010101010101010101010101010101
export PROOFAUTH_DEMO_SUBJECT_SECRET=0202020202020202020202020202020202020202020202020202020202020202

cargo run -- issue \
  @demo-data/identity.json \
  @demo-data/policy.json \
  @demo-data/request.json \
  --issuer-secret "$PROOFAUTH_DEMO_ISSUER_SECRET" \
  --subject-secret "$PROOFAUTH_DEMO_SUBJECT_SECRET" \
  --subject-key-id subject-key-1 \
  --issuer-epoch 7 \
  > demo-data/presentation.json && echo allowed
```

Expected application output:

```text
allowed
```

`issue` calls `authorize` before signing. This succeeds because
`finance.approver` inherits `finance`, whose allow rule matches the action,
tenant, workflow, and resource. The redirected file contains the one-line JCS
JSON presentation.

## Denied request

Create a structurally valid request for a resource outside the policy rule:

```sh
sed 's/invoice-8472/invoice-0000/' \
  demo-data/request.json > demo-data/denied-request.json

cargo run -- authorize \
  @demo-data/identity.json \
  @demo-data/policy.json \
  @demo-data/denied-request.json
```

Expected application failure:

```text
Error: AuthorizationDenied
```

It is denied because `invoice-0000` does not match the rule constrained to
`invoice-8472`. Structural validation alone would accept this request; policy
authorization is what rejects it.

## Complete creator/consumer demo

The examples are deterministic and write under `target/proofauth-demo/`:

```sh
cargo run --example creator
cargo run --example registry_creator
cargo run --example consumer
```

The creator constructs its identity, policy, request, issuer key, and subject
key in memory. It authorizes the request and creates:

- `identity-commitment.json`: issuer-signed identity/key commitment;
- `policy.json` and `request.json`: producer inputs copied for inspection;
- `presentation.json`: issuer- and subject-signed authorization presentation;
- `snapshot.json`: signed revocation state;
- `keys.json`: demo public keys for inspection; and
- `offline-bundle.hex`: the sealed, decodable transport bundle.

`registry_creator` separately creates `registry.json` and prints the
registry-root public key. The demo consumer derives the same deterministic root
inside `consumer.rs`; production code must instead pin that public key in
independent configuration. In a real transfer, the producer sends only
`offline-bundle.hex` as the authorization payload. The consumer receives
`registry.json` through a trusted provisioning or update channel, not from the
bundle. `keys.json` is not consumer trust material.

The consumer decodes the token, verifies its content hash, verifies the signed
registry with the pinned root, resolves the issuer key, checks the commitment,
subject proof, local policy decision, request binding, time window, revocation
snapshot, and replay cache, then prints:

```text
accepted: recipient=payment-control action=invoice.approve tenant=acme subject_key_id=subject-key-1
denied: resource=invoice-0000 reason=authorization denied
verified offline from one hex token plus locally trusted registry material
```

The example keeps all artifacts in one directory only for local convenience.
No server is contacted during the consumer step.

The CLI can also sign a registry JSON document whose `signature` is initially
empty, then verify the result with the independently pinned root public key:

```sh
cargo run -- registry-sign @unsigned-registry.json \
  --root-secret "$REGISTRY_ROOT_SECRET" > registry.json
cargo run -- registry-verify @registry.json \
  --root-public "$REGISTRY_ROOT_PUBLIC"
```

Root private keys must not be passed on command lines in production; this CLI
form is for local demonstrations and controlled tooling.

## Justfile commands

Run `just` to list recipes. The current recipes are:

| Command | Purpose |
| --- | --- |
| `just fmt` | Format all Rust targets. |
| `just fmt-check` | Check formatting without changing files. |
| `just check` | Run `cargo check` for all targets and features. |
| `just lint` | Run strict Clippy for all targets and features. |
| `just audit` | Scan the lockfile with RustSec `cargo-audit` (install separately). |
| `just test` | Run all-feature tests. |
| `just doc-test` | Run Rust documentation tests. |
| `just build` | Build all targets and features. |
| `just generate-example` | Generate or replace inputs under `examples/data`. |
| `just payment-demo` | Run the introductory payment-authorization story. |
| `just examples` | Run the payment story and complete offline examples. |
| `just demo` | Alias for `just examples`. |
| `just registry-verify` | Verify the demo registry using `REGISTRY_ROOT_PUBLIC`. |
| `just serve-registry` | Serve the demo registry at `127.0.0.1:8787`. |
| `just bundle-verify` | Verify the demo bundle and registry at time `1050`. |
| `just ci` | Run format check, check, lint, tests, and doc tests. |
| `just archive` | Create the candidate tarball and checksum under `dist/`. |
| `just release-check` | Run CI, build, examples, and bundle verification. |

For the deterministic registry example, set the printed root key before the
registry or bundle recipes:

```sh
export REGISTRY_ROOT_PUBLIC=ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1
just registry-verify
just bundle-verify
```

## Security limitations and v1.0 boundary

- Protect issuer, subject, and registry-root private keys with production key
  management. The fixed example keys are public test fixtures.
- Offline revocation is only as fresh as the accepted signed snapshot and
  registry. Distribution, expiry policy, and clock correctness are operational
  responsibilities.
- A production replay cache must be durable and shared across every verifier
  that must enforce single use. The examples use an in-memory cache.
- Presentations reveal recipient, tenant, workflow, resource, action, key ID,
  and matched roles. Bundles reveal all embedded material; the current demo
  also embeds full identity claims. Hex encoding provides no confidentiality.
- v1.0 assumes SHA-256, Ed25519, canonical JCS serialization, and the security
  of `uor-addr` canonical addressing. Algorithm agility is not implemented.
- v1.0 provides signed minimal disclosure, not zero-knowledge selective
  disclosure. It cannot prove predicates over claims that remain undisclosed.

## v1.0 checklist

Implemented and exercised in this repository:

- [x] hierarchical RBAC, scoped rules, and deny-overrides-allow tests;
- [x] recipient/request binding, issuer commitments, subject proof-of-possession,
  signed revocation snapshots, replay detection, and signed registries;
- [x] decodable offline bundles with content-integrity checking;
- [x] a generated `Cargo.lock` checked into the project;
- [x] committed UOR, request, and signed-presentation canonicalization vectors
  with byte-for-byte tests; and
- [x] local `just release-check` and a RustSec audit with no known advisories.

Before a v1.0 release:

- [x] run `just release-check` in clean CI on the supported stable Rust
  toolchain ([CI run](https://github.com/auser/proofauth/actions/runs/35783212486));
- [ ] complete an independent security review and resolve its findings; and
- [ ] create the `v1.0.0` release tag only after every release-contract item is
  satisfied.

See [DESIGN.md](DESIGN.md), [RELEASE.md](RELEASE.md), the
[example notes](examples/README.md), and the
[UOR reference vector](vectors/uor-json-reference.md) and
[canonicalization vectors](vectors/canonicalization.md).
