# ProofAuth Design

## Purpose

ProofAuth is a Rust library and CLI for producing privacy-preserving,
offline-verifiable authorization proofs.

The system represents a complete identity, but controls receive only a narrow
authorization presentation for a particular recipient, request, tenant,
workflow, resource, and action.

The default presentation does not disclose the person's identity or unrelated
roles. It proves that a trusted authority evaluated the request and authorized
the action.

## Core distinction

The protocol separates:

1. **Identity** — the complete set of claims held by an issuer or subject.
2. **Policy** — the mapping from hierarchical roles to permissions.
3. **Authorization** — the decision for one specific request.
4. **Presentation** — the signed, recipient-bound proof sent to a control.

The identity is not itself a general-purpose bearer credential.

## Cryptographic model

Objects are semantically normalized and then serialized with JSON
Canonicalization Scheme (JCS). Hashes use
domain-separated SHA-256:

```text
H(domain || canonical_object)
```

Examples:

```text
H("proofauth/identity/v1" || identity_claims)
H("proofauth/policy/v1" || policy)
H("proofauth/request/v1" || authorization_request)
H("proofauth/presentation/v1" || presentation)
```

Digest values are encoded as canonical lowercase hexadecimal strings. A hex
digest is decodable to its raw digest bytes, but not to the original identity,
roles, or object. The signed presentation is the decodable protocol envelope;
the digest is its tamper-evident identifier.

Canonical CBOR may be added as an alternate wire encoding later. It must not
change the semantic object model or domain-separation rules.

ProofAuth uses the official `uor-addr` JSON realization for identity content
addresses. It emits the UOR κ-label format:

```text
sha256:<64 lowercase hexadecimal characters>
```

ProofAuth performs identity-schema normalization first, then delegates JSON
canonicalization, Unicode NFC normalization, SHA-256 derivation, and label
construction to `uor-addr`. The local versioned digest remains available for
internal domain-separated protocol objects such as requests and presentations.

Normalization is type-specific:

- roles and tenant memberships are sets and are sorted and deduplicated;
- object keys are canonicalized by JCS;
- ordered workflow steps remain ordered;
- duplicate claims are rejected or removed according to the type's schema;
- normalization rules are part of the protocol version.

## Identity commitment

The complete identity may contain:

```text
subject type
tenant memberships
hierarchical roles
attributes
delegations
subject key identifiers
validity interval
issuer epoch
```

The issuer signs a commitment to the canonical identity claims. The commitment
can be used as a stable address without revealing the claims.

The identity commitment is not necessarily a global public identifier. Derived
pseudonyms should be scoped to a tenant, workflow, or control to limit
cross-system correlation.

## Role and policy model

Identities carry roles. Policies map roles to permissions.

```text
finance.admin
  └── finance.approver
        ├── invoice.read
        └── invoice.approve
```

Policies are versioned and independently hashed:

```text
policy_hash = H("proofauth/policy/v1" || canonical_policy)
```

Policy evaluation must define:

- explicit role ancestry;
- cycle detection;
- bounded delegation depth;
- namespace isolation between issuers;
- deny-overrides-allow behavior;
- no implicit wildcard inheritance;
- policy version pinning;
- tenant and workflow scope.

The initial implementation uses a trusted authorization issuer to perform
role-to-permission evaluation. A future zero-knowledge verifier may prove the
same evaluation without disclosing the role.

## Authorization request

Every authorization decision is bound to:

```text
recipient
tenant
optional workflow
resource
action
nonce
issued_at
expires_at
```

The request hash is included in the presentation. A presentation created for
one request must fail verification for another request.

## Authorization presentation

The v0.1 presentation contains:

```text
identity commitment
request hash
recipient
tenant
workflow
resource
action
policy hash
authorization identifier
issuer epoch
issued_at
expires_at
issuer signature
```

The receiving control learns the authorization result and the minimum context
needed to enforce it. It does not need to learn the subject's identity or role
hierarchy.

Presentations are derived objects, not modified identity hashes. A separate
presentation is generated for each recipient and request.

## Proof of possession

The presentation must eventually be bound to a private key held by the
subject, device, agent, or delegated workload. Otherwise, anyone who copies a
valid presentation can replay it until it expires.

The verifier should require:

```text
presentation signature
proof of possession
request nonce
recipient binding
expiry validation
local replay detection
```

The implementation uses two independent signatures:

```text
issuer signature  → authorizes the presentation
subject signature → proves possession of the bound subject or agent key
```

The subject signature covers the presentation identifier, request hash, and
request nonce. This prevents a copied presentation from being used with a
different key.

Human subjects, agents, services, devices, and microVMs use the same general
subject model but have explicit subject types and delegation rules.

## Offline verification and revocation

Controls must work offline. Since an offline control cannot learn about a new
revocation immediately, offline authorization is bounded by freshness.

The system uses:

- short-lived presentations;
- issuer epochs;
- signed revocation snapshots;
- snapshot expiry times;
- configurable offline tolerance by action risk;
- local replay caches.

High-risk actions should fail closed when the revocation snapshot is too old.
There is no mechanism that makes stale offline revocation information current.

The implementation provides `RevocationSnapshot`, `ReplayCache`, and
`OfflineVerifier`. The verifier validates the signed snapshot, rejects
presentations from a newer issuer epoch, rejects revoked subject keys, and
records authorization identifiers to prevent reuse.

The complete single-token path is `OfflineBundle`. It contains the canonical
policy, request, presentation, identity commitment, revocation snapshot, and
verification keys, then seals them with a content hash and JCS-hex encoding.
`OfflineBundle::verify` recomputes that hash before checking the independently
provisioned trust registry, issuer-to-subject identity binding, local RBAC
evaluation, and signed presentation. If `identity_claims` is present, the
consumer also recomputes the identity root and verifies the issuer signature
over the exact claims. If it is omitted, the consumer has an authenticated
opaque commitment rather than inspectable claims.

## Trust model

Trusted issuer configuration must identify:

```text
tenant
trusted issuers
permitted role namespaces
policy authority
key rotation rules
revocation authority
```

Multiple issuers and decentralized distribution may be supported, but issuer
conflicts, delegation depth, revocation authority, and policy precedence must
be explicit.

UOR-style addresses may identify issuers, policies, identities, claims, and
presentations. They do not replace signatures, trust roots, or authorization
policy.

## Audit and privacy

The system should use controlled unlinkability rather than absolute anonymity.
Different audiences may see different identifiers:

```text
issuer              → global identity reference
tenant              → tenant-scoped pseudonym
workflow            → workflow-scoped pseudonym
control             → presentation identifier
investigator        → conditional identity escrow, if authorized
```

Authorization decisions should be auditable without exposing the person's
identity to every control. Audit records should include the request hash,
presentation hash, policy hash, issuer epoch, decision, and verifier identity.

## End-to-end v0.1 scenario

An authorized finance approver requests permission to approve an invoice while
the payment control is offline.

```text
tenant:    acme
workflow:  ap-2026
resource:  invoice-8472
action:    invoice.approve
recipient: payment-control
```

The authorization issuer:

1. validates the identity commitment;
2. evaluates role inheritance;
3. checks tenant and workflow membership;
4. evaluates the requested resource and action;
5. checks issuer epoch and local revocation data;
6. creates a request-bound presentation;
7. signs the presentation;
8. binds it to the subject or delegated agent key.

The payment control:

1. verifies the issuer signature;
2. verifies the recipient and request hash;
3. verifies tenant, workflow, resource, and action;
4. checks expiry and issuer epoch;
5. checks its signed revocation snapshot;
6. verifies proof of possession;
7. checks its local replay cache;
8. records the decision and either permits or denies the action.

## Rust API target

```rust
let decision = issuer.authorize(&identity, &request, &policy)?;

verifier.verify(
    &decision.presentation,
    &request,
    &trust_roots,
    &revocation_snapshot,
)?;
```

At the cryptographic layer, verification requires both issuer and subject
verification keys.

## Stable CLI surface

The v1.0 CLI exposes the same content-addressing and validation operations as
the library:

```text
proofauth hash --domain <name> <json-or-@file>
proofauth identity-address <json-or-@file>
proofauth policy-address <json-or-@file>
proofauth validate-request <json-or-@file>
```

All address commands emit the UOR `sha256:<64 lowercase hex>` κ-label. The
CLI does not print private identity claims or private keys.

## Implementation roadmap

### Milestone 1 — canonical protocol foundation

- JCS encoding;
- domain-separated hashes;
- multibase encoded digest APIs;
- stable protocol versioning;
- canonicalization test vectors.
- set-like versus ordered-field semantics;
- UOR-address adapter and compatibility test vectors.
- official `uor-addr` JSON address generation and cross-implementation vectors.

### Milestone 2 — policy-aware authorization

- roles and permissions;
- hierarchical inheritance;
- deny-overrides-allow;
- tenant and workflow constraints;
- policy hashing;
- signed authorization decisions.

The current implementation now includes the first version of this layer:
typed `Role`, `PermissionRule`, `Effect`, `Policy`, and
`AuthorizationDecision` values, plus hierarchical inheritance, tenant and
workflow scoping, resource matching, UOR policy addresses, and
deny-overrides-allow evaluation.

### Milestone 3 — request-bound verification

- recipient binding;
- resource and action binding;
- expiry and nonce validation;
- proof of possession;
- replay detection;
- BDD security tests.

### Milestone 4 — offline status

- signed revocation snapshots;
- issuer epochs;
- freshness policies;
- key rotation;
- trust registries.

The first implementation of signed snapshots, issuer epochs, revoked subject
keys, snapshot freshness, and local replay detection is now present.

Strict request and revocation-snapshot validation is also enforced before
cryptographic verification.

### Milestone 5 — selective disclosure

- Merkle claim commitments;
- individual claim proofs;
- tenant-scoped pseudonyms;
- controlled identity escrow.

### Milestone 6 — zero-knowledge policy proofs

- prove role possession without role disclosure;
- prove policy satisfaction without identity disclosure;
- preserve the v0.1 request and presentation semantics.

## Explicit non-goals for v0.1

- inventing a new signature algorithm;
- making a bare hash act as an identity credential;
- requiring online introspection for every authorization;
- implementing zero-knowledge proofs before the policy model is stable;
- allowing broad reusable bearer tokens;
- treating UOR addressing as a substitute for authorization.
