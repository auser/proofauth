//! ProofAuth v0.1: signed, recipient-bound authorization presentations.
//!
//! The v0.1 design intentionally uses a trusted authorization issuer for
//! role-to-permission evaluation. The identity commitment and claim-proof
//! interfaces leave room for a future zero-knowledge verifier.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("presentation is expired or not yet valid")]
    InvalidTime,
    #[error("presentation audience does not match verifier")]
    WrongAudience,
    #[error("request binding does not match")]
    WrongRequest,
    #[error("permission is not the requested permission")]
    WrongPermission,
    #[error("authorization denied")]
    AuthorizationDenied,
    #[error("revocation snapshot is expired")]
    RevocationSnapshotExpired,
    #[error("issuer epoch is not accepted")]
    IssuerEpochRejected,
    #[error("subject key is revoked")]
    SubjectKeyRevoked,
    #[error("authorization presentation has already been used")]
    ReplayDetected,
    #[error("issuer is not trusted")]
    UntrustedIssuer,
    #[error("issuer key is outside its validity window")]
    IssuerKeyExpired,
    #[error("malformed public key")]
    MalformedPublicKey,
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
}

pub type Hash = [u8; 32];

pub fn canonical_bytes<T: Serialize>(value: &T) -> Vec<u8> {
    serde_jcs::to_vec(value).expect("domain objects must serialize")
}

pub fn hash<T: Serialize>(domain: &[u8], value: &T) -> Hash {
    let bytes = canonical_bytes(value);
    let mut h = Sha256::new();
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

/// Encode a digest as canonical lowercase hexadecimal.
///
/// This is reversible to the raw 32-byte digest, but not to the input object.
pub fn encode_hash(digest: &Hash) -> String {
    hex::encode(digest)
}

pub fn identity_hash(claims: &IdentityClaims) -> String {
    encode_hash(&identity_root(claims))
}

/// Produce the official UOR JSON κ-label for normalized identity content.
///
/// The returned value has the form `sha256:<64 lowercase hex characters>`.
/// UOR-ADDR performs the format-level JCS and NFC canonicalization; this
/// function performs the identity-schema normalization first.
pub fn uor_identity_address(claims: &IdentityClaims) -> Result<String, String> {
    let normalized = normalized_identity(claims);
    let json = serde_json::to_vec(&normalized).map_err(|e| e.to_string())?;
    let outcome = uor_addr::json::address(&json).map_err(|e| format!("{e:?}"))?;
    Ok(outcome.address.to_string())
}
pub fn request_hash(request: &AuthorizationRequest) -> String {
    encode_hash(&request.digest())
}
pub fn presentation_hash(presentation: &AuthorizationPresentation) -> String {
    encode_hash(&hash(b"proofauth/presentation/v1", presentation))
}

pub fn encode_presentation(
    presentation: &AuthorizationPresentation,
) -> Result<Vec<u8>, serde_json::Error> {
    serde_jcs::to_vec(presentation)
}

pub fn decode_presentation(bytes: &[u8]) -> Result<AuthorizationPresentation, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityClaims {
    pub subject_type: String,
    pub tenant_ids: Vec<String>,
    pub roles: Vec<String>,
    pub attributes: serde_json::Value,
    pub key_id: String,
    pub valid_until: u64,
    pub issuer_epoch: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    pub parents: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionRule {
    pub permission: String,
    pub effect: Effect,
    pub tenants: Vec<String>,
    pub workflows: Vec<String>,
    pub resources: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Policy {
    pub version: String,
    pub roles: Vec<Role>,
    pub rules: std::collections::BTreeMap<String, Vec<PermissionRule>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub permission: String,
    pub tenant: String,
    pub workflow: Option<String>,
    pub resource: String,
    pub policy_hash: String,
    pub matched_roles: Vec<String>,
}

impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.version.is_empty() {
            return Err(Error::InvalidField("policy version"));
        }
        let mut role_names = std::collections::HashSet::new();
        for role in &self.roles {
            if role.name.is_empty() || !role_names.insert(&role.name) {
                return Err(Error::InvalidField("role name"));
            }
            if role.parents.iter().any(|parent| parent.is_empty()) {
                return Err(Error::InvalidField("role parent"));
            }
        }
        for (role, rules) in &self.rules {
            if role.is_empty() {
                return Err(Error::InvalidField("rule role"));
            }
            for rule in rules {
                if rule.permission.is_empty() {
                    return Err(Error::InvalidField("permission"));
                }
                if rule.tenants.iter().any(|value| value.is_empty())
                    || rule.workflows.iter().any(|value| value.is_empty())
                    || rule.resources.iter().any(|value| value.is_empty())
                {
                    return Err(Error::InvalidField("policy scope"));
                }
            }
        }
        Ok(())
    }

    pub fn address(&self) -> Result<String, String> {
        let json = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        let outcome = uor_addr::json::address(&json).map_err(|e| format!("{e:?}"))?;
        Ok(outcome.address.to_string())
    }

    pub fn evaluate(
        &self,
        identity: &IdentityClaims,
        request: &AuthorizationRequest,
    ) -> AuthorizationDecision {
        let mut roles = identity.roles.clone();
        let mut index = 0;
        while index < roles.len() {
            let current = roles[index].clone();
            if let Some(role) = self.roles.iter().find(|r| r.name == current) {
                for parent in &role.parents {
                    if !roles.contains(parent) {
                        roles.push(parent.clone());
                    }
                }
            }
            index += 1;
        }
        roles.sort();
        roles.dedup();

        let in_scope = identity.tenant_ids.contains(&request.tenant)
            && request.expires_at <= identity.valid_until;
        let mut matched_roles = Vec::new();
        let mut denied = false;
        let mut allowed = false;
        for role in &roles {
            for rule in self.rules.get(role).into_iter().flatten() {
                if rule.permission != request.action || !rule_matches(rule, request) {
                    continue;
                }
                matched_roles.push(role.clone());
                match rule.effect {
                    Effect::Allow => allowed = true,
                    Effect::Deny => denied = true,
                }
            }
        }
        matched_roles.sort();
        matched_roles.dedup();
        AuthorizationDecision {
            allowed: in_scope && allowed && !denied,
            permission: request.action.clone(),
            tenant: request.tenant.clone(),
            workflow: request.workflow.clone(),
            resource: request.resource.clone(),
            policy_hash: self.address().unwrap_or_default(),
            matched_roles,
        }
    }
}

pub fn uor_policy_address(policy: &Policy) -> Result<String, String> {
    policy.address()
}

fn rule_matches(rule: &PermissionRule, request: &AuthorizationRequest) -> bool {
    let matches = |values: &[String], value: &str| {
        values.is_empty() || values.iter().any(|v| v == value || v == "*")
    };
    matches(&rule.tenants, &request.tenant)
        && request
            .workflow
            .as_deref()
            .map_or(rule.workflows.is_empty(), |w| matches(&rule.workflows, w))
        && matches(&rule.resources, &request.resource)
}

pub fn authorize(
    identity: &IdentityClaims,
    request: &AuthorizationRequest,
    policy: &Policy,
) -> Result<AuthorizationDecision, Error> {
    identity.validate()?;
    policy.validate()?;
    request.validate()?;
    let decision = policy.evaluate(identity, request);
    if decision.allowed {
        Ok(decision)
    } else {
        Err(Error::AuthorizationDenied)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityCommitment {
    pub issuer: String,
    pub issuer_key_id: String,
    pub claims_hash: Hash,
    pub policy_hash: Hash,
    pub key_id: String,
    pub subject_public_key: Vec<u8>,
    pub valid_until: u64,
    pub issuer_epoch: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedIdentityCommitment<'a> {
    issuer: &'a str,
    issuer_key_id: &'a str,
    claims_hash: Hash,
    policy_hash: Hash,
    key_id: &'a str,
    subject_public_key: &'a Vec<u8>,
    valid_until: u64,
    issuer_epoch: u64,
}

impl IdentityCommitment {
    pub fn sign(mut self, issuer_key: &SigningKey) -> Self {
        let unsigned = UnsignedIdentityCommitment {
            issuer: &self.issuer,
            issuer_key_id: &self.issuer_key_id,
            claims_hash: self.claims_hash,
            policy_hash: self.policy_hash,
            key_id: &self.key_id,
            subject_public_key: &self.subject_public_key,
            valid_until: self.valid_until,
            issuer_epoch: self.issuer_epoch,
        };
        self.signature = issuer_key
            .sign(&hash(b"proofauth/identity-commitment/v1", &unsigned))
            .to_bytes()
            .to_vec();
        self
    }

    pub fn verify(
        &self,
        claims: &IdentityClaims,
        issuer_key: &VerifyingKey,
        subject_key: &VerifyingKey,
        now: u64,
    ) -> Result<(), Error> {
        claims.validate()?;
        if self.issuer.is_empty() || self.issuer_key_id.is_empty() || self.key_id.is_empty() {
            return Err(Error::InvalidField("identity commitment"));
        }
        if self.claims_hash != identity_root(claims)
            || self.key_id != claims.key_id
            || now > self.valid_until
            || self.subject_public_key != subject_key.to_bytes().as_slice()
        {
            return Err(Error::WrongRequest);
        }
        self.verify_binding(issuer_key, subject_key, now)?;
        Ok(())
    }

    /// Verify the issuer-to-key binding without needing the private identity claims.
    /// The claims hash remains opaque, but its provenance and subject-key binding
    /// are authenticated by the issuer signature.
    pub fn verify_binding(
        &self,
        issuer_key: &VerifyingKey,
        subject_key: &VerifyingKey,
        now: u64,
    ) -> Result<(), Error> {
        if self.issuer.is_empty()
            || self.issuer_key_id.is_empty()
            || self.key_id.is_empty()
            || self.subject_public_key.len() != 32
            || now > self.valid_until
        {
            return Err(Error::InvalidField("identity commitment"));
        }
        if self.subject_public_key != subject_key.to_bytes().as_slice() {
            return Err(Error::WrongRequest);
        }
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| Error::InvalidSignature)?;
        let unsigned = UnsignedIdentityCommitment {
            issuer: &self.issuer,
            issuer_key_id: &self.issuer_key_id,
            claims_hash: self.claims_hash,
            policy_hash: self.policy_hash,
            key_id: &self.key_id,
            subject_public_key: &self.subject_public_key,
            valid_until: self.valid_until,
            issuer_epoch: self.issuer_epoch,
        };
        issuer_key
            .verify(
                &hash(b"proofauth/identity-commitment/v1", &unsigned),
                &signature,
            )
            .map_err(|_| Error::InvalidSignature)
    }
}

pub fn issue_identity_commitment(
    issuer: String,
    issuer_key_id: String,
    claims: &IdentityClaims,
    policy: &Policy,
    issuer_epoch: u64,
    issuer_key: &SigningKey,
    subject_key: &VerifyingKey,
) -> Result<IdentityCommitment, Error> {
    claims.validate()?;
    policy.validate()?;
    if issuer.is_empty() || issuer_key_id.is_empty() {
        return Err(Error::InvalidField("identity issuer"));
    }
    Ok(IdentityCommitment {
        issuer,
        issuer_key_id,
        claims_hash: identity_root(claims),
        policy_hash: hash(b"proofauth/policy/v1", policy),
        key_id: claims.key_id.clone(),
        subject_public_key: subject_key.to_bytes().to_vec(),
        valid_until: claims.valid_until,
        issuer_epoch,
        signature: Vec::new(),
    }
    .sign(issuer_key))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub recipient: String,
    pub tenant: String,
    pub workflow: Option<String>,
    pub resource: String,
    pub action: String,
    pub nonce: Hash,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationPresentation {
    pub identity_root: Hash,
    pub request_hash: Hash,
    pub recipient: String,
    pub tenant: String,
    pub workflow: Option<String>,
    pub resource: String,
    pub action: String,
    pub policy_hash: Hash,
    pub authorization_id: Hash,
    pub issued_at: u64,
    pub expires_at: u64,
    pub issuer_epoch: u64,
    pub issuer_signature: Vec<u8>,
    pub subject_key_id: String,
    pub roles: Vec<String>,
    pub subject_signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevocationSnapshot {
    pub issuer: String,
    pub epoch: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub revoked_key_ids: Vec<String>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedRevocationSnapshot<'a> {
    issuer: &'a str,
    epoch: u64,
    issued_at: u64,
    expires_at: u64,
    revoked_key_ids: &'a Vec<String>,
}

impl RevocationSnapshot {
    pub fn sign(mut self, issuer_key: &SigningKey) -> Self {
        self.revoked_key_ids.sort();
        self.revoked_key_ids.dedup();
        let unsigned = UnsignedRevocationSnapshot {
            issuer: &self.issuer,
            epoch: self.epoch,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revoked_key_ids: &self.revoked_key_ids,
        };
        self.signature = issuer_key
            .sign(&hash(b"proofauth/revocation/v1", &unsigned))
            .to_bytes()
            .to_vec();
        self
    }

    pub fn verify(&self, issuer_key: &VerifyingKey, now: u64) -> Result<(), Error> {
        if self.issuer.is_empty() || self.expires_at <= self.issued_at {
            return Err(Error::InvalidField("revocation snapshot"));
        }
        if now < self.issued_at || now > self.expires_at {
            return Err(Error::RevocationSnapshotExpired);
        }
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| Error::InvalidSignature)?;
        let unsigned = UnsignedRevocationSnapshot {
            issuer: &self.issuer,
            epoch: self.epoch,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revoked_key_ids: &self.revoked_key_ids,
        };
        issuer_key
            .verify(&hash(b"proofauth/revocation/v1", &unsigned), &signature)
            .map_err(|_| Error::InvalidSignature)
    }
}

#[derive(Clone, Default)]
pub struct ReplayCache(std::collections::HashSet<Hash>);

impl ReplayCache {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn check_and_record(&mut self, id: Hash) -> Result<(), Error> {
        if !self.0.insert(id) {
            return Err(Error::ReplayDetected);
        }
        Ok(())
    }
}

pub struct OfflineVerifier {
    pub snapshot: RevocationSnapshot,
    pub replay_cache: ReplayCache,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedIssuerKey {
    pub issuer: String,
    pub key_id: String,
    pub public_key: Vec<u8>,
    pub valid_from: u64,
    pub valid_until: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustRegistry {
    pub keys: Vec<TrustedIssuerKey>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedTrustRegistry {
    pub version: String,
    pub issuer: String,
    pub epoch: u64,
    pub keys: Vec<TrustedIssuerKey>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct UnsignedTrustRegistry<'a> {
    version: &'a str,
    issuer: &'a str,
    epoch: u64,
    keys: &'a Vec<TrustedIssuerKey>,
}

impl SignedTrustRegistry {
    pub fn sign(mut self, root_key: &SigningKey) -> Self {
        self.keys
            .sort_by(|a, b| (&a.issuer, &a.key_id).cmp(&(&b.issuer, &b.key_id)));
        let unsigned = UnsignedTrustRegistry {
            version: &self.version,
            issuer: &self.issuer,
            epoch: self.epoch,
            keys: &self.keys,
        };
        self.signature = root_key
            .sign(&hash(b"proofauth/trust-registry/v1", &unsigned))
            .to_bytes()
            .to_vec();
        self
    }

    pub fn verify(&self, root_key: &VerifyingKey) -> Result<TrustRegistry, Error> {
        if self.version.is_empty() || self.issuer.is_empty() {
            return Err(Error::InvalidField("trust registry"));
        }
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| Error::InvalidSignature)?;
        let unsigned = UnsignedTrustRegistry {
            version: &self.version,
            issuer: &self.issuer,
            epoch: self.epoch,
            keys: &self.keys,
        };
        root_key
            .verify(&hash(b"proofauth/trust-registry/v1", &unsigned), &signature)
            .map_err(|_| Error::InvalidSignature)?;
        Ok(TrustRegistry {
            keys: self.keys.clone(),
        })
    }
}

/// Self-contained transport object for offline authorization.
///
/// This is intentionally an encoded envelope, not a hash pretending to carry
/// data. `content_hash` commits to every field except itself; the envelope is
/// then serialized with JCS and hex encoded for transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfflineBundle {
    /// Full claims when the consumer is allowed to inspect them. A future
    /// selective-disclosure proof can replace this with disclosed fields.
    pub identity_claims: Option<IdentityClaims>,
    pub identity_commitment: IdentityCommitment,
    pub policy: Policy,
    pub request: AuthorizationRequest,
    pub presentation: AuthorizationPresentation,
    pub revocation_snapshot: RevocationSnapshot,
    pub issuer_public_key: Vec<u8>,
    pub subject_public_key: Vec<u8>,
    pub content_hash: Hash,
}

#[derive(Serialize)]
struct UnsignedOfflineBundle<'a> {
    identity_claims: &'a Option<IdentityClaims>,
    identity_commitment: &'a IdentityCommitment,
    policy: &'a Policy,
    request: &'a AuthorizationRequest,
    presentation: &'a AuthorizationPresentation,
    revocation_snapshot: &'a RevocationSnapshot,
    issuer_public_key: &'a Vec<u8>,
    subject_public_key: &'a Vec<u8>,
}

impl OfflineBundle {
    pub fn seal(mut self) -> Self {
        self.content_hash = self.compute_hash();
        self
    }

    fn compute_hash(&self) -> Hash {
        hash(
            b"proofauth/offline-bundle/v1",
            &UnsignedOfflineBundle {
                identity_claims: &self.identity_claims,
                identity_commitment: &self.identity_commitment,
                policy: &self.policy,
                request: &self.request,
                presentation: &self.presentation,
                revocation_snapshot: &self.revocation_snapshot,
                issuer_public_key: &self.issuer_public_key,
                subject_public_key: &self.subject_public_key,
            },
        )
    }

    pub fn verify_content(&self) -> Result<(), Error> {
        if self.content_hash != self.compute_hash() {
            return Err(Error::WrongRequest);
        }
        Ok(())
    }
}

/// Encode a complete offline bundle as lowercase hexadecimal JCS bytes.
/// The result is decodable; it is not a one-way digest.
pub fn encode_offline_bundle(bundle: &OfflineBundle) -> Result<String, serde_json::Error> {
    Ok(hex::encode(serde_jcs::to_vec(bundle)?))
}

pub fn decode_offline_bundle(encoded: &str) -> Result<OfflineBundle, Box<dyn std::error::Error>> {
    let bytes = hex::decode(encoded)?;
    let bundle: OfflineBundle = serde_json::from_slice(&bytes)?;
    bundle
        .verify_content()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(bundle)
}

impl TrustRegistry {
    pub fn resolve(&self, issuer: &str, key_id: &str, now: u64) -> Result<VerifyingKey, Error> {
        let entry = self
            .keys
            .iter()
            .find(|entry| entry.issuer == issuer && entry.key_id == key_id)
            .ok_or(Error::UntrustedIssuer)?;
        if entry.revoked || now < entry.valid_from || now > entry.valid_until {
            return Err(Error::IssuerKeyExpired);
        }
        let bytes: [u8; 32] = entry
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedPublicKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| Error::MalformedPublicKey)
    }
}

impl OfflineBundle {
    pub fn verify(
        &self,
        registry: &TrustRegistry,
        replay_cache: &mut ReplayCache,
        now: u64,
    ) -> Result<AuthorizationDecision, Error> {
        self.verify_content()?;
        let issuer_bytes: [u8; 32] = self
            .issuer_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedPublicKey)?;
        let issuer_key =
            VerifyingKey::from_bytes(&issuer_bytes).map_err(|_| Error::MalformedPublicKey)?;
        let trusted_key = registry.resolve(
            &self.identity_commitment.issuer,
            &self.identity_commitment.issuer_key_id,
            now,
        )?;
        if trusted_key != issuer_key {
            return Err(Error::UntrustedIssuer);
        }
        let subject_bytes: [u8; 32] = self
            .subject_public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::MalformedPublicKey)?;
        let subject_key =
            VerifyingKey::from_bytes(&subject_bytes).map_err(|_| Error::MalformedPublicKey)?;
        if let Some(claims) = &self.identity_claims {
            self.identity_commitment
                .verify(claims, &issuer_key, &subject_key, now)?;
        }
        let mut verifier = OfflineVerifier {
            snapshot: self.revocation_snapshot.clone(),
            replay_cache: replay_cache.clone(),
        };
        let decision = verifier.verify_authorization(
            &self.presentation,
            &self.identity_commitment,
            &self.policy,
            &self.request,
            &issuer_key,
            &subject_key,
            now,
        );
        *replay_cache = verifier.replay_cache;
        decision
    }
}

impl OfflineVerifier {
    pub fn verify(
        &mut self,
        presentation: &AuthorizationPresentation,
        request: &AuthorizationRequest,
        issuer_key: &VerifyingKey,
        subject_key: &VerifyingKey,
        now: u64,
    ) -> Result<(), Error> {
        self.snapshot.verify(issuer_key, now)?;
        if presentation.issuer_epoch > self.snapshot.epoch {
            return Err(Error::IssuerEpochRejected);
        }
        if self
            .snapshot
            .revoked_key_ids
            .iter()
            .any(|id| id == &presentation.subject_key_id)
        {
            return Err(Error::SubjectKeyRevoked);
        }
        presentation.verify(request, issuer_key, subject_key, now)?;
        self.replay_cache
            .check_and_record(presentation.authorization_id)
    }

    /// Verify the complete offline identity and RBAC path.
    ///
    /// The verifier supplies the trusted issuer key, identity credential, and
    /// canonical policy bundle locally. No policy or identity service is
    /// contacted during this operation.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_authorization(
        &mut self,
        presentation: &AuthorizationPresentation,
        credential: &IdentityCommitment,
        policy: &Policy,
        request: &AuthorizationRequest,
        issuer_key: &VerifyingKey,
        subject_key: &VerifyingKey,
        now: u64,
    ) -> Result<AuthorizationDecision, Error> {
        policy.validate()?;
        credential.verify_binding(issuer_key, subject_key, now)?;
        if credential.claims_hash != presentation.identity_root
            || credential.key_id != presentation.subject_key_id
            || credential.policy_hash != hash(b"proofauth/policy/v1", policy)
        {
            return Err(Error::WrongRequest);
        }
        self.verify(presentation, request, issuer_key, subject_key, now)?;
        let identity = IdentityClaims {
            subject_type: "credential-subject".into(),
            tenant_ids: vec![presentation.tenant.clone()],
            roles: presentation.roles.clone(),
            attributes: serde_json::Value::Null,
            key_id: presentation.subject_key_id.clone(),
            valid_until: presentation.expires_at,
            issuer_epoch: presentation.issuer_epoch,
        };
        let decision = authorize(&identity, request, policy)?;
        let expected_policy_hash = hash(
            b"proofauth/policy-address/v1",
            &policy
                .address()
                .map_err(|_| Error::InvalidField("policy address"))?,
        );
        if !decision.allowed
            || decision.policy_hash != policy.address().unwrap_or_default()
            || presentation.policy_hash != expected_policy_hash
            || decision.matched_roles != presentation.roles
        {
            return Err(Error::AuthorizationDenied);
        }
        Ok(decision)
    }

    /// Registry-backed variant: the caller supplies no arbitrary issuer key.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_authorization_with_registry(
        &mut self,
        presentation: &AuthorizationPresentation,
        credential: &IdentityCommitment,
        policy: &Policy,
        request: &AuthorizationRequest,
        registry: &TrustRegistry,
        subject_key: &VerifyingKey,
        now: u64,
    ) -> Result<AuthorizationDecision, Error> {
        let issuer_key = registry.resolve(&credential.issuer, &credential.issuer_key_id, now)?;
        self.verify_authorization(
            presentation,
            credential,
            policy,
            request,
            &issuer_key,
            subject_key,
            now,
        )
    }
}

impl AuthorizationRequest {
    pub fn digest(&self) -> Hash {
        hash(b"proofauth/request/v1", self)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.recipient.is_empty() {
            return Err(Error::InvalidField("recipient"));
        }
        if self.tenant.is_empty() {
            return Err(Error::InvalidField("tenant"));
        }
        if self.resource.is_empty() {
            return Err(Error::InvalidField("resource"));
        }
        if self.action.is_empty() {
            return Err(Error::InvalidField("action"));
        }
        if self.expires_at <= self.issued_at {
            return Err(Error::InvalidField("time interval"));
        }
        Ok(())
    }
}

impl IdentityClaims {
    pub fn validate(&self) -> Result<(), Error> {
        if self.subject_type.is_empty() {
            return Err(Error::InvalidField("subject type"));
        }
        if self.key_id.is_empty() {
            return Err(Error::InvalidField("subject key id"));
        }
        if self.tenant_ids.iter().any(|value| value.is_empty()) {
            return Err(Error::InvalidField("tenant id"));
        }
        if self.roles.iter().any(|value| value.is_empty()) {
            return Err(Error::InvalidField("role"));
        }
        Ok(())
    }
}

impl AuthorizationPresentation {
    pub fn verify(
        &self,
        request: &AuthorizationRequest,
        issuer_key: &VerifyingKey,
        subject_key: &VerifyingKey,
        now: u64,
    ) -> Result<(), Error> {
        request.validate()?;
        if self.recipient != request.recipient {
            return Err(Error::WrongAudience);
        }
        if self.request_hash != request.digest() {
            return Err(Error::WrongRequest);
        }
        if self.action != request.action || self.resource != request.resource {
            return Err(Error::WrongRequest);
        }
        if now < self.issued_at || now > self.expires_at || now > request.expires_at {
            return Err(Error::InvalidTime);
        }
        let signature =
            Signature::from_slice(&self.issuer_signature).map_err(|_| Error::InvalidSignature)?;
        let unsigned = UnsignedPresentation::from(self);
        issuer_key
            .verify(&hash(b"proofauth/presentation/v1", &unsigned), &signature)
            .map_err(|_| Error::InvalidSignature)?;
        let subject_signature =
            Signature::from_slice(&self.subject_signature).map_err(|_| Error::InvalidSignature)?;
        subject_key
            .verify(
                &hash(
                    b"proofauth/possession/v1",
                    &PossessionBinding {
                        presentation: self.authorization_id,
                        request: self.request_hash,
                        nonce: request.nonce,
                    },
                ),
                &subject_signature,
            )
            .map_err(|_| Error::InvalidSignature)
    }
}

#[derive(Serialize)]
struct PossessionBinding {
    presentation: Hash,
    request: Hash,
    nonce: Hash,
}

#[derive(Serialize)]
struct UnsignedPresentation<'a> {
    identity_root: Hash,
    request_hash: Hash,
    recipient: &'a str,
    tenant: &'a str,
    workflow: &'a Option<String>,
    resource: &'a str,
    action: &'a str,
    policy_hash: Hash,
    authorization_id: Hash,
    issued_at: u64,
    expires_at: u64,
    issuer_epoch: u64,
    subject_key_id: &'a str,
    roles: &'a Vec<String>,
}

impl<'a> From<&'a AuthorizationPresentation> for UnsignedPresentation<'a> {
    fn from(p: &'a AuthorizationPresentation) -> Self {
        Self {
            identity_root: p.identity_root,
            request_hash: p.request_hash,
            recipient: &p.recipient,
            tenant: &p.tenant,
            workflow: &p.workflow,
            resource: &p.resource,
            action: &p.action,
            policy_hash: p.policy_hash,
            authorization_id: p.authorization_id,
            issued_at: p.issued_at,
            expires_at: p.expires_at,
            issuer_epoch: p.issuer_epoch,
            subject_key_id: &p.subject_key_id,
            roles: &p.roles,
        }
    }
}

pub fn identity_root(claims: &IdentityClaims) -> Hash {
    hash(b"proofauth/identity/v1", &normalized_identity(claims))
}

/// Normalize fields whose meaning is set-like before content addressing.
/// Arrays that represent ordered data must not be passed through this helper.
pub fn normalized_identity(claims: &IdentityClaims) -> IdentityClaims {
    let mut normalized = claims.clone();
    normalized.tenant_ids.sort();
    normalized.tenant_ids.dedup();
    normalized.roles.sort();
    normalized.roles.dedup();
    normalized
}

pub fn sign_presentation(
    mut presentation: AuthorizationPresentation,
    issuer_key: &SigningKey,
) -> AuthorizationPresentation {
    let unsigned = UnsignedPresentation::from(&presentation);
    presentation.issuer_signature = issuer_key
        .sign(&hash(b"proofauth/presentation/v1", &unsigned))
        .to_bytes()
        .to_vec();
    presentation
}

pub fn sign_subject_binding(
    mut presentation: AuthorizationPresentation,
    request: &AuthorizationRequest,
    subject_key: &SigningKey,
) -> AuthorizationPresentation {
    let binding = PossessionBinding {
        presentation: presentation.authorization_id,
        request: presentation.request_hash,
        nonce: request.nonce,
    };
    presentation.subject_signature = subject_key
        .sign(&hash(b"proofauth/possession/v1", &binding))
        .to_bytes()
        .to_vec();
    presentation
}

/// Convert an evaluated authorization decision into a recipient-bound,
/// dual-signed presentation.
pub fn issue_presentation(
    identity_root: Hash,
    request: &AuthorizationRequest,
    decision: &AuthorizationDecision,
    issuer_epoch: u64,
    issuer_key: &SigningKey,
    subject_key_id: String,
    subject_key: &SigningKey,
) -> Result<AuthorizationPresentation, Error> {
    request.validate()?;
    if !decision.allowed {
        return Err(Error::AuthorizationDenied);
    }
    if decision.permission != request.action
        || decision.tenant != request.tenant
        || decision.resource != request.resource
        || decision.workflow != request.workflow
    {
        return Err(Error::WrongRequest);
    }
    let unsigned = AuthorizationPresentation {
        identity_root,
        request_hash: request.digest(),
        recipient: request.recipient.clone(),
        tenant: request.tenant.clone(),
        workflow: request.workflow.clone(),
        resource: request.resource.clone(),
        action: request.action.clone(),
        policy_hash: hash(b"proofauth/policy-address/v1", &decision.policy_hash),
        authorization_id: hash(
            b"proofauth/authorization/v1",
            &(request.digest(), identity_root, issuer_epoch),
        ),
        issued_at: request.issued_at,
        expires_at: request.expires_at,
        issuer_epoch,
        issuer_signature: Vec::new(),
        subject_key_id,
        roles: decision.matched_roles.clone(),
        subject_signature: Vec::new(),
    };
    Ok(sign_subject_binding(
        sign_presentation(unsigned, issuer_key),
        request,
        subject_key,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn presentation_is_recipient_and_request_bound() {
        let issuer = SigningKey::generate(&mut OsRng);
        let request = AuthorizationRequest {
            recipient: "payment-control".into(),
            tenant: "acme".into(),
            workflow: Some("ap-2026".into()),
            resource: "invoice-8472".into(),
            action: "invoice.approve".into(),
            nonce: [7; 32],
            issued_at: 100,
            expires_at: 200,
        };
        let p = AuthorizationPresentation {
            identity_root: [1; 32],
            request_hash: request.digest(),
            recipient: request.recipient.clone(),
            tenant: request.tenant.clone(),
            workflow: request.workflow.clone(),
            resource: request.resource.clone(),
            action: request.action.clone(),
            policy_hash: [2; 32],
            authorization_id: [3; 32],
            issued_at: 100,
            expires_at: 200,
            issuer_epoch: 4,
            issuer_signature: vec![],
            subject_key_id: "subject-1".into(),
            roles: vec![],
            subject_signature: vec![],
        };
        let subject = SigningKey::generate(&mut OsRng);
        let p = sign_subject_binding(sign_presentation(p, &issuer), &request, &subject);
        assert!(p
            .verify(
                &request,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                150
            )
            .is_ok());
        let mut wrong = request.clone();
        wrong.recipient = "other-control".into();
        assert!(p
            .verify(
                &wrong,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                150
            )
            .is_err());
    }

    #[test]
    fn copied_presentation_without_subject_key_fails() {
        let issuer = SigningKey::generate(&mut OsRng);
        let subject = SigningKey::generate(&mut OsRng);
        let attacker = SigningKey::generate(&mut OsRng);
        let request = AuthorizationRequest {
            recipient: "control".into(),
            tenant: "acme".into(),
            workflow: None,
            resource: "resource".into(),
            action: "read".into(),
            nonce: [9; 32],
            issued_at: 1,
            expires_at: 10,
        };
        let p = AuthorizationPresentation {
            identity_root: [1; 32],
            request_hash: request.digest(),
            recipient: request.recipient.clone(),
            tenant: request.tenant.clone(),
            workflow: None,
            resource: request.resource.clone(),
            action: request.action.clone(),
            policy_hash: [2; 32],
            authorization_id: [3; 32],
            issued_at: 1,
            expires_at: 10,
            issuer_epoch: 1,
            issuer_signature: vec![],
            subject_key_id: "subject".into(),
            roles: vec![],
            subject_signature: vec![],
        };
        let p = sign_subject_binding(sign_presentation(p, &issuer), &request, &subject);
        assert!(p
            .verify(
                &request,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                5
            )
            .is_ok());
        assert!(p
            .verify(
                &request,
                &issuer.verifying_key(),
                &attacker.verifying_key(),
                5
            )
            .is_err());
    }

    #[test]
    fn identity_hash_is_content_based_for_set_like_fields() {
        let base = IdentityClaims {
            subject_type: "human".into(),
            tenant_ids: vec!["acme".into(), "beta".into()],
            roles: vec!["finance.approver".into(), "reviewer".into()],
            attributes: serde_json::json!({"clearance":"confidential"}),
            key_id: "key-1".into(),
            valid_until: 200,
            issuer_epoch: 4,
        };
        let reordered = IdentityClaims {
            tenant_ids: vec!["beta".into(), "acme".into(), "acme".into()],
            roles: vec!["reviewer".into(), "finance.approver".into()],
            ..base.clone()
        };
        assert_eq!(identity_root(&base), identity_root(&reordered));
    }

    #[test]
    fn identity_hash_changes_when_content_changes() {
        let mut claims = IdentityClaims {
            subject_type: "human".into(),
            tenant_ids: vec!["acme".into()],
            roles: vec!["reviewer".into()],
            attributes: serde_json::json!({}),
            key_id: "key-1".into(),
            valid_until: 200,
            issuer_epoch: 4,
        };
        let first = identity_root(&claims);
        claims.roles.push("approver".into());
        assert_ne!(first, identity_root(&claims));
    }

    #[test]
    fn uor_address_is_stable_for_reordered_identity_sets() {
        let base = IdentityClaims {
            subject_type: "human".into(),
            tenant_ids: vec!["acme".into(), "beta".into()],
            roles: vec!["finance.approver".into(), "reviewer".into()],
            attributes: serde_json::json!({"clearance":"confidential"}),
            key_id: "key-1".into(),
            valid_until: 200,
            issuer_epoch: 4,
        };
        let reordered = IdentityClaims {
            tenant_ids: vec!["beta".into(), "acme".into(), "acme".into()],
            roles: vec!["reviewer".into(), "finance.approver".into()],
            ..base.clone()
        };
        let first = uor_identity_address(&base).unwrap();
        assert_eq!(first, uor_identity_address(&reordered).unwrap());
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), 71);
    }

    fn example_identity() -> IdentityClaims {
        IdentityClaims {
            subject_type: "human".into(),
            tenant_ids: vec!["acme".into()],
            roles: vec!["finance.approver".into()],
            attributes: serde_json::json!({}),
            key_id: "key-1".into(),
            valid_until: 200,
            issuer_epoch: 1,
        }
    }

    fn example_request() -> AuthorizationRequest {
        AuthorizationRequest {
            recipient: "payment-control".into(),
            tenant: "acme".into(),
            workflow: Some("ap-2026".into()),
            resource: "invoice-8472".into(),
            action: "invoice.approve".into(),
            nonce: [8; 32],
            issued_at: 100,
            expires_at: 150,
        }
    }

    #[test]
    fn policy_inherits_parent_roles() {
        let policy = Policy {
            version: "1".into(),
            roles: vec![Role {
                name: "finance.approver".into(),
                parents: vec!["finance".into()],
            }],
            rules: std::collections::BTreeMap::from([(
                "finance".into(),
                vec![PermissionRule {
                    permission: "invoice.approve".into(),
                    effect: Effect::Allow,
                    tenants: vec!["acme".into()],
                    workflows: vec!["ap-2026".into()],
                    resources: vec![],
                }],
            )]),
        };
        assert!(authorize(&example_identity(), &example_request(), &policy).is_ok());
    }

    #[test]
    fn issue_encode_decode_and_verify_end_to_end() {
        let issuer = SigningKey::generate(&mut OsRng);
        let subject = SigningKey::generate(&mut OsRng);
        let identity = example_identity();
        let request = example_request();
        let policy = Policy {
            version: "1".into(),
            roles: vec![Role {
                name: "finance.approver".into(),
                parents: vec!["finance".into()],
            }],
            rules: std::collections::BTreeMap::from([(
                "finance".into(),
                vec![PermissionRule {
                    permission: "invoice.approve".into(),
                    effect: Effect::Allow,
                    tenants: vec!["acme".into()],
                    workflows: vec!["ap-2026".into()],
                    resources: vec![],
                }],
            )]),
        };
        let decision = authorize(&identity, &request, &policy).unwrap();
        let credential = issue_identity_commitment(
            "authority".into(),
            "issuer-key-1".into(),
            &identity,
            &policy,
            1,
            &issuer,
            &subject.verifying_key(),
        )
        .unwrap();
        let presentation = issue_presentation(
            identity_root(&identity),
            &request,
            &decision,
            1,
            &issuer,
            identity.key_id.clone(),
            &subject,
        )
        .unwrap();
        let encoded = encode_presentation(&presentation).unwrap();
        let decoded = decode_presentation(&encoded).unwrap();
        let snapshot = RevocationSnapshot {
            issuer: "authority".into(),
            epoch: 1,
            issued_at: 1,
            expires_at: 200,
            revoked_key_ids: vec![],
            signature: vec![],
        }
        .sign(&issuer);
        let bundle = OfflineBundle {
            identity_claims: Some(identity.clone()),
            identity_commitment: credential.clone(),
            policy: policy.clone(),
            request: request.clone(),
            presentation: decoded.clone(),
            revocation_snapshot: snapshot.clone(),
            issuer_public_key: issuer.verifying_key().to_bytes().to_vec(),
            subject_public_key: subject.verifying_key().to_bytes().to_vec(),
            content_hash: [0; 32],
        }
        .seal();
        let encoded_bundle = encode_offline_bundle(&bundle).unwrap();
        let decoded_bundle = decode_offline_bundle(&encoded_bundle).unwrap();
        assert_eq!(decoded_bundle.content_hash, bundle.content_hash);
        let mut registry = TrustRegistry {
            keys: vec![TrustedIssuerKey {
                issuer: "authority".into(),
                key_id: "issuer-key-1".into(),
                public_key: issuer.verifying_key().to_bytes().to_vec(),
                valid_from: 1,
                valid_until: 200,
                revoked: false,
            }],
        };
        let mut bundle_replay = ReplayCache::new();
        decoded_bundle
            .verify(&registry, &mut bundle_replay, 120)
            .unwrap();
        registry.keys[0].public_key[0] ^= 1;
        assert!(matches!(
            decoded_bundle.verify(&registry, &mut ReplayCache::new(), 120),
            Err(Error::MalformedPublicKey) | Err(Error::UntrustedIssuer)
        ));
        let mut verifier = OfflineVerifier {
            snapshot,
            replay_cache: ReplayCache::new(),
        };
        verifier
            .verify_authorization(
                &decoded,
                &credential,
                &policy,
                &request,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                120,
            )
            .unwrap();
    }

    #[test]
    fn malformed_identity_and_policy_are_rejected() {
        let mut identity = example_identity();
        identity.key_id.clear();
        assert!(matches!(
            identity.validate(),
            Err(Error::InvalidField("subject key id"))
        ));
        let policy = Policy {
            version: String::new(),
            roles: vec![],
            rules: std::collections::BTreeMap::new(),
        };
        assert!(matches!(
            policy.validate(),
            Err(Error::InvalidField("policy version"))
        ));
    }

    #[test]
    fn issuer_commitment_binds_identity_to_subject_key() {
        let issuer = SigningKey::generate(&mut OsRng);
        let subject = SigningKey::generate(&mut OsRng);
        let identity = example_identity();
        let policy = Policy {
            version: "1".into(),
            roles: vec![],
            rules: std::collections::BTreeMap::new(),
        };
        let credential = issue_identity_commitment(
            "authority".into(),
            "issuer-key-1".into(),
            &identity,
            &policy,
            1,
            &issuer,
            &subject.verifying_key(),
        )
        .unwrap();
        assert!(credential
            .verify(
                &identity,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                150
            )
            .is_ok());
        let attacker = SigningKey::generate(&mut OsRng);
        assert!(credential
            .verify(
                &identity,
                &issuer.verifying_key(),
                &attacker.verifying_key(),
                150
            )
            .is_err());
        let mut changed = identity.clone();
        changed.roles.push("administrator".into());
        assert!(credential
            .verify(
                &changed,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                150
            )
            .is_err());
    }

    #[test]
    fn deny_overrides_allow() {
        let policy = Policy {
            version: "1".into(),
            roles: vec![],
            rules: std::collections::BTreeMap::from([(
                "finance.approver".into(),
                vec![
                    PermissionRule {
                        permission: "invoice.approve".into(),
                        effect: Effect::Allow,
                        tenants: vec![],
                        workflows: vec![],
                        resources: vec![],
                    },
                    PermissionRule {
                        permission: "invoice.approve".into(),
                        effect: Effect::Deny,
                        tenants: vec!["acme".into()],
                        workflows: vec![],
                        resources: vec!["invoice-8472".into()],
                    },
                ],
            )]),
        };
        assert!(matches!(
            authorize(&example_identity(), &example_request(), &policy),
            Err(Error::AuthorizationDenied)
        ));
    }

    #[test]
    fn tenant_and_workflow_scope_are_enforced() {
        let policy = Policy {
            version: "1".into(),
            roles: vec![],
            rules: std::collections::BTreeMap::from([(
                "finance.approver".into(),
                vec![PermissionRule {
                    permission: "invoice.approve".into(),
                    effect: Effect::Allow,
                    tenants: vec!["other-tenant".into()],
                    workflows: vec!["ap-2026".into()],
                    resources: vec![],
                }],
            )]),
        };
        assert!(authorize(&example_identity(), &example_request(), &policy).is_err());
    }

    #[test]
    fn offline_verifier_enforces_snapshot_and_replay() {
        let issuer = SigningKey::generate(&mut OsRng);
        let subject = SigningKey::generate(&mut OsRng);
        let request = AuthorizationRequest {
            recipient: "control".into(),
            tenant: "acme".into(),
            workflow: None,
            resource: "resource".into(),
            action: "read".into(),
            nonce: [4; 32],
            issued_at: 1,
            expires_at: 10,
        };
        let p = AuthorizationPresentation {
            identity_root: [1; 32],
            request_hash: request.digest(),
            recipient: request.recipient.clone(),
            tenant: request.tenant.clone(),
            workflow: None,
            resource: request.resource.clone(),
            action: request.action.clone(),
            policy_hash: [2; 32],
            authorization_id: [5; 32],
            issued_at: 1,
            expires_at: 10,
            issuer_epoch: 2,
            issuer_signature: vec![],
            subject_key_id: "subject".into(),
            roles: vec![],
            subject_signature: vec![],
        };
        let p = sign_subject_binding(sign_presentation(p, &issuer), &request, &subject);
        let snapshot = RevocationSnapshot {
            issuer: "issuer".into(),
            epoch: 2,
            issued_at: 1,
            expires_at: 20,
            revoked_key_ids: vec![],
            signature: vec![],
        }
        .sign(&issuer);
        let mut verifier = OfflineVerifier {
            snapshot,
            replay_cache: ReplayCache::new(),
        };
        assert!(verifier
            .verify(
                &p,
                &request,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                5
            )
            .is_ok());
        assert!(matches!(
            verifier.verify(
                &p,
                &request,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                5
            ),
            Err(Error::ReplayDetected)
        ));
    }

    #[test]
    fn offline_verifier_rejects_revoked_subject() {
        let issuer = SigningKey::generate(&mut OsRng);
        let subject = SigningKey::generate(&mut OsRng);
        let request = AuthorizationRequest {
            recipient: "control".into(),
            tenant: "acme".into(),
            workflow: None,
            resource: "resource".into(),
            action: "read".into(),
            nonce: [6; 32],
            issued_at: 1,
            expires_at: 10,
        };
        let p = AuthorizationPresentation {
            identity_root: [1; 32],
            request_hash: request.digest(),
            recipient: request.recipient.clone(),
            tenant: request.tenant.clone(),
            workflow: None,
            resource: request.resource.clone(),
            action: request.action.clone(),
            policy_hash: [2; 32],
            authorization_id: [7; 32],
            issued_at: 1,
            expires_at: 10,
            issuer_epoch: 1,
            issuer_signature: vec![],
            subject_key_id: "subject".into(),
            roles: vec![],
            subject_signature: vec![],
        };
        let p = sign_subject_binding(sign_presentation(p, &issuer), &request, &subject);
        let snapshot = RevocationSnapshot {
            issuer: "issuer".into(),
            epoch: 1,
            issued_at: 1,
            expires_at: 20,
            revoked_key_ids: vec!["subject".into()],
            signature: vec![],
        }
        .sign(&issuer);
        let mut verifier = OfflineVerifier {
            snapshot,
            replay_cache: ReplayCache::new(),
        };
        assert!(matches!(
            verifier.verify(
                &p,
                &request,
                &issuer.verifying_key(),
                &subject.verifying_key(),
                5
            ),
            Err(Error::SubjectKeyRevoked)
        ));
    }

    #[test]
    fn trust_registry_resolves_rotated_issuer_keys() {
        let issuer = SigningKey::generate(&mut OsRng);
        let registry = TrustRegistry {
            keys: vec![TrustedIssuerKey {
                issuer: "authority".into(),
                key_id: "key-2".into(),
                public_key: issuer.verifying_key().to_bytes().to_vec(),
                valid_from: 100,
                valid_until: 200,
                revoked: false,
            }],
        };
        assert_eq!(
            registry.resolve("authority", "key-2", 150).unwrap(),
            issuer.verifying_key()
        );
        assert!(matches!(
            registry.resolve("authority", "key-2", 99),
            Err(Error::IssuerKeyExpired)
        ));
        assert!(matches!(
            registry.resolve("authority", "missing", 150),
            Err(Error::UntrustedIssuer)
        ));
    }

    #[test]
    fn signed_registry_requires_pinned_root() {
        let root = SigningKey::generate(&mut OsRng);
        let issuer = SigningKey::generate(&mut OsRng);
        let document = SignedTrustRegistry {
            version: "1".into(),
            issuer: "root".into(),
            epoch: 1,
            keys: vec![TrustedIssuerKey {
                issuer: "authority".into(),
                key_id: "issuer-1".into(),
                public_key: issuer.verifying_key().to_bytes().to_vec(),
                valid_from: 1,
                valid_until: 100,
                revoked: false,
            }],
            signature: vec![],
        }
        .sign(&root);
        assert!(document.verify(&root.verifying_key()).is_ok());
        let other = SigningKey::generate(&mut OsRng);
        assert!(matches!(
            document.verify(&other.verifying_key()),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn malformed_requests_are_rejected_before_crypto() {
        let request = AuthorizationRequest {
            recipient: String::new(),
            tenant: "acme".into(),
            workflow: None,
            resource: "r".into(),
            action: "read".into(),
            nonce: [0; 32],
            issued_at: 10,
            expires_at: 10,
        };
        assert!(matches!(
            request.validate(),
            Err(Error::InvalidField("recipient"))
        ));
    }

    #[test]
    fn uor_json_golden_vector_matches_reference() {
        let outcome = uor_addr::json::address(br#"{"foo":"bar"}"#).unwrap();
        assert_eq!(
            outcome.address.to_string(),
            "sha256:7a38bf81f383f69433ad6e900d35b3e2385593f76a7b7ab5d4355b8ba41ee24b"
        );
    }

    #[test]
    fn presentation_jcs_round_trips() {
        let presentation = AuthorizationPresentation {
            identity_root: [1; 32],
            request_hash: [2; 32],
            recipient: "control".into(),
            tenant: "acme".into(),
            workflow: None,
            resource: "resource".into(),
            action: "read".into(),
            policy_hash: [3; 32],
            authorization_id: [4; 32],
            issued_at: 1,
            expires_at: 10,
            issuer_epoch: 1,
            issuer_signature: vec![5; 64],
            subject_key_id: "subject".into(),
            roles: vec![],
            subject_signature: vec![6; 64],
        };
        let encoded = encode_presentation(&presentation).unwrap();
        let decoded = decode_presentation(&encoded).unwrap();
        assert_eq!(decoded.recipient, presentation.recipient);
        assert_eq!(decoded.authorization_id, presentation.authorization_id);
        assert_eq!(decoded.issuer_signature, presentation.issuer_signature);
    }
}
