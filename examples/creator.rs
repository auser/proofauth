//! Creates the sender-side artifacts consumed by `consumer.rs`.
//!
//! Run with:
//!   cargo run --example creator
//!   cargo run --example consumer

use ed25519_dalek::SigningKey;
use proofauth::{
    authorize, encode_offline_bundle, encode_presentation, identity_root,
    issue_identity_commitment, issue_presentation, uor_identity_address, uor_policy_address,
    AuthorizationRequest, Effect, IdentityClaims, PermissionRule, Policy, RevocationSnapshot, Role,
};
use serde::Serialize;
use std::{collections::BTreeMap, fs, path::PathBuf};

#[derive(Serialize)]
struct DemoKeys {
    issuer_public: String,
    subject_public: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let subject = SigningKey::from_bytes(&[2; 32]);
    let identity = IdentityClaims {
        subject_type: "human".into(),
        tenant_ids: vec!["acme".into()],
        roles: vec!["finance.approver".into()],
        attributes: serde_json::json!({"clearance": "confidential"}),
        key_id: "subject-key-1".into(),
        valid_until: 1_200,
        issuer_epoch: 7,
    };
    let policy = Policy {
        version: "1".into(),
        roles: vec![Role {
            name: "finance.approver".into(),
            parents: vec!["finance".into()],
        }],
        rules: BTreeMap::from([(
            "finance".into(),
            vec![PermissionRule {
                permission: "invoice.approve".into(),
                effect: Effect::Allow,
                tenants: vec!["acme".into()],
                workflows: vec!["ap-2026".into()],
                resources: vec!["invoice-8472".into()],
            }],
        )]),
    };
    let request = AuthorizationRequest {
        recipient: "payment-control".into(),
        tenant: "acme".into(),
        workflow: Some("ap-2026".into()),
        resource: "invoice-8472".into(),
        action: "invoice.approve".into(),
        nonce: [9; 32],
        issued_at: 1_000,
        expires_at: 1_100,
    };
    let decision = authorize(&identity, &request, &policy)?;
    let commitment = issue_identity_commitment(
        "authority".into(),
        "issuer-key-1".into(),
        &identity,
        &policy,
        7,
        &issuer,
        &subject.verifying_key(),
    )?;
    let presentation = issue_presentation(
        identity_root(&identity),
        &request,
        &decision,
        7,
        &issuer,
        identity.key_id.clone(),
        &subject,
    )?;
    let snapshot = RevocationSnapshot {
        issuer: "authority".into(),
        epoch: 7,
        issued_at: 900,
        expires_at: 1_200,
        revoked_key_ids: vec![],
        signature: vec![],
    }
    .sign(&issuer);

    let bundle = proofauth::OfflineBundle {
        identity_claims: Some(identity.clone()),
        identity_commitment: commitment.clone(),
        policy: policy.clone(),
        request: request.clone(),
        presentation: presentation.clone(),
        revocation_snapshot: snapshot.clone(),
        issuer_public_key: issuer.verifying_key().to_bytes().to_vec(),
        subject_public_key: subject.verifying_key().to_bytes().to_vec(),
        content_hash: [0; 32],
    }
    .seal();

    let dir = PathBuf::from("target/proofauth-demo");
    fs::create_dir_all(&dir)?;
    fs::write(
        dir.join("presentation.json"),
        encode_presentation(&presentation)?,
    )?;
    fs::write(
        dir.join("offline-bundle.hex"),
        encode_offline_bundle(&bundle)?,
    )?;
    fs::write(
        dir.join("identity-commitment.json"),
        serde_json::to_vec_pretty(&commitment)?,
    )?;
    fs::write(
        dir.join("request.json"),
        serde_json::to_vec_pretty(&request)?,
    )?;
    fs::write(dir.join("policy.json"), serde_json::to_vec_pretty(&policy)?)?;
    fs::write(
        dir.join("snapshot.json"),
        serde_json::to_vec_pretty(&snapshot)?,
    )?;
    fs::write(
        dir.join("keys.json"),
        serde_json::to_vec_pretty(&DemoKeys {
            issuer_public: hex::encode(issuer.verifying_key().to_bytes()),
            subject_public: hex::encode(subject.verifying_key().to_bytes()),
        })?,
    )?;

    println!("created {}", dir.display());
    println!("identity root: {}", hex::encode(identity_root(&identity)));
    println!("identity UOR address: {}", uor_identity_address(&identity)?);
    println!("policy UOR address: {}", uor_policy_address(&policy)?);
    println!("presentation: {}", dir.join("presentation.json").display());
    Ok(())
}
