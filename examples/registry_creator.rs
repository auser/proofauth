//! Create a signed issuer registry for the local registry server demo.

use ed25519_dalek::SigningKey;
use proofauth::{SignedTrustRegistry, TrustedIssuerKey};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = SigningKey::from_bytes(&[3; 32]);
    let issuer = SigningKey::from_bytes(&[1; 32]);
    let registry = SignedTrustRegistry {
        version: "1".into(),
        issuer: "proofauth-root".into(),
        epoch: 1,
        keys: vec![TrustedIssuerKey {
            issuer: "authority".into(),
            key_id: "issuer-key-1".into(),
            public_key: issuer.verifying_key().to_bytes().to_vec(),
            valid_from: 900,
            valid_until: 1_200,
            revoked: false,
        }],
        signature: vec![],
    }
    .sign(&root);
    fs::create_dir_all("target/proofauth-demo")?;
    fs::write(
        "target/proofauth-demo/registry.json",
        serde_json::to_vec_pretty(&registry)?,
    )?;
    println!("registry: target/proofauth-demo/registry.json");
    println!(
        "pinned root public key: {}",
        hex::encode(root.verifying_key().to_bytes())
    );
    Ok(())
}
