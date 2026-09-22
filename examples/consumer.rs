//! Consumer-side offline verification. This process receives no identity claims.

use ed25519_dalek::SigningKey;
use proofauth::{decode_offline_bundle, ReplayCache, SignedTrustRegistry};
use std::{fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from("target/proofauth-demo");
    let encoded = fs::read_to_string(dir.join("offline-bundle.hex"))?;
    let bundle = decode_offline_bundle(encoded.trim())?;
    // In production this root public key is pinned/configured independently.
    let root = SigningKey::from_bytes(&[3; 32]);
    let signed_registry: SignedTrustRegistry =
        serde_json::from_slice(&fs::read(dir.join("registry.json"))?)?;
    let registry = signed_registry.verify(&root.verifying_key())?;
    let mut replay_cache = ReplayCache::new();
    bundle.verify(&registry, &mut replay_cache, 1_050)?;
    println!(
        "accepted: recipient={} action={} tenant={} subject_key_id={}",
        bundle.presentation.recipient,
        bundle.presentation.action,
        bundle.presentation.tenant,
        bundle.presentation.subject_key_id
    );
    println!("the consumer validated one hex token offline without receiving the identity claims");
    Ok(())
}
