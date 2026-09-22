//! Consumer-side offline verification using one token and local trust material.

use ed25519_dalek::SigningKey;
use proofauth::{authorize, decode_offline_bundle, Error, ReplayCache, SignedTrustRegistry};
use std::{fs, io, path::PathBuf};

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
    let identity = bundle
        .identity_claims
        .as_ref()
        .ok_or_else(|| io::Error::other("demo bundle must disclose identity claims"))?;
    let mut denied_request = bundle.request.clone();
    denied_request.resource = "invoice-0000".into();
    match authorize(identity, &denied_request, &bundle.policy) {
        Err(Error::AuthorizationDenied) => println!(
            "denied: resource={} reason=authorization denied",
            denied_request.resource
        ),
        result => {
            return Err(io::Error::other(format!("expected denied request, got {result:?}")).into())
        }
    }
    println!("verified offline from one hex token plus locally trusted registry material");
    Ok(())
}
