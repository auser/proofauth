use ed25519_dalek::SigningKey;
use proofauth::{
    authorize, identity_root, issue_identity_commitment, issue_presentation, uor_identity_address,
    uor_policy_address, AuthorizationRequest, IdentityClaims, OfflineBundle, Policy,
    RevocationSnapshot, SignedTrustRegistry, TrustedIssuerKey,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("proofauth-cli-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("create temporary CLI test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_proofauth"))
        .args(arguments)
        .output()
        .expect("run proofauth CLI")
}

fn file_argument(path: &Path) -> String {
    format!("@{}", path.display())
}

#[test]
fn cli_and_library_addresses_and_decisions_agree() {
    let identity_path = Path::new("demo-data/identity.json");
    let policy_path = Path::new("demo-data/policy.json");
    let request_path = Path::new("demo-data/request.json");
    let identity: IdentityClaims =
        serde_json::from_slice(&fs::read(identity_path).unwrap()).unwrap();
    let policy: Policy = serde_json::from_slice(&fs::read(policy_path).unwrap()).unwrap();

    let identity_output = run(&["identity-address".into(), file_argument(identity_path)]);
    assert!(identity_output.status.success());
    assert_eq!(
        String::from_utf8(identity_output.stdout).unwrap().trim(),
        uor_identity_address(&identity).unwrap()
    );

    let policy_output = run(&["policy-address".into(), file_argument(policy_path)]);
    assert!(policy_output.status.success());
    assert_eq!(
        String::from_utf8(policy_output.stdout).unwrap().trim(),
        uor_policy_address(&policy).unwrap()
    );

    let allowed = run(&[
        "authorize".into(),
        file_argument(identity_path),
        file_argument(policy_path),
        file_argument(request_path),
    ]);
    assert!(allowed.status.success());
    assert_eq!(String::from_utf8(allowed.stdout).unwrap().trim(), "allowed");

    let temporary = TempDir::new();
    let mut denied_request: AuthorizationRequest =
        serde_json::from_slice(&fs::read(request_path).unwrap()).unwrap();
    denied_request.resource = "invoice-0000".into();
    let denied_path = temporary.path().join("denied-request.json");
    fs::write(
        &denied_path,
        serde_json::to_vec_pretty(&denied_request).unwrap(),
    )
    .unwrap();
    let denied = run(&[
        "authorize".into(),
        file_argument(identity_path),
        file_argument(policy_path),
        file_argument(&denied_path),
    ]);
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("AuthorizationDenied"));

    let issuer = SigningKey::from_bytes(&[1; 32]);
    let subject = SigningKey::from_bytes(&[2; 32]);
    let issued = run(&[
        "issue".into(),
        file_argument(identity_path),
        file_argument(policy_path),
        file_argument(request_path),
        "--issuer-secret".into(),
        hex::encode(issuer.to_bytes()),
        "--subject-secret".into(),
        hex::encode(subject.to_bytes()),
        "--subject-key-id".into(),
        identity.key_id.clone(),
        "--issuer-epoch".into(),
        identity.issuer_epoch.to_string(),
    ]);
    assert!(issued.status.success());
    let presentation_path = temporary.path().join("presentation.json");
    fs::write(&presentation_path, issued.stdout).unwrap();
    let snapshot = RevocationSnapshot {
        issuer: "authority".into(),
        epoch: 7,
        issued_at: 900,
        expires_at: 1_200,
        revoked_key_ids: vec![],
        signature: vec![],
    }
    .sign(&issuer);
    let snapshot_path = temporary.path().join("snapshot.json");
    fs::write(
        &snapshot_path,
        serde_json::to_vec_pretty(&snapshot).unwrap(),
    )
    .unwrap();
    let verified = run(&[
        "verify".into(),
        file_argument(&presentation_path),
        file_argument(request_path),
        file_argument(&snapshot_path),
        "--issuer-public".into(),
        hex::encode(issuer.verifying_key().to_bytes()),
        "--subject-public".into(),
        hex::encode(subject.verifying_key().to_bytes()),
        "--now".into(),
        "1050".into(),
    ]);
    assert!(verified.status.success());
    assert_eq!(String::from_utf8(verified.stdout).unwrap().trim(), "valid");
}

#[test]
fn cli_signs_and_verifies_registry_with_pinned_root() {
    let temporary = TempDir::new();
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
    };
    let unsigned_path = temporary.path().join("unsigned-registry.json");
    fs::write(
        &unsigned_path,
        serde_json::to_vec_pretty(&registry).unwrap(),
    )
    .unwrap();

    let signed_output = run(&[
        "registry-sign".into(),
        file_argument(&unsigned_path),
        "--root-secret".into(),
        hex::encode(root.to_bytes()),
    ]);
    assert!(
        signed_output.status.success(),
        "registry signing failed: {}",
        String::from_utf8_lossy(&signed_output.stderr)
    );
    let signed: SignedTrustRegistry = serde_json::from_slice(&signed_output.stdout).unwrap();
    signed.verify(&root.verifying_key()).unwrap();

    let signed_path = temporary.path().join("registry.json");
    fs::write(&signed_path, &signed_output.stdout).unwrap();
    let verified = run(&[
        "registry-verify".into(),
        file_argument(&signed_path),
        "--root-public".into(),
        hex::encode(root.verifying_key().to_bytes()),
    ]);
    assert!(verified.status.success());
    assert_eq!(String::from_utf8(verified.stdout).unwrap().trim(), "valid");

    let subject = SigningKey::from_bytes(&[2; 32]);
    let identity: IdentityClaims =
        serde_json::from_slice(&fs::read("demo-data/identity.json").unwrap()).unwrap();
    let policy: Policy =
        serde_json::from_slice(&fs::read("demo-data/policy.json").unwrap()).unwrap();
    let request: AuthorizationRequest =
        serde_json::from_slice(&fs::read("demo-data/request.json").unwrap()).unwrap();
    let decision = authorize(&identity, &request, &policy).unwrap();
    let identity_commitment = issue_identity_commitment(
        "authority".into(),
        "issuer-key-1".into(),
        &identity,
        &policy,
        7,
        &issuer,
        &subject.verifying_key(),
    )
    .unwrap();
    let presentation = issue_presentation(
        identity_root(&identity),
        &request,
        &decision,
        7,
        &issuer,
        identity.key_id.clone(),
        &subject,
    )
    .unwrap();
    let snapshot = RevocationSnapshot {
        issuer: "authority".into(),
        epoch: 7,
        issued_at: 900,
        expires_at: 1_200,
        revoked_key_ids: vec![],
        signature: vec![],
    }
    .sign(&issuer);
    let unsealed = OfflineBundle {
        identity_claims: Some(identity),
        identity_commitment,
        policy,
        request,
        presentation,
        revocation_snapshot: snapshot,
        issuer_public_key: issuer.verifying_key().to_bytes().to_vec(),
        subject_public_key: subject.verifying_key().to_bytes().to_vec(),
        content_hash: [0; 32],
    };
    let bundle_json_path = temporary.path().join("bundle.json");
    fs::write(
        &bundle_json_path,
        serde_json::to_vec_pretty(&unsealed).unwrap(),
    )
    .unwrap();
    let sealed = run(&["bundle-seal".into(), file_argument(&bundle_json_path)]);
    assert!(sealed.status.success());
    let encoded = String::from_utf8(sealed.stdout).unwrap();
    assert!(encoded
        .trim()
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    let bundle_path = temporary.path().join("offline-bundle.hex");
    fs::write(&bundle_path, encoded).unwrap();
    let bundle_verified = run(&[
        "bundle-verify".into(),
        file_argument(&bundle_path),
        file_argument(&signed_path),
        "--root-public".into(),
        hex::encode(root.verifying_key().to_bytes()),
        "--now".into(),
        "1050".into(),
    ]);
    assert!(
        bundle_verified.status.success(),
        "bundle verification failed: {}",
        String::from_utf8_lossy(&bundle_verified.stderr)
    );
    assert_eq!(
        String::from_utf8(bundle_verified.stdout).unwrap().trim(),
        "valid"
    );
}
