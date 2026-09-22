use proofauth::{AuthorizationRequest, Effect, IdentityClaims, PermissionRule, Policy, Role};
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
        let path = std::env::temp_dir().join(format!(
            "proofauth-generate-example-{}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create temporary test directory");
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

fn run_generate(output: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_proofauth"))
        .args(["generate-example", "--output"])
        .arg(output)
        .output()
        .expect("run proofauth generate-example")
}

#[test]
fn generates_all_documents_as_expected_types() {
    let temporary = TempDir::new();
    let output = temporary.path().join("nested/demo-data");

    let result = run_generate(&output);
    assert!(
        result.status.success(),
        "generator failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let identity: IdentityClaims =
        serde_json::from_slice(&fs::read(output.join("identity.json")).unwrap()).unwrap();
    let policy: Policy =
        serde_json::from_slice(&fs::read(output.join("policy.json")).unwrap()).unwrap();
    let request: AuthorizationRequest =
        serde_json::from_slice(&fs::read(output.join("request.json")).unwrap()).unwrap();

    assert_eq!(identity.subject_type, "human");
    assert_eq!(identity.tenant_ids, ["acme"]);
    assert_eq!(identity.roles, ["finance.approver"]);
    assert_eq!(
        identity.attributes,
        serde_json::json!({"clearance": "confidential"})
    );
    assert_eq!(identity.key_id, "subject-key-1");
    assert_eq!(identity.valid_until, 1_200);
    assert_eq!(identity.issuer_epoch, 7);

    assert_eq!(
        policy,
        Policy {
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
                    resources: vec!["invoice-8472".into()],
                }],
            )]),
        }
    );

    assert_eq!(request.recipient, "payment-control");
    assert_eq!(request.tenant, "acme");
    assert_eq!(request.workflow.as_deref(), Some("ap-2026"));
    assert_eq!(request.resource, "invoice-8472");
    assert_eq!(request.action, "invoice.approve");
    assert_eq!(request.nonce, [9; 32]);
    assert_eq!(request.issued_at, 1_000);
    assert_eq!(request.expires_at, 1_100);
}

#[test]
fn overwrites_existing_documents_and_preserves_unrelated_files() {
    let output = TempDir::new();
    let identity_path = output.path().join("identity.json");
    let policy_path = output.path().join("policy.json");
    let request_path = output.path().join("request.json");
    let unrelated_path = output.path().join("keep.txt");
    fs::write(&identity_path, b"old identity").unwrap();
    fs::write(&policy_path, b"old policy").unwrap();
    fs::write(&request_path, b"old request").unwrap();
    fs::write(&unrelated_path, b"keep this content").unwrap();

    let result = run_generate(output.path());

    assert!(
        result.status.success(),
        "generator failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice::<IdentityClaims>(&fs::read(identity_path).unwrap()).unwrap();
    serde_json::from_slice::<Policy>(&fs::read(policy_path).unwrap()).unwrap();
    serde_json::from_slice::<AuthorizationRequest>(&fs::read(request_path).unwrap()).unwrap();
    assert_eq!(fs::read(unrelated_path).unwrap(), b"keep this content");
}

#[test]
fn reports_when_output_path_is_not_a_directory() {
    let temporary = TempDir::new();
    let output = temporary.path().join("not-a-directory");
    fs::write(&output, b"existing file").unwrap();

    let result = run_generate(&output);

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(stderr.contains("output path"), "unexpected error: {stderr}");
    assert!(
        stderr.contains("is not a directory"),
        "unexpected error: {stderr}"
    );
    assert_eq!(fs::read(output).unwrap(), b"existing file");
}
