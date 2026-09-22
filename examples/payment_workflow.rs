//! A narrative RBAC example for an accounts-payable application.
//!
//! Run with:
//!   cargo run --example payment_workflow

use ed25519_dalek::SigningKey;
use proofauth::{
    authorize, decode_offline_bundle, encode_offline_bundle, identity_root,
    issue_identity_commitment, issue_presentation, AuthorizationRequest, Effect, Error,
    IdentityClaims, OfflineBundle, PermissionRule, Policy, RevocationSnapshot, Role,
};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

struct OutputStyle {
    color: bool,
}

impl OutputStyle {
    fn detect() -> Self {
        Self {
            color: io::stdout().is_terminal() && env::var_os("NO_COLOR").is_none(),
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }
}

fn payment_request(action: &str, resource: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        recipient: "payment-api".into(),
        tenant: "acme".into(),
        workflow: Some("ap-2026".into()),
        resource: resource.into(),
        action: action.into(),
        nonce: [9; 32],
        issued_at: 1_000,
        expires_at: 1_100,
    }
}

fn expect_denied(
    identity: &IdentityClaims,
    request: &AuthorizationRequest,
    policy: &Policy,
) -> Result<(), Box<dyn std::error::Error>> {
    match authorize(identity, request, policy) {
        Err(Error::AuthorizationDenied) => Ok(()),
        result => {
            Err(io::Error::other(format!("expected authorization denial, got {result:?}")).into())
        }
    }
}

fn formatted_request(request: &AuthorizationRequest) -> Result<String, serde_json::Error> {
    Ok(format!(
        concat!(
            "{{\n",
            "  \"recipient\": {},\n",
            "  \"tenant\": {},\n",
            "  \"workflow\": {},\n",
            "  \"resource\": {},\n",
            "  \"action\": {},\n",
            "  \"nonce\": {},\n",
            "  \"issued_at\": {},\n",
            "  \"expires_at\": {}\n",
            "}}"
        ),
        serde_json::to_string(&request.recipient)?,
        serde_json::to_string(&request.tenant)?,
        serde_json::to_string(&request.workflow)?,
        serde_json::to_string(&request.resource)?,
        serde_json::to_string(&request.action)?,
        serde_json::to_string(&request.nonce)?,
        request.issued_at,
        request.expires_at,
    ))
}

fn colorize_json(json: &str, style: &OutputStyle) -> String {
    if !style.color {
        return json.to_owned();
    }

    let bytes = json.as_bytes();
    let mut output = String::with_capacity(json.len() * 2);
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            let mut escaped = false;
            while index < bytes.len() {
                let byte = bytes[index];
                index += 1;
                if !escaped && byte == b'"' {
                    break;
                }
                escaped = !escaped && byte == b'\\';
            }
            let mut next = index;
            while next < bytes.len() && bytes[next].is_ascii_whitespace() {
                next += 1;
            }
            let code = if next < bytes.len() && bytes[next] == b':' {
                "1;36"
            } else {
                "32"
            };
            output.push_str(&style.paint(code, &json[start..index]));
        } else if bytes[index].is_ascii_digit() || bytes[index] == b'-' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit()
                    || matches!(bytes[index], b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                index += 1;
            }
            output.push_str(&style.paint("33", &json[start..index]));
        } else if json[index..].starts_with("true") {
            output.push_str(&style.paint("35", "true"));
            index += 4;
        } else if json[index..].starts_with("false") {
            output.push_str(&style.paint("35", "false"));
            index += 5;
        } else if json[index..].starts_with("null") {
            output.push_str(&style.paint("35", "null"));
            index += 4;
        } else {
            let character = bytes[index] as char;
            if matches!(character, '{' | '}' | '[' | ']' | ':' | ',') {
                output.push_str(&style.paint("90", &character.to_string()));
            } else {
                output.push(character);
            }
            index += 1;
        }
    }
    output
}

fn print_payload(
    request: &AuthorizationRequest,
    style: &OutputStyle,
) -> Result<(), serde_json::Error> {
    let label = format!(
        "Her client sends this JSON request to `{}`:",
        request.recipient
    );
    println!("   {}", style.paint("1;35", &label));
    for line in colorize_json(&formatted_request(request)?, style).lines() {
        println!("   {line}");
    }
    Ok(())
}

fn write_pretty_json<T: Serialize>(path: &Path, value: &T) -> Result<(), io::Error> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        io::Error::other(format!("failed to serialize {}: {error}", path.display()))
    })?;
    bytes.push(b'\n');
    fs::write(path, bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let style = OutputStyle::detect();

    // Acme's identity issuer says Priya is a finance approver. The policy below
    // makes that role inherit the less-privileged finance.viewer role.
    let priya = IdentityClaims {
        subject_type: "human".into(),
        tenant_ids: vec!["acme".into()],
        roles: vec!["finance.approver".into()],
        attributes: serde_json::json!({"display_name": "Priya"}),
        key_id: "priya-key-1".into(),
        valid_until: 1_200,
        issuer_epoch: 7,
    };

    let policy = Policy {
        version: "1".into(),
        roles: vec![
            Role {
                name: "finance.approver".into(),
                parents: vec!["finance.viewer".into()],
            },
            Role {
                name: "finance.suspended".into(),
                parents: vec![],
            },
        ],
        rules: BTreeMap::from([
            (
                "finance.viewer".into(),
                vec![PermissionRule {
                    permission: "payment.view".into(),
                    effect: Effect::Allow,
                    tenants: vec!["acme".into()],
                    workflows: vec!["ap-2026".into()],
                    resources: vec!["payment-8472".into()],
                }],
            ),
            (
                "finance.approver".into(),
                vec![PermissionRule {
                    permission: "payment.approve".into(),
                    effect: Effect::Allow,
                    tenants: vec!["acme".into()],
                    workflows: vec!["ap-2026".into()],
                    resources: vec!["payment-8472".into()],
                }],
            ),
            (
                "finance.suspended".into(),
                vec![PermissionRule {
                    permission: "payment.approve".into(),
                    effect: Effect::Deny,
                    tenants: vec!["acme".into()],
                    workflows: vec!["ap-2026".into()],
                    resources: vec!["payment-8472".into()],
                }],
            ),
        ]),
    };

    let output_dir = PathBuf::from("target/proofauth-payment-demo");
    let identity_path = output_dir.join("identity.json");
    let policy_path = output_dir.join("policy.json");
    let view_request_path = output_dir.join("view-request.json");
    let request_path = output_dir.join("request.json");
    let bundle_json_path = output_dir.join("offline-bundle.json");
    let bundle_hex_path = output_dir.join("offline-bundle.hex");
    fs::create_dir_all(&output_dir)?;
    write_pretty_json(&identity_path, &priya)?;
    write_pretty_json(&policy_path, &policy)?;

    println!(
        "{}",
        style.paint("1;36", "=== A day at Acme: Priya approves a payment ===")
    );
    println!("Priya works in accounts payable. A new payment, payment-8472, needs review.");
    println!("The payment-api will show or approve it only after receiving verifiable proof.");
    println!("Before today, Acme's issuer gave Priya the finance.approver role.");
    println!();

    let view = payment_request("payment.view", "payment-8472");
    write_pretty_json(&view_request_path, &view)?;
    println!(
        "{}",
        style.paint(
            "1;34",
            "Chapter 1 — Priya wants to see what she is being asked to approve."
        )
    );
    println!("   She clicks “View payment” in her client.");
    print_payload(&view, &style)?;
    println!("   Saved request: {}", view_request_path.display());
    println!("   ProofAuth compares Priya's identity with Acme's policy.");
    let view_decision = authorize(&priya, &view, &policy)?;
    let view_result = format!(
        "Result: ALLOWED. Her approver role inherits viewer access through {}.",
        view_decision.matched_roles.join(", ")
    );
    println!("   {}", style.paint("1;32", &view_result));
    println!();

    let approve = payment_request("payment.approve", "payment-8472");
    write_pretty_json(&request_path, &approve)?;
    println!(
        "{}",
        style.paint(
            "1;34",
            "Chapter 2 — The details look right, so Priya wants to approve the payment."
        )
    );
    println!("   She clicks “Approve payment” in her client, which creates a new request.");
    print_payload(&approve, &style)?;
    println!("   Saved request: {}", request_path.display());
    println!("   ProofAuth evaluates the new action against the same identity and policy.");
    let approve_decision = authorize(&priya, &approve, &policy)?;
    let approve_result = format!(
        "Result: ALLOWED. The policy grants approval to {}.",
        approve_decision.matched_roles.join(", ")
    );
    println!("   {}", style.paint("1;32", &approve_result));
    println!();

    println!(
        "{}",
        style.paint(
            "1;34",
            "Chapter 3 — Priya needs more than an ALLOWED message. She needs portable proof."
        )
    );
    println!(
        "   Her client gathers the identity, policy, and exact approval request behind the decision."
    );
    println!("   Identity claims: {}", identity_path.display());
    println!("   Policy:          {}", policy_path.display());
    println!("   Approval request: {}", request_path.display());
    println!(
        "   The request is not hex-encoded alone; it becomes the request field in a signed bundle."
    );
    println!();

    let issuer = SigningKey::from_bytes(&[1; 32]);
    let subject = SigningKey::from_bytes(&[2; 32]);
    let commitment = issue_identity_commitment(
        "authority".into(),
        "issuer-key-1".into(),
        &priya,
        &policy,
        7,
        &issuer,
        &subject.verifying_key(),
    )?;
    let presentation = issue_presentation(
        identity_root(&priya),
        &approve,
        &approve_decision,
        7,
        &issuer,
        priya.key_id.clone(),
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
    let bundle = OfflineBundle {
        identity_claims: Some(priya.clone()),
        identity_commitment: commitment,
        policy: policy.clone(),
        request: approve.clone(),
        presentation,
        revocation_snapshot: snapshot,
        issuer_public_key: issuer.verifying_key().to_bytes().to_vec(),
        subject_public_key: subject.verifying_key().to_bytes().to_vec(),
        content_hash: [0; 32],
    }
    .seal();
    let encoded_bundle = encode_offline_bundle(&bundle)?;
    let canonical_bundle_json = hex::decode(&encoded_bundle)?;
    fs::write(&bundle_json_path, &canonical_bundle_json)?;
    fs::write(&bundle_hex_path, format!("{encoded_bundle}\n"))?;

    let stored_bundle_json = fs::read(&bundle_json_path)?;
    let stored_bundle_hex = fs::read_to_string(&bundle_hex_path)?;
    if hex::encode(&stored_bundle_json) != stored_bundle_hex.trim() {
        return Err(io::Error::other("saved hex does not encode the saved bundle JSON").into());
    }
    decode_offline_bundle(stored_bundle_hex.trim())?;

    println!(
        "{}",
        style.paint(
            "1;34",
            "Chapter 4 — The proof is signed, packed, and made ready to send."
        )
    );
    println!(
        "   Acme's issuer vouches for Priya's identity; Priya's client proves possession of her key."
    );
    println!(
        "   The demo performs both operations together; production keeps the two private keys separate."
    );
    println!(
        "   Signed canonical bundle JSON: {} ({} bytes)",
        bundle_json_path.display(),
        stored_bundle_json.len()
    );
    println!(
        "   {}",
        style.paint(
            "1;35",
            &format!(
                "Hex sent to `payment-api`: {} ({} characters).",
                bundle_hex_path.display(),
                stored_bundle_hex.trim().len()
            )
        )
    );
    println!("   Verified: the hex decodes to the saved bundle JSON.");
    println!("   Priya now has one file to send: offline-bundle.hex.");
    println!("   payment-api can verify it later without contacting Acme's issuer.");
    println!();

    println!(
        "{}",
        style.paint("1;36", "=== Two guardrails in the same story ===")
    );
    let other_payment = payment_request("payment.approve", "payment-9000");
    println!(
        "{}",
        style.paint(
            "1;34",
            "Guardrail 1 — Priya asks to approve a different payment, payment-9000."
        )
    );
    println!("   Her role is valid, but this payment is outside the resource named by the policy.");
    print_payload(&other_payment, &style)?;
    expect_denied(&priya, &other_payment, &policy)?;
    println!(
        "   {}",
        style.paint(
            "1;31",
            "Result: DENIED. The resource is outside Priya's policy scope."
        )
    );
    println!();

    let mut suspended_priya = priya.clone();
    suspended_priya.roles.push("finance.suspended".into());
    println!(
        "{}",
        style.paint(
            "1;34",
            "Guardrail 2 — Acme suspends Priya, but her old approver role is still present."
        )
    );
    println!("   She sends the original approval request again.");
    print_payload(&approve, &style)?;
    expect_denied(&suspended_priya, &approve, &policy)?;
    println!(
        "   {}",
        style.paint(
            "1;31",
            "Result: DENIED. The suspension rule overrides the older allow rule."
        )
    );
    println!();

    println!("The whole happy-path story in one line:");
    println!("  identity.json + policy.json + request.json");
    println!("    -> signed offline-bundle.json");
    println!("    -> offline-bundle.hex");
    println!("Priya sends offline-bundle.hex to the payment-api consumer.");
    println!(
        "The consumer also needs a trusted registry and independently pinned root public key."
    );

    Ok(())
}
