//! A narrative RBAC example for an accounts-payable application.
//!
//! Run with:
//!   cargo run --example payment_workflow

use proofauth::{
    authorize, AuthorizationRequest, Effect, Error, IdentityClaims, PermissionRule, Policy, Role,
};
use std::{collections::BTreeMap, io};

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

fn print_payload(request: &AuthorizationRequest) -> Result<(), serde_json::Error> {
    println!("   Payload delivered to consumer `{}`:", request.recipient);
    println!("   {}", serde_json::to_string(request)?);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    println!("=== Acme payment desk ===");
    println!("Acme's issuer identifies Priya as a finance.approver for tenant acme.");
    println!("The policy lets approvers inherit payment viewing permission.");
    println!();

    let view = payment_request("payment.view", "payment-8472");
    println!("1. Priya opens payment-8472 before deciding whether to approve it.");
    print_payload(&view)?;
    let view_decision = authorize(&priya, &view, &policy)?;
    println!(
        "   Decision: ALLOW through inherited role {}.",
        view_decision.matched_roles.join(", ")
    );
    println!();

    let approve = payment_request("payment.approve", "payment-8472");
    println!("2. Priya approves the payment she reviewed.");
    print_payload(&approve)?;
    let approve_decision = authorize(&priya, &approve, &policy)?;
    println!(
        "   Decision: ALLOW through matched role {}.",
        approve_decision.matched_roles.join(", ")
    );
    println!();

    let other_payment = payment_request("payment.approve", "payment-9000");
    println!("3. Priya tries to approve payment-9000, which is outside her policy scope.");
    print_payload(&other_payment)?;
    expect_denied(&priya, &other_payment, &policy)?;
    println!("   Decision: DENY because the resource is outside policy scope.");
    println!();

    let mut suspended_priya = priya.clone();
    suspended_priya.roles.push("finance.suspended".into());
    println!("4. Acme suspends Priya but her identity still contains the approver role.");
    print_payload(&approve)?;
    expect_denied(&suspended_priya, &approve, &policy)?;
    println!("   Decision: DENY because the suspension deny overrides the allow.");
    println!();
    println!("Each payload above is the exact AuthorizationRequest evaluated by ProofAuth.");
    println!("Run `just demo` to see the signed .hex bundle delivered for offline verification.");

    Ok(())
}
