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

    let view = payment_request("payment.view", "payment-8472");
    let view_decision = authorize(&priya, &view, &policy)?;
    println!(
        "ALLOW Priya to view payment-8472 (inherited role: {})",
        view_decision.matched_roles.join(", ")
    );

    let approve = payment_request("payment.approve", "payment-8472");
    let approve_decision = authorize(&priya, &approve, &policy)?;
    println!(
        "ALLOW Priya to approve payment-8472 (matched role: {})",
        approve_decision.matched_roles.join(", ")
    );

    let other_payment = payment_request("payment.approve", "payment-9000");
    expect_denied(&priya, &other_payment, &policy)?;
    println!("DENY Priya approval of payment-9000 (resource is outside policy scope)");

    let mut suspended_priya = priya.clone();
    suspended_priya.roles.push("finance.suspended".into());
    expect_denied(&suspended_priya, &approve, &policy)?;
    println!("DENY suspended Priya approval of payment-8472 (deny overrides allow)");

    Ok(())
}
