use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use proofauth::{
    authorize, decode_offline_bundle, decode_presentation, encode_hash, encode_offline_bundle,
    encode_presentation, hash, issue_presentation, uor_identity_address, uor_policy_address,
    AuthorizationPresentation, AuthorizationRequest, Effect, IdentityClaims, OfflineBundle,
    OfflineVerifier, PermissionRule, Policy, ReplayCache, RevocationSnapshot, Role,
    SignedTrustRegistry,
};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
};

#[derive(Parser)]
#[command(
    name = "proofauth",
    version,
    about = "Canonical, encoded authorization hashes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate starter identity, policy, and request JSON documents.
    GenerateExample {
        #[arg(long)]
        output: PathBuf,
    },
    /// Hash a canonical JSON object with a domain label.
    Hash {
        #[arg(long)]
        domain: String,
        input: String,
    },
    /// Produce the official UOR JSON address for an identity object.
    IdentityAddress { input: String },
    /// Produce the official UOR JSON address for a policy object.
    PolicyAddress { input: String },
    /// Validate an authorization request without issuing or verifying it.
    ValidateRequest { input: String },
    /// Issue a recipient-bound presentation from identity, policy, and request JSON.
    Issue {
        identity: String,
        policy: String,
        request: String,
        #[arg(long)]
        issuer_secret: String,
        #[arg(long)]
        subject_secret: String,
        #[arg(long)]
        subject_key_id: String,
        #[arg(long, default_value_t = 1)]
        issuer_epoch: u64,
    },
    /// Verify a presentation and request using an offline revocation snapshot.
    Verify {
        presentation: String,
        request: String,
        snapshot: String,
        #[arg(long)]
        issuer_public: String,
        #[arg(long)]
        subject_public: String,
        #[arg(long)]
        now: u64,
    },
    /// Serve a signed registry document over HTTP for distribution.
    ServeRegistry {
        input: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        bind: String,
    },
    /// Seal a JSON OfflineBundle and emit its lowercase-hex transport token.
    BundleSeal { input: String },
    /// Verify one lowercase-hex bundle using a signed local registry.
    BundleVerify {
        input: String,
        registry: String,
        #[arg(long)]
        root_public: String,
        #[arg(long)]
        now: u64,
    },
    /// Verify a signed registry document using a pinned root public key.
    RegistryVerify {
        input: String,
        #[arg(long)]
        root_public: String,
    },
}

fn example_documents() -> Result<[(&'static str, Vec<u8>); 3], serde_json::Error> {
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

    Ok([
        ("identity.json", serde_json::to_vec_pretty(&identity)?),
        ("policy.json", serde_json::to_vec_pretty(&policy)?),
        ("request.json", serde_json::to_vec_pretty(&request)?),
    ])
}

fn generate_example(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if output.exists() && !output.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("output path '{}' is not a directory", output.display()),
        )
        .into());
    }

    let documents = example_documents()?;
    fs::create_dir_all(output).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "failed to create output directory '{}': {error}",
                output.display()
            ),
        )
    })?;

    for (name, contents) in documents {
        let target = output.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&target)
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("failed to create '{}': {error}", target.display()),
                )
            })?;
        if let Err(error) = file
            .write_all(&contents)
            .and_then(|()| file.write_all(b"\n"))
        {
            return Err(io::Error::new(
                error.kind(),
                format!("failed to write '{}': {error}", target.display()),
            )
            .into());
        }
    }

    Ok(())
}

fn read_input(value: String) -> Result<String, Box<dyn std::error::Error>> {
    Ok(value
        .strip_prefix('@')
        .map(fs::read_to_string)
        .transpose()?
        .unwrap_or(value))
}

fn secret(value: &str) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let bytes: [u8; 32] = hex::decode(value)?.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "signing key must be 32 bytes / 64 hex characters",
        )
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn public(value: &str) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let bytes: [u8; 32] = hex::decode(value)?.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "public key must be 32 bytes / 64 hex characters",
        )
    })?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

fn serve_registry(input: String, bind: String) -> Result<(), Box<dyn std::error::Error>> {
    let body = read_input(input)?.into_bytes();
    let listener = TcpListener::bind(&bind)?;
    eprintln!("serving signed registry on http://{bind}/registry.json");
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut request = [0_u8; 4096];
        let size = stream.read(&mut request)?;
        let request = String::from_utf8_lossy(&request[..size]);
        let status = if request.starts_with("GET /registry.json ") {
            "200 OK"
        } else {
            "404 Not Found"
        };
        let payload = if status == "200 OK" {
            body.as_slice()
        } else {
            b"not found"
        };
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", payload.len())?;
        stream.write_all(payload)?;
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::GenerateExample { output } => generate_example(&output)?,
        Command::Hash { domain, input } => {
            let json = read_input(input)?;
            let value: Value = serde_json::from_str(&json)?;
            let domain = format!("proofauth/{domain}/v1");
            println!("{}", encode_hash(&hash(domain.as_bytes(), &value)));
        }
        Command::IdentityAddress { input } => {
            let json = read_input(input)?;
            let claims: IdentityClaims = serde_json::from_str(&json)?;
            println!("{}", uor_identity_address(&claims)?);
        }
        Command::PolicyAddress { input } => {
            let json = read_input(input)?;
            let policy: Policy = serde_json::from_str(&json)?;
            println!("{}", uor_policy_address(&policy)?);
        }
        Command::ValidateRequest { input } => {
            let json = read_input(input)?;
            let request: AuthorizationRequest = serde_json::from_str(&json)?;
            request.validate()?;
            println!("valid");
        }
        Command::Issue {
            identity,
            policy,
            request,
            issuer_secret,
            subject_secret,
            subject_key_id,
            issuer_epoch,
        } => {
            let identity: IdentityClaims = serde_json::from_str(&read_input(identity)?)?;
            let policy: Policy = serde_json::from_str(&read_input(policy)?)?;
            let request: AuthorizationRequest = serde_json::from_str(&read_input(request)?)?;
            let decision = authorize(&identity, &request, &policy)?;
            let presentation = issue_presentation(
                proofauth::identity_root(&identity),
                &request,
                &decision,
                issuer_epoch,
                &secret(&issuer_secret)?,
                subject_key_id,
                &secret(&subject_secret)?,
            )?;
            println!(
                "{}",
                String::from_utf8(encode_presentation(&presentation)?)?
            );
        }
        Command::Verify {
            presentation,
            request,
            snapshot,
            issuer_public,
            subject_public,
            now,
        } => {
            let presentation: AuthorizationPresentation =
                decode_presentation(read_input(presentation)?.as_bytes())?;
            let request: AuthorizationRequest = serde_json::from_str(&read_input(request)?)?;
            let snapshot: RevocationSnapshot = serde_json::from_str(&read_input(snapshot)?)?;
            let mut verifier = OfflineVerifier {
                snapshot,
                replay_cache: ReplayCache::new(),
            };
            verifier.verify(
                &presentation,
                &request,
                &public(&issuer_public)?,
                &public(&subject_public)?,
                now,
            )?;
            println!("valid");
        }
        Command::ServeRegistry { input, bind } => serve_registry(input, bind)?,
        Command::BundleSeal { input } => {
            let mut bundle: OfflineBundle = serde_json::from_str(&read_input(input)?)?;
            bundle = bundle.seal();
            println!("{}", encode_offline_bundle(&bundle)?);
        }
        Command::BundleVerify {
            input,
            registry,
            root_public,
            now,
        } => {
            let bundle = decode_offline_bundle(read_input(input)?.trim())?;
            let signed: SignedTrustRegistry = serde_json::from_str(&read_input(registry)?)?;
            let root = public(&root_public)?;
            let registry = signed.verify(&root)?;
            let mut replay_cache = ReplayCache::new();
            bundle.verify(&registry, &mut replay_cache, now)?;
            println!("valid");
        }
        Command::RegistryVerify { input, root_public } => {
            let signed: SignedTrustRegistry = serde_json::from_str(&read_input(input)?)?;
            signed.verify(&public(&root_public)?)?;
            println!("valid");
        }
    }
    Ok(())
}
