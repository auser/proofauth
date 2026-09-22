# Run recipes with strict Bash error handling.
set shell := ["bash", "-euo", "pipefail", "-c"]

# List all available recipes.
default:
    @just --list

# Format all Rust targets.
fmt:
    cargo fmt --all

# Check Rust formatting without changing files.
fmt-check:
    cargo fmt --all -- --check

# Type-check all targets with every feature enabled.
check:
    cargo check --all-targets --all-features

# Run strict Clippy checks for all targets and features.
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Scan locked dependencies for known RustSec advisories.
audit:
    cargo audit

# Run the complete all-features test suite.
test:
    cargo test --all-features

# Run Rust documentation tests.
doc-test:
    cargo test --doc

# Build all targets with every feature enabled.
build:
    cargo build --all-targets --all-features

# Run the creator, registry creator, and consumer examples in order.
examples:
    cargo run --example creator
    cargo run --example registry_creator
    cargo run --example consumer

# Run the complete deterministic offline demonstration.
demo:
    just examples

# Generate or replace starter protocol JSON under examples/data.
generate-example:
    cargo run -- generate-example --output examples/data

# Verify the demo registry using the pinned root public key.
registry-verify:
    cargo run -- registry-verify @target/proofauth-demo/registry.json \
        --root-public "$REGISTRY_ROOT_PUBLIC"

# Serve the demo registry on the local development address.
serve-registry:
    cargo run -- serve-registry @target/proofauth-demo/registry.json

# Verify the demo offline bundle against the trusted registry.
bundle-verify:
    cargo run -- bundle-verify @target/proofauth-demo/offline-bundle.hex \
        @target/proofauth-demo/registry.json \
        --root-public "$REGISTRY_ROOT_PUBLIC" \
        --now 1050

# Run formatting, checking, linting, tests, and documentation tests.
ci: fmt-check check lint test doc-test

# Package the v1.0 release candidate under dist/ and write its checksum.
archive:
    mkdir -p dist
    tar -czf dist/proofauth-v1.0-candidate.tar.gz \
        --exclude='target' --exclude='.git' \
        Cargo.toml Cargo.lock Justfile README.md DESIGN.md RELEASE.md CHANGELOG.md \
        src tests examples demo-data specs vectors .github
    sha256sum dist/proofauth-v1.0-candidate.tar.gz > dist/proofauth-v1.0-candidate.SHA256SUMS.txt

# Run every local v1.0 release gate, including the offline demo verification.
release-check: ci build examples bundle-verify
