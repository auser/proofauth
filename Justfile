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

# Run every narrative and offline protocol example in order.
examples:
    cargo run --example payment_workflow
    cargo run --example creator
    cargo run --example registry_creator
    cargo run --example consumer

# Run the complete deterministic offline demonstration.
demo:
    just examples

# Run the introductory Acme payment-authorization story.
payment-demo:
    cargo run --example payment_workflow

# Generate or replace starter protocol JSON under examples/data.
generate-example:
    cargo run -- generate-example --output examples/data

# Validate the static GitHub Pages demo and its deterministic proof data.
pages-check:
    test -f docs/index.html
    jq -e . docs/offline-bundle.json >/dev/null
    jq -e . docs/registry.json >/dev/null
    node -e 'const fs=require("fs"); const html=fs.readFileSync("docs/index.html", "utf8"); const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]; if (scripts.length === 0) throw new Error("expected inline scripts"); scripts.forEach((script) => new Function(script[1]));'
    cargo run --quiet -- bundle-verify \
        "$(cargo run --quiet -- bundle-seal @docs/offline-bundle.json)" \
        @docs/registry.json \
        --root-public ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1 \
        --now 1050

# Serve the GitHub Pages demo locally at http://127.0.0.1:4173.
pages-serve:
    python3 -m http.server 4173 --directory docs

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

# Run formatting, checking, linting, tests, documentation tests, and the Pages proof check.
ci: fmt-check check lint test doc-test pages-check

# Package the v1.0 release candidate under dist/ and write its checksum.
archive:
    test -z "$(git status --porcelain)" || { echo "error: archive requires a clean working tree" >&2; exit 1; }
    mkdir -p dist
    git archive --format=tar.gz \
        --prefix=proofauth-v1.0.0/ \
        --output=dist/proofauth-v1.0-candidate.tar.gz HEAD
    sha256sum dist/proofauth-v1.0-candidate.tar.gz > dist/proofauth-v1.0-candidate.SHA256SUMS.txt

# Run every local v1.0 release gate, including the offline demo verification.
release-check: ci build examples bundle-verify
