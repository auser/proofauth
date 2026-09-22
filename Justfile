set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

check:
    cargo check --all-targets --all-features

lint:
    cargo clippy --all-targets --all-features -- -D warnings

test:
    cargo test --all-features

doc-test:
    cargo test --doc

build:
    cargo build --all-targets --all-features

examples:
    cargo run --example creator
    cargo run --example registry_creator
    cargo run --example consumer

demo:
    just examples

generate-example:
    cargo run -- generate-example --output examples/data

registry-verify:
    cargo run -- registry-verify @target/proofauth-demo/registry.json \
        --root-public "$REGISTRY_ROOT_PUBLIC"

serve-registry:
    cargo run -- serve-registry @target/proofauth-demo/registry.json

bundle-verify:
    cargo run -- bundle-verify @target/proofauth-demo/offline-bundle.hex \
        @target/proofauth-demo/registry.json \
        --root-public "$REGISTRY_ROOT_PUBLIC" \
        --now 1050

ci: fmt-check check lint test doc-test

archive:
    tar -czf proofauth-v1.0-candidate.tar.gz \
        --exclude='target' --exclude='.git' \
        Cargo.toml Justfile README.md DESIGN.md RELEASE.md CHANGELOG.md \
        src examples vectors .github
    sha256sum proofauth-v1.0-candidate.tar.gz > proofauth-v1.0-candidate.SHA256SUMS.txt

release-check: ci build examples bundle-verify
