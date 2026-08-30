#!/bin/sh
set -eu

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"

cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo audit
cargo test --all-targets --locked
cargo test --test production_soak --locked -- --ignored
polyform check
cargo build --release --locked --bin polyguard
cargo run --quiet --locked --bin polyguard-manifest > target/release/polyguard-manifest.json

if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 target/release/polyguard target/release/polyguard-manifest.json \
        > target/release/SHA256SUMS
else
    sha256sum target/release/polyguard target/release/polyguard-manifest.json \
        > target/release/SHA256SUMS
fi
