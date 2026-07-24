#!/usr/bin/env bash
# Build the file_registry canister WASM: cargo -> ic-wasm shrink ->
# candid metadata -> gzip. Output: out/file_registry.wasm.gz
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --target wasm32-unknown-unknown --release

mkdir -p out
ic-wasm target/wasm32-unknown-unknown/release/file_registry.wasm \
    -o out/file_registry.wasm shrink
ic-wasm out/file_registry.wasm -o out/file_registry.wasm \
    metadata candid:service -f file_registry.did -v public

gzip -nf9 out/file_registry.wasm
ls -lh out/file_registry.wasm.gz
