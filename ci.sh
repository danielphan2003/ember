#!/bin/sh
# ember: image=docker.io/library/rust:1-alpine vcpus=4 memory=4096
# ember's CI: the checks `just check` runs. Radicle CI runs this file in an
# ember microVM (factory docs/radicle-ci.md); locally it is `sh ci.sh`.
# Everything goes to stderr: CI keeps stdout as artifacts.
set -eu
exec >&2
if command -v apk >/dev/null; then
  apk add -q musl-dev
  rustup component add rustfmt clippy >/dev/null 2>&1
fi
scripts/cargo fmt --check
scripts/cargo clippy --locked --all-targets -- -D warnings
scripts/cargo test --locked
