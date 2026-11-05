# ember tasks. Cargo runs in a container when it is not installed, so a
# stock host needs only podman (or docker) and just.

firecracker_version := "v1.17.0"
firecracker_sha256 := "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
kernel_url := "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/vmlinux-6.1.155"
kernel_sha256 := "e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"
target := "x86_64-unknown-linux-musl"

# Build dist/ember: static binaries, with the guest agent embedded.
build:
    mkdir -p dist
    scripts/cargo build --release --locked --target {{target}} --bin ember-agent
    EMBER_AGENT=target/{{target}}/release/ember-agent scripts/cargo build --release --locked --target {{target}} --bin ember
    cp target/{{target}}/release/ember dist/ember
    ls -l dist/ember

# Format check, clippy and tests. CI runs this.
check:
    scripts/cargo fmt --check
    scripts/cargo clippy --locked --all-targets -- -D warnings
    scripts/cargo test --locked

fmt:
    scripts/cargo fmt

# Download Firecracker and the guest kernel into dist/, verified by sha256.
fetch:
    #!/usr/bin/env sh
    set -eu
    mkdir -p dist && cd dist
    tgz=firecracker-{{firecracker_version}}-x86_64.tgz
    [ -f firecracker ] || {
        curl -fsSLO https://github.com/firecracker-microvm/firecracker/releases/download/{{firecracker_version}}/$tgz
        echo "{{firecracker_sha256}}  $tgz" | sha256sum -c -
        tar xzf $tgz --strip-components=1 release-{{firecracker_version}}-x86_64/firecracker-{{firecracker_version}}-x86_64
        mv firecracker-{{firecracker_version}}-x86_64 firecracker && rm $tgz
    }
    [ -f vmlinux ] || {
        curl -fsSL -o vmlinux.tmp {{kernel_url}}
        echo "{{kernel_sha256}}  vmlinux.tmp" | sha256sum -c -
        mv vmlinux.tmp vmlinux
    }
    ls -l firecracker vmlinux

# Boot real VMs: needs /dev/kvm, `just fetch`, `sudo dist/ember host up --config CONFIG`,
# and no `ember serve` on the same slots. The test binary runs natively for /dev/kvm.
e2e config="examples/dev.yaml": build
    #!/usr/bin/env sh
    set -eu
    EMBER_AGENT=target/{{target}}/release/ember-agent scripts/cargo test --release --locked --target {{target}} --test e2e --no-run 2>&1 | tail -1
    bin=$(ls -t target/{{target}}/release/deps/e2e-* | grep -v '\.d$' | head -1)
    EMBER_E2E_CONFIG={{config}} "$bin" --test-threads=1 --nocapture
