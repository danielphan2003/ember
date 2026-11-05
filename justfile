# ember tasks. Go runs in a container when it is not installed, so a stock
# host needs only podman (or docker) and just.

firecracker_version := "v1.17.0"
firecracker_sha256 := "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
kernel_url := "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/vmlinux-6.1.155"
kernel_sha256 := "e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"
version := `git describe --tags --always --dirty 2>/dev/null || echo dev`

# Build dist/ember with the guest agent embedded.
build:
    mkdir -p dist
    CGO_ENABLED=0 scripts/go build -trimpath -ldflags="-s -w" -o internal/agentbin/bin/ember-agent ./cmd/ember-agent
    CGO_ENABLED=0 scripts/go build -trimpath -ldflags="-s -w -X main.version={{version}}" -o dist/ember ./cmd/ember

# Format, vet and test. CI runs this.
check:
    scripts/go vet ./...
    scripts/go test ./...
    test -z "$(scripts/go run golang.org/x/tools/cmd/goimports@v0.38.0 -l .)" || (echo "run: just fmt"; exit 1)

fmt:
    scripts/go run golang.org/x/tools/cmd/goimports@v0.38.0 -w .

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
    CGO_ENABLED=0 scripts/go test -c -o dist/e2e.test ./e2e
    EMBER_E2E_CONFIG={{config}} dist/e2e.test -test.v -test.count=1
