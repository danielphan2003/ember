# ember

Run Forgejo Actions jobs in Firecracker microVMs. Each job gets its own
kernel, a copy-on-write clone of its image's root filesystem, and a network
that reaches the internet but not your host or LAN. A VM is ready about
150 ms after the runner asks for it, so a fleet of agents can push every
minute without queueing behind container start-up or sharing a Docker
daemon.

ember is a plugin for the stock `forgejo-runner` (13.1 or newer), using the
runner's [plugin execution engine](https://forgejo.org/2026-09-runner-release-v131/).
The runner keeps doing what it does well: talking to Forgejo, parsing
workflows, fetching actions, streaming logs. ember only provides the
environment the steps run in.

```
Forgejo ◀──── forgejo-runner ──gRPC (plugin.v1alpha)──▶ ember serve ──vsock──▶ ember-agent (PID 1 in each VM)
                                                          │
                                                          ├─ image cache: OCI image → ext4, built once per digest
                                                          └─ per job: reflink clone + Firecracker + tap device
```

## How it works

- **Images.** The first time a job names an image, ember pulls it from the
  registry, flattens the layers and writes an ext4 filesystem with the guest
  agent at `/.ember/agent`. No root is involved: `mke2fs` runs in a user
  namespace and `debugfs` restores non-root owners and setuid bits. The
  result is cached by digest; tags are re-checked hourly, and a cached image
  keeps working while the registry is down.
- **Jobs.** Create reserves nothing. Start clones the cached filesystem
  (a reflink on btrfs or XFS, so it takes milliseconds and no space), boots
  Firecracker with the image's filesystem as root and `ember-agent` as init,
  and waits for the agent to answer on vsock. Exec, CopyIn and CopyOut are
  relayed to the agent unchanged. Remove kills the VM and deletes its disk.
- **Network.** `ember host up` (root, once per boot) creates one tap device
  per slot, owned by the `ember` user, and one nftables table. Guests get
  IPv4 to the internet through NAT. They cannot reach the host, each other,
  private or CGNAT (tailnet) ranges, link-local addresses such as cloud
  metadata, or IPv6, and they cannot spoof another slot's address. Only
  TCP, UDP and ICMP leave (so no 6in4 or GRE tunnels), each guest may hold
  4096 tracked connections, and outbound SMTP is dropped. A public NAT64
  service would still give a guest IPv6 reach; no rule can tell it apart. The
  end-to-end test checks each of these from inside a VM.
- **Privileges.** `ember serve` and every Firecracker process run as the
  unprivileged `ember` user under a systemd sandbox that may only reach
  public addresses (job-chosen image references cannot make the host call
  its own services or the LAN). The runner runs as a separate user with the
  same address restriction.
- **If a guest escaped Firecracker** (its seccomp filter and KVM), it would
  be the `ember` user: no root and no Forgejo token, but it could tamper
  with the image cache and reach the other VMs and the jobs' environment
  variables, secrets included. Running each Firecracker under the jailer is
  on the list; until then, treat all jobs on one host as one trust domain.

## Install

On an x86_64 Linux host with KVM, systemd, e2fsprogs and nftables (firewalld
is handled if present):

```sh
git clone https://github.com/danielphan2003/ember && cd ember
just build fetch            # needs Go, or podman/docker to build in a container
sudo deploy/install.sh      # binaries, users, units; starts ember-host and ember
sudo -u ember ember doctor --config /etc/ember/config.yaml
```

`fetch` downloads Firecracker 1.17.0 and Firecracker's CI guest kernel
(6.1), both checked against pinned SHA-256 sums. `install.sh` adds
forgejo-runner 13.2.1, also pinned.

### Connect to Forgejo

In Forgejo, create a runner (site, organisation or repository settings →
Actions → Runners) and note its UUID and token. Then:

```sh
sudoedit /etc/ember/runner.yaml      # url and uuid under server.connections
sudo systemd-creds encrypt --name=forgejo-token - /etc/ember/forgejo-token.cred
# paste the token, then Ctrl-D; it is encrypted to this host (and its TPM)
sudo systemctl enable --now ember-runner
```

The token never sits in a config file: the runner reads it from
`$CREDENTIALS_DIRECTORY`, which systemd fills only for that service.

## Use it in a workflow

```yaml
jobs:
  test:
    runs-on: ember                # node:24-trixie, 2 vCPU, 2 GiB
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test

  build:
    runs-on: ember-large          # same image, 4 vCPU, 8 GiB
    container:
      image: docker.io/library/golang:1.26   # any OCI image with a shell
    steps:
      - uses: actions/checkout@v4
      - run: go test ./...
```

A label is `name:plugin://default-image`, and each plugin entry in
`runner.yaml` can set `vcpus`, `memory_mib` and `disk_gib`. JavaScript
actions need `node` in the image; `docker.io/library/node:*` images and
Forgejo's runner images have it.

## Try it without Forgejo

`ember run` speaks the same protocol as the runner:

```sh
sudo -u ember ember run -i docker.io/library/alpine:3.22 -- sh -c 'uname -a; nproc; free -m'
```

For development, `examples/dev.yaml` keeps everything inside the checkout:

```sh
sudo dist/ember host up --config examples/dev.yaml   # taps owned by you
dist/ember serve --config examples/dev.yaml &
dist/ember run --config examples/dev.yaml -- uname -a
```

## Performance

Measured on an Intel i7-11850H (16 GB, btrfs on SATA SSD), 2 vCPU and 1 GiB
per VM:

| | |
| --- | --- |
| Create → agent ready, image cached | 145–185 ms (alpine:3.22 and node:24-trixie alike) |
| Whole job cycle (create, start, `true`, remove), sequential | 0.18–0.21 s |
| First use of node:24-trixie (1.2 GB): pull and build the filesystem | 36 s, once per digest |

Memory is the real limit on concurrency. A VM starts only when its memory
fits in `memory_budget_mib` (the sum promised to all running VMs) and the
host's `MemAvailable` still covers it plus `host_reserve_mib`; otherwise the
job waits. If the kernel still runs out, its OOM killer takes a VM first,
and ember keeps serving the others.

## Limitations

- No service containers (`services:`) and no Docker inside jobs yet; the job
  fails with a clear message if it asks for services. A step may start a
  server in the background (`server &`) and use it in later steps.
- Guests have no inbound connections and cannot send mail (port 25).
- The runner's cache server is unreachable from guests, so `actions/cache`
  misses. Large dependencies are better baked into the job image.
- Images are pulled anonymously, on purpose: image references come from
  jobs, so a credential would let every job read what it can read.
- x86_64 only (Firecracker supports aarch64; ember has not been tried there).
- File capabilities and other extended attributes in images are dropped.
- The plugin protocol is alpha upstream and may change between runner
  releases; `deploy/install.sh` pins the runner version ember was tested with.

## Development

```sh
just check   # go vet, unit tests, goimports
just e2e     # boots real VMs: needs /dev/kvm, `just fetch` and the dev host network
```

`scripts/go` runs Go in a container when it is not installed, so `just`
recipes work on a host with only podman or docker.

## Related work

- [hyperfleet](https://github.com/alexisbchz/hyperfleet) and its
  [Forgejo plugin](https://github.com/alexisbchz/hyperfleet-forgejo-plugin):
  a general Firecracker orchestrator behind a REST API, with no guest
  networking.
- [weft-runner-forgejo](https://github.com/openweft/weft-runner-forgejo): a
  separate runner implementation that runs `act_runner` inside weft microVMs.

ember is smaller than either: one binary, the stock runner, no containerd or
cluster, and guests with filtered internet access.

## License

MIT. `internal/pluginpb` is generated from Forgejo's MIT-licensed
`plugin.proto` (copyright The Forgejo Authors).
