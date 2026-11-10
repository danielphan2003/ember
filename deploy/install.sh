#!/usr/bin/env bash
# Install ember, Firecracker, the guest kernel and forgejo-runner, with their
# users and systemd units. Run as root from a checkout after `just build fetch`:
#
#   sudo deploy/install.sh
#
# It is idempotent and never overwrites /etc/ember/*.yaml or the token.
# Uninstall: deploy/install.sh --uninstall (keeps /etc/ember and /var/lib).
set -euo pipefail

readonly runner_version=13.2.1
readonly runner_sha256=bb369fe1ecb50fdc983c0b1d993f19b0920df6e5864511892b3cdbf16d858b34
readonly units=(ember-host.service ember.service ember-runner.service)

here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")

[[ $EUID -eq 0 ]] || { echo "install.sh: run as root" >&2; exit 2; }
[[ $(uname -m) == x86_64 ]] || { echo "install.sh: x86_64 only for now" >&2; exit 2; }

if [[ ${1:-} == --uninstall ]]; then
  systemctl disable --now "${units[@]}" 2>/dev/null || true
  for u in "${units[@]}"; do rm -f "/etc/systemd/system/$u"; done
  systemctl daemon-reload
  rm -f /usr/local/bin/ember /usr/local/bin/forgejo-runner /etc/sysusers.d/ember.conf
  rm -rf /usr/local/lib/ember
  echo "removed ember; /etc/ember, /var/lib/ember and /var/lib/forgejo-runner are left in place"
  if firewall-cmd --state >/dev/null 2>&1; then
    echo "firewalld still has zone ember and policy ember-egress (named after tap_prefix); delete them with:"
    echo "  firewall-cmd --permanent --delete-policy=ember-egress && firewall-cmd --permanent --delete-zone=ember && firewall-cmd --reload"
  fi
  exit 0
fi

for f in "$repo/dist/ember" "$repo/dist/firecracker" "$repo/dist/vmlinux"; do
  [[ -f $f ]] || { echo "install.sh: $f missing; run \`just build fetch\` first" >&2; exit 1; }
done

install -D -m 0755 "$repo/dist/ember" /usr/local/bin/ember
install -D -m 0755 "$repo/dist/firecracker" /usr/local/lib/ember/firecracker
install -D -m 0644 "$repo/dist/vmlinux" /usr/local/lib/ember/vmlinux

if [[ $(/usr/local/bin/forgejo-runner --version 2>/dev/null) != *"v$runner_version"* ]]; then
  tmp=$(mktemp)
  trap 'rm -f "$tmp"' EXIT
  curl -fsSL -o "$tmp" \
    "https://code.forgejo.org/forgejo/runner/releases/download/v$runner_version/forgejo-runner-$runner_version-linux-amd64"
  echo "$runner_sha256  $tmp" | sha256sum -c --quiet -
  install -m 0755 "$tmp" /usr/local/bin/forgejo-runner
fi

install -D -m 0644 "$here/sysusers.conf" /etc/sysusers.d/ember.conf
systemd-sysusers /etc/sysusers.d/ember.conf

install -d -m 0750 -g ember /etc/ember
[[ -f /etc/ember/config.yaml ]] || install -m 0640 -g ember "$here/config.yaml" /etc/ember/config.yaml
[[ -f /etc/ember/runner.yaml ]] || install -m 0640 -g forgejo-runner "$here/runner.yaml" /etc/ember/runner.yaml

for u in "${units[@]}"; do install -m 0644 "$here/$u" "/etc/systemd/system/$u"; done
if command -v restorecon >/dev/null; then
  restorecon -R /usr/local/bin/ember /usr/local/bin/forgejo-runner /usr/local/lib/ember /etc/ember /etc/systemd/system/ember*.service || true
fi
systemctl daemon-reload
systemctl enable --now ember-host.service ember.service

cat <<EOF

ember is running. Next:
  1. Edit /etc/ember/runner.yaml: your Forgejo url and the runner's uuid.
  2. Store the runner token, encrypted to this host:
       systemd-creds encrypt --name=forgejo-token - /etc/ember/forgejo-token.cred
     (paste the token, then Ctrl-D)
  3. systemctl enable --now ember-runner
  4. Check: ember doctor; journalctl -u ember -u ember-runner -f
EOF
