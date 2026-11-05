// Package hostnet prepares the host network for ember's VMs. It runs as
// root, once per boot (`ember host up`), so the daemon itself needs no
// privileges.
//
// Each slot gets a tap device owned by the ember user and a /30 network.
// An nftables table then enforces the isolation:
//
//   - guests cannot reach the host (input from the taps is dropped),
//   - guests cannot reach each other, private networks, the tailnet's CGNAT
//     range, link-local or multicast addresses,
//   - guests have no IPv6,
//   - a guest can only send from its own address,
//   - everything else is masqueraded to the internet.
package hostnet

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/danielphan2003/ember/internal/config"
	"github.com/vishvananda/netlink"
)

// Blocked lists the IPv4 destinations guests may never reach.
var Blocked = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3",
}

const ipForwardSysctl = "/proc/sys/net/ipv4/ip_forward"

// The nftables table and firewalld zone are named after the tap prefix, so
// two ember instances (say, production and a test) never touch each
// other's rules.

// Ruleset renders the nftables table for cfg. Taps are matched by name
// from a set, not a wildcard, so another instance's taps never match.
func Ruleset(cfg config.Config) string {
	var taps, slots []string
	for _, s := range cfg.SlotList() {
		taps = append(taps, fmt.Sprintf("%q", s.Tap))
		slots = append(slots, fmt.Sprintf("%q . %s", s.Tap, s.Guest))
	}
	return fmt.Sprintf(`table inet %[1]s {
	set taps {
		type ifname
		elements = { %[4]s }
	}
	set blocked4 {
		type ipv4_addr
		flags interval
		elements = { %[2]s }
	}
	set slots {
		type ifname . ipv4_addr
		elements = { %[3]s }
	}
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname @taps drop
	}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname @taps meta nfproto ipv6 drop
		iifname @taps iifname . ip saddr != @slots drop
		iifname @taps oifname @taps drop
		iifname @taps ip daddr @blocked4 drop
		iifname @taps tcp dport 25 drop
		oifname @taps ct state != { established, related } drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		iifname @taps oifname != @taps masquerade
	}
}
`, cfg.TapPrefix, strings.Join(Blocked, ", "), strings.Join(slots, ", "), strings.Join(taps, ", "))
}

// Up creates the taps and installs the ruleset. It is idempotent.
func Up(cfg config.Config, logf func(string, ...any)) error {
	name := cfg.User
	if name == "" {
		name = os.Getenv("SUDO_USER")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("user %q: %w (create it first; see deploy/)", name, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)

	for _, s := range cfg.SlotList() {
		if err := ensureTap(s, uid, gid); err != nil {
			return fmt.Errorf("%s: %w", s.Tap, err)
		}
	}
	logf("%d tap devices ready (%s0..%s%d, owner %s)", cfg.Slots, cfg.TapPrefix, cfg.TapPrefix, cfg.Slots-1, name)

	// Replace the table atomically: delete (if present) and add in one batch.
	script := "table inet " + cfg.TapPrefix + "\ndelete table inet " + cfg.TapPrefix + "\n" + Ruleset(cfg)
	if out, err := run("nft", script, "-f", "-"); err != nil {
		return fmt.Errorf("nft: %v: %s", err, out)
	}
	logf("nftables table inet %s installed", cfg.TapPrefix)

	if err := os.WriteFile(ipForwardSysctl, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("enable ip_forward: %w", err)
	}

	if firewalldRunning() {
		if err := firewalldUp(cfg); err != nil {
			return err
		}
		logf("firewalld zone %s holds the tap devices", cfg.TapPrefix)
	}
	return nil
}

func ensureTap(s config.Slot, uid, gid int) error {
	link, err := netlink.LinkByName(s.Tap)
	if err == nil {
		if t, ok := link.(*netlink.Tuntap); !ok || t.Owner != uint32(uid) {
			// Wrong owner or not a tap: recreate.
			if err := netlink.LinkDel(link); err != nil {
				return err
			}
			link = nil
		}
	} else {
		link = nil
	}
	if link == nil {
		tap := &netlink.Tuntap{
			LinkAttrs: netlink.LinkAttrs{Name: s.Tap},
			Mode:      netlink.TUNTAP_MODE_TAP,
			Flags:     netlink.TUNTAP_DEFAULTS | netlink.TUNTAP_NO_PI,
			Owner:     uint32(uid),
			Group:     uint32(gid),
		}
		if err := netlink.LinkAdd(tap); err != nil {
			return err
		}
		if link, err = netlink.LinkByName(s.Tap); err != nil {
			return err
		}
	}
	addr, err := netlink.ParseAddr(s.HostCIDR())
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return err
	}
	// Guests never need to be reached by name or by IPv6.
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/"+s.Tap+"/disable_ipv6", []byte("1"), 0o644)
	return netlink.LinkSetUp(link)
}

// Down removes the taps, the ruleset and the firewalld zone binding.
func Down(cfg config.Config, logf func(string, ...any)) error {
	var errs []error
	for _, s := range cfg.SlotList() {
		if link, err := netlink.LinkByName(s.Tap); err == nil {
			if err := netlink.LinkDel(link); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s.Tap, err))
			}
		}
	}
	if out, err := run("nft", "", "delete", "table", "inet", cfg.TapPrefix); err != nil && !strings.Contains(out, "No such file") {
		errs = append(errs, fmt.Errorf("nft: %v: %s", err, out))
	}
	if firewalldRunning() {
		for _, s := range cfg.SlotList() {
			_, _ = run("firewall-cmd", "", "--permanent", "--zone="+cfg.TapPrefix, "--remove-interface="+s.Tap)
		}
		_, _ = run("firewall-cmd", "", "--reload")
	}
	logf("removed taps and table inet %s (ip_forward and the empty firewalld zone are left as is)", cfg.TapPrefix)
	return errors.Join(errs...)
}

func firewalldRunning() bool {
	out, err := run("firewall-cmd", "", "--state")
	return err == nil && strings.TrimSpace(out) == "running"
}

// firewalldUp puts the taps in a zone named after the tap prefix, with
// target DROP: if ember's table were ever flushed, the host would still
// refuse the guests. A policy from that zone to every other zone lets their
// forwarded traffic through firewalld; ember's table filters it first. The
// bindings are permanent, so `firewall-cmd --reload` keeps them.
func firewalldUp(cfg config.Config) error {
	zone, policy := cfg.TapPrefix, cfg.TapPrefix+"-egress"
	fw := func(args ...string) error {
		if out, err := run("firewall-cmd", "", args...); err != nil {
			return fmt.Errorf("firewall-cmd %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}
	has := func(list, name string) bool {
		out, _ := run("firewall-cmd", "", "--permanent", list)
		return strings.Contains(" "+strings.TrimSpace(out)+" ", " "+name+" ")
	}
	if !has("--get-zones", zone) {
		if err := fw("--permanent", "--new-zone="+zone); err != nil {
			return err
		}
	}
	if err := fw("--permanent", "--zone="+zone, "--set-target=DROP"); err != nil {
		return err
	}
	_ = fw("--permanent", "--zone="+zone, "--set-description=ember microVM taps; filtering is in nftables table inet "+zone)
	if !has("--get-policies", policy) {
		for _, args := range [][]string{
			{"--permanent", "--new-policy=" + policy},
			{"--permanent", "--policy=" + policy, "--set-target=ACCEPT"},
			{"--permanent", "--policy=" + policy, "--add-ingress-zone=" + zone},
			{"--permanent", "--policy=" + policy, "--add-egress-zone=ANY"},
		} {
			if err := fw(args...); err != nil {
				return err
			}
		}
	}
	for _, s := range cfg.SlotList() {
		if err := fw("--permanent", "--zone="+zone, "--change-interface="+s.Tap); err != nil {
			return err
		}
	}
	return fw("--reload")
}

func run(name, stdin string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	b, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(b)), err
}
