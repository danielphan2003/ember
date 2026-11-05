// Package config loads ember's configuration file. Every field has a
// default, so an empty file (or none) is a working configuration.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// Listen is where the runner reaches ember: unix:///path or host:port.
	Listen string `yaml:"listen"`
	// StateDir holds the image cache and per-VM working directories.
	StateDir string `yaml:"state_dir"`
	// Firecracker and Kernel are the VMM binary and the guest kernel.
	Firecracker string `yaml:"firecracker"`
	Kernel      string `yaml:"kernel"`
	// User owns the tap devices and runs the VMs (used by `ember host up`).
	User string `yaml:"user"`
	// Slots is the number of VMs that may run at once. Each slot has its own
	// tap device and /30 network.
	Slots int `yaml:"slots"`
	// TapPrefix names the tap devices: <prefix>0, <prefix>1, ...
	TapPrefix string `yaml:"tap_prefix"`
	// Subnet is carved into one /30 per slot. It must hold Slots*4 addresses.
	Subnet string `yaml:"subnet"`
	// DNS resolvers the guests use. Guests cannot reach the host, so these
	// must be public resolvers.
	DNS []string `yaml:"dns"`
	// DefaultImage is used when a job names no image.
	DefaultImage string `yaml:"default_image"`
	// ImageRefresh is how long a tag's digest is trusted before ember asks
	// the registry again.
	ImageRefresh time.Duration `yaml:"image_refresh"`
	// ImageKeep removes cached images unused for this long.
	ImageKeep time.Duration `yaml:"image_keep"`
	// Defaults are the VM size when the runner's plugin options set none.
	VCPUs     int `yaml:"vcpus"`
	MemoryMiB int `yaml:"memory_mib"`
	DiskGiB   int `yaml:"disk_gib"`
	// HostReserveMiB is memory kept free for the host: a VM waits to start
	// until MemAvailable covers its memory plus this reserve.
	HostReserveMiB int `yaml:"host_reserve_mib"`
}

func Default() Config {
	return Config{
		Listen:       "unix:///run/ember/ember.sock",
		StateDir:     "/var/lib/ember",
		Firecracker:  "/usr/local/lib/ember/firecracker",
		Kernel:       "/usr/local/lib/ember/vmlinux",
		User:         "ember",
		Slots:        8,
		TapPrefix:    "ember",
		Subnet:       "172.30.0.0/16",
		DNS:          []string{"1.1.1.1", "9.9.9.9"},
		DefaultImage: "docker.io/library/node:24-bookworm",
		ImageRefresh: time.Hour,
		ImageKeep:    7 * 24 * time.Hour,
		VCPUs:        2,
		MemoryMiB:    2048,
		DiskGiB:      16,

		HostReserveMiB: 1024,
	}
}

// Load reads path over the defaults. A missing file is not an error.
func Load(path string) (Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return c, err
		default:
			if err := yaml.Unmarshal(b, &c); err != nil {
				return c, fmt.Errorf("%s: %w", path, err)
			}
		}
	}
	c.absolutize()
	return c, c.Validate()
}

// absolutize resolves relative paths against the working directory, since
// Firecracker runs in each VM's own directory.
func (c *Config) absolutize() {
	for _, p := range []*string{&c.StateDir, &c.Firecracker, &c.Kernel} {
		if *p != "" && !filepath.IsAbs(*p) {
			if abs, err := filepath.Abs(*p); err == nil {
				*p = abs
			}
		}
	}
}

func (c Config) Validate() error {
	if c.Slots < 1 {
		return errors.New("slots must be at least 1")
	}
	p, err := netip.ParsePrefix(c.Subnet)
	if err != nil || !p.Addr().Is4() {
		return fmt.Errorf("subnet %q must be an IPv4 prefix", c.Subnet)
	}
	if bits := 32 - p.Bits(); bits < 31 && (1<<bits)/4 < c.Slots {
		return fmt.Errorf("subnet %s holds %d slots, fewer than slots=%d", c.Subnet, (1<<bits)/4, c.Slots)
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9]{0,7}$`).MatchString(c.TapPrefix) {
		return fmt.Errorf("tap_prefix %q must be 1-8 lowercase letters or digits, starting with a letter", c.TapPrefix)
	}
	if c.VCPUs < 1 || c.MemoryMiB < 128 || c.DiskGiB < 1 {
		return errors.New("vcpus, memory_mib and disk_gib must be positive (memory_mib >= 128)")
	}
	return nil
}

// Slot is one VM's network position.
type Slot struct {
	Index int
	Tap   string
	Host  netip.Addr // host side of the tap, the guest's gateway
	Guest netip.Addr
	MAC   string
}

// GuestCIDR is the guest address with its /30 mask.
func (s Slot) GuestCIDR() string { return netip.PrefixFrom(s.Guest, 30).String() }

// HostCIDR is the host address with its /30 mask.
func (s Slot) HostCIDR() string { return netip.PrefixFrom(s.Host, 30).String() }

// Slots lists every slot's tap and addresses.
func (c Config) SlotList() []Slot {
	base := netip.MustParsePrefix(c.Subnet).Masked().Addr().As4()
	n := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	out := make([]Slot, c.Slots)
	for i := range out {
		net := n + uint32(i)*4
		ip := func(off uint32) netip.Addr {
			v := net + off
			return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		}
		g := ip(2).As4()
		out[i] = Slot{
			Index: i,
			Tap:   fmt.Sprintf("%s%d", c.TapPrefix, i),
			Host:  ip(1),
			Guest: ip(2),
			MAC:   fmt.Sprintf("06:00:%02x:%02x:%02x:%02x", g[0], g[1], g[2], g[3]),
		}
	}
	return out
}
