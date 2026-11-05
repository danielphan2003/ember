package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSlotList(t *testing.T) {
	c := Default()
	c.Slots = 3
	c.Subnet = "172.30.0.0/16"
	got := c.SlotList()
	if len(got) != 3 {
		t.Fatalf("want 3 slots, got %d", len(got))
	}
	s := got[2]
	if s.Tap != "ember2" || s.Host.String() != "172.30.0.9" || s.Guest.String() != "172.30.0.10" ||
		s.GuestCIDR() != "172.30.0.10/30" || s.MAC != "06:00:ac:1e:00:0a" {
		t.Fatalf("slot 2 = %+v", s)
	}
}

func TestValidate(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"subnet too small": func(c *Config) { c.Subnet = "10.0.0.0/30"; c.Slots = 2 },
		"bad prefix":       func(c *Config) { c.TapPrefix = "Ember-0" },
		"ipv6 subnet":      func(c *Config) { c.Subnet = "fd00::/64" },
		"no slots":         func(c *Config) { c.Slots = 0 },
	} {
		c := Default()
		mut(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := Default().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestLoadMergesOverDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("slots: 4\nstate_dir: rel\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Slots != 4 || c.VCPUs != Default().VCPUs || !filepath.IsAbs(c.StateDir) {
		t.Fatalf("%+v", c)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err != nil {
		t.Fatalf("missing file should mean defaults: %v", err)
	}
}
