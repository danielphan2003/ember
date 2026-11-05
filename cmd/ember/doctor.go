package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/danielphan2003/ember/internal/agentbin"
	"github.com/danielphan2003/ember/internal/config"
	"github.com/danielphan2003/ember/internal/vm"
	"github.com/vishvananda/netlink"
)

// cmdDoctor checks every host requirement and says how to fix each
// failure. It changes nothing.
func cmdDoctor(args []string) error {
	fs, cfgPath := flags("doctor")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	failed := 0
	check := func(name string, err error, fix string) {
		if err == nil {
			fmt.Printf("  ok    %s\n", name)
			return
		}
		failed++
		fmt.Printf("  FAIL  %s: %v\n        fix: %s\n", name, err, fix)
	}

	fmt.Println("ember doctor")
	check("guest agent embedded", boolErr(len(agentbin.Agent()) > 0, "missing"), "build with `just build`")
	check("/dev/kvm is usable", openRW("/dev/kvm"), "enable virtualization in firmware; add the user to the kvm group")
	check("firecracker at "+cfg.Firecracker, executable(cfg.Firecracker), "run `just fetch` or set firecracker: in the config")
	_, kerr := os.Stat(cfg.Kernel)
	check("guest kernel at "+cfg.Kernel, kerr, "run `just fetch` or set kernel: in the config")
	check("mke2fs can build from a tar (e2fsprogs >= 1.47.1)", mke2fsOK(), "install e2fsprogs 1.47.1+ built with libarchive")
	_, rerr := exec.LookPath("resize2fs")
	check("resize2fs available", rerr, "install e2fsprogs")
	check("state dir "+cfg.StateDir+" supports reflinks", reflinkOK(cfg.StateDir), "use btrfs or XFS for state_dir (works without, but each job copies the image)")

	owner := cfg.User
	if owner == "" {
		if cur, err := user.Current(); err == nil {
			owner = cur.Username
		}
	}
	u, uerr := user.Lookup(owner)
	check("user "+owner+" exists", uerr, "create it, e.g. with deploy/sysusers.conf")
	if uerr == nil {
		uid, _ := strconv.Atoi(u.Uid)
		for _, s := range cfg.SlotList() {
			check("tap "+s.Tap+" owned by "+owner, tapOK(s.Tap, uid), "run `sudo ember host up`")
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d check(s) failed", failed)
	}
	fmt.Println("all good")
	return nil
}

func boolErr(ok bool, msg string) error {
	if ok {
		return nil
	}
	return fmt.Errorf("%s", msg)
}

func openRW(p string) error {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	return f.Close()
}

func executable(p string) error {
	fi, err := os.Stat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("not executable")
	}
	return nil
}

func mke2fsOK() error {
	out, err := exec.Command("mke2fs", "-V").CombinedOutput()
	if err != nil {
		return err
	}
	m := regexp.MustCompile(`mke2fs (\d+)\.(\d+)\.?(\d*)`).FindSubmatch(out)
	if m == nil {
		return fmt.Errorf("cannot parse %q", out)
	}
	maj, _ := strconv.Atoi(string(m[1]))
	minor, _ := strconv.Atoi(string(m[2]))
	patch, _ := strconv.Atoi(string(m[3]))
	if maj > 1 || minor > 47 || (minor == 47 && patch >= 1) {
		return nil
	}
	return fmt.Errorf("version %d.%d.%d", maj, minor, patch)
}

func reflinkOK(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(dir, ".doctor-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	src := filepath.Join(tmp, "a")
	if err := os.WriteFile(src, []byte("ember"), 0o600); err != nil {
		return err
	}
	return vm.Reflink(src, filepath.Join(tmp, "b"))
}

func tapOK(name string, uid int) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	t, ok := link.(*netlink.Tuntap)
	if !ok {
		return fmt.Errorf("not a tap device")
	}
	if int(t.Owner) != uid {
		return fmt.Errorf("owner uid %d", t.Owner)
	}
	return nil
}
