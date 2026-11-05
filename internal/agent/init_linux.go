package agent

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// BootParams are the ember.* parameters the host puts on the kernel command
// line.
type BootParams struct {
	Addr     string   // guest address in CIDR form, e.g. 172.30.3.2/30
	Gateway  string   // host side of the tap, e.g. 172.30.3.1
	DNS      []string // resolvers written to /etc/resolv.conf
	Hostname string
}

// ParseCmdline extracts ember.* parameters from a kernel command line.
func ParseCmdline(cmdline string) BootParams {
	var p BootParams
	for _, f := range strings.Fields(cmdline) {
		k, v, ok := strings.Cut(f, "=")
		if !ok {
			continue
		}
		switch k {
		case "ember.ip":
			p.Addr = v
		case "ember.gw":
			p.Gateway = v
		case "ember.dns":
			p.DNS = strings.Split(v, ",")
		case "ember.hostname":
			p.Hostname = v
		}
	}
	return p
}

// Init prepares the guest as PID 1: pseudo-filesystems, hostname and
// network. Failures in optional steps are logged, not fatal, so a job still
// gets a shell to report from.
func Init() error {
	mounts := []struct {
		src, target, fstype string
		flags               uintptr
		data                string
	}{
		{"proc", "/proc", "proc", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
		{"devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "mode=0755"},
		{"devpts", "/dev/pts", "devpts", unix.MS_NOSUID | unix.MS_NOEXEC, "gid=5,mode=0620,ptmxmode=0666"},
		{"tmpfs", "/dev/shm", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=1777"},
		{"tmpfs", "/run", "tmpfs", unix.MS_NOSUID | unix.MS_NODEV, "mode=0755"},
		{"cgroup2", "/sys/fs/cgroup", "cgroup2", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC, ""},
	}
	for _, m := range mounts {
		if err := os.MkdirAll(m.target, 0o755); err != nil {
			log.Printf("mkdir %s: %v", m.target, err)
			continue
		}
		if err := unix.Mount(m.src, m.target, m.fstype, m.flags, m.data); err != nil && !errors.Is(err, unix.EBUSY) {
			log.Printf("mount %s: %v", m.target, err)
		}
	}
	for link, target := range map[string]string{
		"/dev/fd": "/proc/self/fd", "/dev/stdin": "/proc/self/fd/0",
		"/dev/stdout": "/proc/self/fd/1", "/dev/stderr": "/proc/self/fd/2",
		"/dev/ptmx": "pts/ptmx",
	} {
		_ = os.Remove(link)
		_ = os.Symlink(target, link)
	}
	// /tmp, and the runner's RUNNER_TEMP and RUNNER_TOOL_CACHE, must be
	// writable by whatever user the image runs steps as.
	for _, d := range []string{"/tmp", "/ember/tmp", "/ember/toolcache"} {
		if err := os.MkdirAll(d, 0o1777); err == nil {
			_ = os.Chmod(d, 0o1777)
		}
	}

	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return fmt.Errorf("read cmdline: %w", err)
	}
	p := ParseCmdline(string(cmdline))
	if p.Hostname != "" {
		if err := unix.Sethostname([]byte(p.Hostname)); err != nil {
			log.Printf("sethostname: %v", err)
		}
	}
	writeEtc(p)
	if err := setupNetwork(p); err != nil {
		log.Printf("network: %v", err)
	}
	return nil
}

func writeEtc(p BootParams) {
	if len(p.DNS) > 0 {
		var b strings.Builder
		for _, ns := range p.DNS {
			fmt.Fprintf(&b, "nameserver %s\n", ns)
		}
		// Images often ship resolv.conf as a symlink into /run; replace it.
		_ = os.Remove("/etc/resolv.conf")
		if err := os.WriteFile("/etc/resolv.conf", []byte(b.String()), 0o644); err != nil {
			log.Printf("resolv.conf: %v", err)
		}
	}
	hosts := "127.0.0.1 localhost\n::1 localhost ip6-localhost ip6-loopback\n"
	if p.Hostname != "" {
		hosts += "127.0.1.1 " + p.Hostname + "\n"
		_ = os.WriteFile("/etc/hostname", []byte(p.Hostname+"\n"), 0o644)
	}
	_ = os.WriteFile("/etc/hosts", []byte(hosts), 0o644)
}

func setupNetwork(p BootParams) error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return err
	}
	if p.Addr == "" {
		return nil
	}
	eth, err := netlink.LinkByName("eth0")
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(p.Addr)
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(eth, addr); err != nil {
		return err
	}
	if err := netlink.LinkSetUp(eth); err != nil {
		return err
	}
	if p.Gateway != "" {
		return netlink.RouteAdd(&netlink.Route{LinkIndex: eth.Attrs().Index, Gw: net.ParseIP(p.Gateway)})
	}
	return nil
}

// Supervise runs as PID 1: it starts the agent server as a child process
// and reaps every orphan. When the server exits, the VM powers off.
//
// The server runs in a separate process because exec.Cmd.Wait and a PID 1
// reaper calling wait4(-1) would race for the same children.
func Supervise(serverArgs []string) {
	cmd := exec.Command("/proc/self/exe", serverArgs...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("start server: %v", err)
		PowerOff()
	}
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			log.Printf("wait: %v", err)
			PowerOff()
		}
		if pid == cmd.Process.Pid {
			log.Printf("agent server exited: %v", ws)
			PowerOff()
		}
	}
}

// PowerOff stops the VM. Firecracker exits when the guest reboots.
func PowerOff() {
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	os.Exit(1)
}
