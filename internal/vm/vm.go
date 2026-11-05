// Package vm boots one Firecracker microVM and connects to its guest agent.
package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

// AgentPort is the vsock port ember-agent listens on.
const AgentPort = 1024

// Spec describes one VM.
type Spec struct {
	Dir         string // private working directory; removed by Destroy
	Firecracker string
	Kernel      string
	BaseRootFS  string // cached image; cloned, never written
	DiskBytes   int64  // grow the clone to this size if larger (0 = keep)
	VCPUs       int
	MemoryMiB   int
	Tap         string
	MAC         string
	GuestCIDR   string
	Gateway     string
	DNS         []string
	Hostname    string
}

// Machine is a running VM.
type Machine struct {
	spec    Spec
	cmd     *exec.Cmd
	exited  chan struct{}
	waitErr error
	conn    *grpc.ClientConn
	Agent   pb.BackendPluginClient
}

func (s Spec) consolePath() string { return filepath.Join(s.Dir, "console.log") }
func (s Spec) vsockPath() string   { return filepath.Join(s.Dir, "vsock.sock") }

// Boot clones the root filesystem and starts Firecracker. It returns once
// the process is running; use WaitAgent to wait for the guest.
func Boot(spec Spec) (*Machine, error) {
	if err := os.MkdirAll(spec.Dir, 0o700); err != nil {
		return nil, err
	}
	rootfs := filepath.Join(spec.Dir, "rootfs.ext4")
	if err := CloneFile(spec.BaseRootFS, rootfs); err != nil {
		return nil, fmt.Errorf("clone rootfs: %w", err)
	}
	if spec.DiskBytes > 0 {
		if err := grow(rootfs, spec.DiskBytes); err != nil {
			return nil, err
		}
	}

	args := []string{
		"console=ttyS0", "reboot=k", "panic=1", "pci=off", "quiet",
		"i8042.noaux", "i8042.nomux", "i8042.dumbkbd",
		"rootfstype=ext4", "rw", "init=/.ember/agent",
		"ember.ip=" + spec.GuestCIDR, "ember.gw=" + spec.Gateway,
		"ember.hostname=" + spec.Hostname,
	}
	if len(spec.DNS) > 0 {
		args = append(args, "ember.dns="+strings.Join(spec.DNS, ","))
	}
	cfg := map[string]any{
		"boot-source": map[string]any{
			"kernel_image_path": spec.Kernel,
			"boot_args":         strings.Join(args, " "),
		},
		"drives": []map[string]any{{
			"drive_id": "rootfs", "path_on_host": rootfs,
			"is_root_device": true, "is_read_only": false,
		}},
		"machine-config": map[string]any{
			"vcpu_count": spec.VCPUs, "mem_size_mib": spec.MemoryMiB, "smt": false,
		},
		"network-interfaces": []map[string]any{{
			"iface_id": "eth0", "host_dev_name": spec.Tap, "guest_mac": spec.MAC,
		}},
		"vsock": map[string]any{"guest_cid": 3, "uds_path": spec.vsockPath()},
	}
	cfgPath := filepath.Join(spec.Dir, "firecracker.json")
	b, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		return nil, err
	}

	console, err := os.Create(spec.consolePath())
	if err != nil {
		return nil, err
	}
	defer console.Close()
	cmd := exec.Command(spec.Firecracker, "--no-api", "--config-file", cfgPath, "--level", "Warning")
	cmd.Dir = spec.Dir
	cmd.Stdout, cmd.Stderr = console, console
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start firecracker: %w", err)
	}
	m := &Machine{spec: spec, cmd: cmd, exited: make(chan struct{})}
	go func() {
		m.waitErr = cmd.Wait()
		close(m.exited)
	}()
	return m, nil
}

// WaitAgent waits until the guest agent answers, the VM dies, or ctx ends.
func (m *Machine) WaitAgent(ctx context.Context) error {
	// Poll the raw vsock handshake: it succeeds as soon as the agent
	// listens, without gRPC's reconnect backoff (which starts at 1s).
	for {
		attempt, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		c, err := dialVsock(attempt, m.spec.vsockPath(), AgentPort)
		cancel()
		if err == nil {
			c.Close()
			break
		}
		select {
		case <-m.exited:
			return fmt.Errorf("vm exited during boot (%v)", m.waitErr)
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %v)", ctx.Err(), err)
		case <-time.After(5 * time.Millisecond):
		}
	}
	conn, err := grpc.NewClient("passthrough:///agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return dialVsock(ctx, m.spec.vsockPath(), AgentPort)
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 10 * time.Millisecond, Multiplier: 1.6, MaxDelay: time.Second},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(16<<20)),
	)
	if err != nil {
		return err
	}
	m.conn = conn
	m.Agent = pb.NewBackendPluginClient(conn)
	_, err = m.Agent.Capabilities(ctx, &pb.CapabilitiesRequest{}, grpc.WaitForReady(true))
	return err
}

// Exited is closed when the Firecracker process ends.
func (m *Machine) Exited() <-chan struct{} { return m.exited }

// ConsoleTail returns the last n lines of the serial console.
func (m *Machine) ConsoleTail(n int) string {
	b, err := os.ReadFile(m.spec.consolePath())
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// Kill stops the VM immediately; Destroy still has to clean up.
func (m *Machine) Kill() {
	if m.cmd.Process != nil {
		_ = syscall.Kill(-m.cmd.Process.Pid, syscall.SIGKILL)
	}
}

// Destroy kills the VM and removes its working directory.
func (m *Machine) Destroy() {
	if m.conn != nil {
		_ = m.conn.Close()
	}
	if m.cmd.Process != nil {
		_ = syscall.Kill(-m.cmd.Process.Pid, syscall.SIGKILL)
	}
	select {
	case <-m.exited:
	case <-time.After(5 * time.Second):
	}
	_ = os.RemoveAll(m.spec.Dir)
}

// dialVsock connects to a guest port through Firecracker's vsock unix
// socket: send "CONNECT <port>", expect "OK <host port>".
func dialVsock(ctx context.Context, uds string, port int) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", uds)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %d\n", port); err != nil {
		conn.Close()
		return nil, err
	}
	// Read the reply byte by byte so no gRPC bytes are swallowed.
	var line []byte
	buf := make([]byte, 1)
	for len(line) < 64 {
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return nil, err
		}
		if buf[0] == '\n' {
			break
		}
		line = append(line, buf[0])
	}
	if !strings.HasPrefix(string(line), "OK ") {
		conn.Close()
		return nil, fmt.Errorf("vsock handshake: %q", line)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// CloneFile makes dst a copy-on-write clone of src (btrfs, XFS), falling
// back to a sparse copy on filesystems without reflinks.
func CloneFile(src, dst string) error {
	if err := Reflink(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	return sparseCopy(in, out)
}

// Reflink clones src to dst and fails if the filesystem cannot share
// extents.
func Reflink(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := unix.IoctlFileClone(int(out.Fd()), int(in.Fd())); err != nil {
		out.Close()
		_ = os.Remove(dst)
		return fmt.Errorf("reflink: %w", err)
	}
	return out.Close()
}

func sparseCopy(in, out *os.File) error {
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, 1<<20)
	zero := make([]byte, len(buf))
	var off int64
	for {
		n, err := in.ReadAt(buf, off)
		if n > 0 {
			chunk := buf[:n]
			if string(chunk) != string(zero[:n]) {
				if _, werr := out.WriteAt(chunk, off); werr != nil {
					return werr
				}
			}
			off += int64(n)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	return out.Truncate(fi.Size())
}

func grow(path string, size int64) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if size <= fi.Size() {
		return nil
	}
	if err := os.Truncate(path, size); err != nil {
		return err
	}
	if b, err := exec.Command("resize2fs", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("resize2fs: %v: %s", err, strings.TrimSpace(string(b)))
	}
	return nil
}
