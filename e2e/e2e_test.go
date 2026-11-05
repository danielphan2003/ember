// Package e2e boots real microVMs. It runs only when EMBER_E2E_CONFIG
// names an ember config whose host network is up (`ember host up`), with
// no `ember serve` using the same slots. `just e2e` builds and runs it.
package e2e

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielphan2003/ember/internal/agentbin"
	"github.com/danielphan2003/ember/internal/config"
	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"github.com/danielphan2003/ember/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const image = "docker.io/library/alpine:3.22"

func setup(t *testing.T) pb.BackendPluginClient {
	t.Helper()
	path := os.Getenv("EMBER_E2E_CONFIG")
	if path == "" {
		t.Skip("EMBER_E2E_CONFIG not set")
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Slots < 2 {
		t.Fatal("e2e needs at least 2 slots")
	}
	srv := server.New(cfg, agentbin.Agent(), slog.New(slog.NewTextHandler(os.Stderr, nil)))
	sock := filepath.Join(t.TempDir(), "ember.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	pb.RegisterBackendPluginServer(g, srv)
	go g.Serve(lis)
	t.Cleanup(func() { srv.Shutdown(); g.Stop() })
	conn, err := grpc.NewClient("unix:"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewBackendPluginClient(conn)
}

type vm struct {
	t  *testing.T
	c  pb.BackendPluginClient
	id string
}

func boot(t *testing.T, c pb.BackendPluginClient) *vm {
	t.Helper()
	ctx := context.Background()
	start := time.Now()
	resp, err := c.Create(ctx, &pb.CreateRequest{Image: image})
	if err != nil {
		t.Fatal(err)
	}
	v := &vm{t: t, c: c, id: resp.GetEnvironmentId()}
	t.Cleanup(func() { c.Remove(context.Background(), &pb.RemoveRequest{EnvironmentId: v.id}) })
	s, err := c.Start(ctx, &pb.StartRequest{EnvironmentId: v.id})
	if err != nil {
		t.Fatal(err)
	}
	for {
		msg, err := s.Recv()
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		if d := msg.GetData(); d != nil {
			t.Logf("%s", strings.TrimSpace(string(d.GetData())))
			continue
		}
		break
	}
	t.Logf("%s ready after %s", v.id, time.Since(start).Round(time.Millisecond))
	return v
}

func (v *vm) sh(script string) (string, int32) {
	v.t.Helper()
	s, err := v.c.Exec(context.Background(), &pb.ExecRequest{
		EnvironmentId: v.id, Command: []string{"sh", "-c", script}, Workdir: "/root",
		Env: map[string]string{"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
	})
	if err != nil {
		v.t.Fatal(err)
	}
	var out bytes.Buffer
	for {
		msg, err := s.Recv()
		if errors.Is(err, io.EOF) {
			v.t.Fatal("exec ended without completion")
		}
		if err != nil {
			v.t.Fatal(err)
		}
		switch {
		case msg.GetData() != nil:
			out.Write(msg.GetData().GetData())
		case msg.GetExecFailed() != nil:
			v.t.Fatalf("exec failed: %s", msg.GetExecFailed().GetErrorMessage())
		case msg.GetExecComplete() != nil:
			return out.String(), msg.GetExecComplete().GetExitCode()
		}
	}
}

func TestE2ELifecycle(t *testing.T) {
	c := setup(t)
	v := boot(t, c)

	if out, code := v.sh("echo hi; exit 4"); out != "hi\n" || code != 4 {
		t.Fatalf("exec: %q %d", out, code)
	}

	// CopyIn a script, run it, CopyOut its output file.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := "#!/bin/sh\necho copied > /ember/act/out.txt\n"
	tw.WriteHeader(&tar.Header{Name: "run.sh", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
	tw.Write([]byte(body))
	tw.Close()
	in, err := c.CopyIn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dest := "/ember/act"
	in.Send(&pb.CopyInChunk{EnvironmentId: &v.id, DestPath: &dest})
	in.Send(&pb.CopyInChunk{Data: buf.Bytes()})
	if _, err := in.CloseAndRecv(); err != nil {
		t.Fatal(err)
	}
	if _, code := v.sh("/ember/act/run.sh"); code != 0 {
		t.Fatal("script failed")
	}
	out, err := c.CopyOut(context.Background(), &pb.CopyOutRequest{EnvironmentId: v.id, SrcPath: "/ember/act/out.txt"})
	if err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	for {
		ch, err := out.Recv()
		if err != nil {
			break
		}
		got.Write(ch.GetData())
	}
	tr := tar.NewReader(&got)
	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(tr); string(b) != "copied\n" {
		t.Fatalf("copyout: %q", b)
	}
}

func TestE2ENetworkIsolation(t *testing.T) {
	c := setup(t)
	a, b := boot(t, c), boot(t, c)

	ipOf := func(v *vm) string {
		out, _ := v.sh("ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1")
		return strings.TrimSpace(out)
	}
	gwOf := func(v *vm) string {
		out, _ := v.sh("ip route | awk '/default/ {print $3}'")
		return strings.TrimSpace(out)
	}

	// Positive controls: the probes below must be able to succeed at all.
	if out, code := a.sh("wget -q -T 10 -O /dev/null https://example.com && echo ok"); code != 0 {
		t.Fatalf("internet unreachable: %q", out)
	}
	if out, code := a.sh("nc -z -w 3 1.1.1.1 443"); code != 0 {
		t.Fatalf("nc cannot reach the internet, so the probes prove nothing: %q", out)
	}
	if out, code := a.sh("nc -z -w 3 -s " + ipOf(a) + " 1.1.1.1 443"); code != 0 {
		t.Fatalf("nc -s with the guest's own address fails: %q", out)
	}
	blocked := map[string]string{
		"gateway (host)": gwOf(a),
		"other VM":       ipOf(b),
		"cloud metadata": "169.254.169.254",
		"tailnet":        "100.100.100.100",
		"private LAN":    "192.168.1.1",
	}
	if lan := hostLANAddr(); lan != "" {
		blocked["host LAN address"] = lan
	}
	for name, ip := range blocked {
		if _, code := a.sh("nc -z -w 2 " + ip + " 22 || nc -z -w 2 " + ip + " 80 || nc -z -w 2 " + ip + " 443"); code == 0 {
			t.Errorf("%s (%s) is reachable from a guest", name, ip)
		}
	}
	// Spoofing another slot's address must not get packets out.
	if _, code := a.sh("ip addr add " + ipOf(b) + "/32 dev eth0 && nc -z -w 3 -s " + ipOf(b) + " 1.1.1.1 443"); code == 0 {
		t.Error("spoofed source address reached the internet")
	}
}

// hostLANAddr returns the host's first private IPv4 address, if any.
func hostLANAddr() string {
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.IP.IsPrivate() &&
			!strings.HasPrefix(ipn.IP.String(), "172.") {
			return ipn.IP.String()
		}
	}
	return ""
}
