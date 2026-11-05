package agent

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func client(t *testing.T) pb.BackendPluginClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	pb.RegisterBackendPluginServer(srv, &Server{})
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///agent",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewBackendPluginClient(conn)
}

func run(t *testing.T, c pb.BackendPluginClient, req *pb.ExecRequest) (stdout, stderr string, code int32, failed string) {
	t.Helper()
	s, err := c.Exec(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	var o, e bytes.Buffer
	for {
		msg, err := s.Recv()
		if errors.Is(err, io.EOF) {
			return o.String(), e.String(), code, failed
		}
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case msg.GetData() != nil && msg.GetData().GetStream() == pb.DataChunk_STDERR:
			e.Write(msg.GetData().GetData())
		case msg.GetData() != nil:
			o.Write(msg.GetData().GetData())
		case msg.GetExecComplete() != nil:
			code = msg.GetExecComplete().GetExitCode()
		case msg.GetExecFailed() != nil:
			failed = msg.GetExecFailed().GetErrorMessage()
		}
	}
}

func TestExec(t *testing.T) {
	c := client(t)
	dir := filepath.Join(t.TempDir(), "new", "workdir")
	out, errOut, code, failed := run(t, c, &pb.ExecRequest{
		Command: []string{"sh", "-c", `echo "$GREETING from $(pwd)"; echo oops >&2; exit 3`},
		Env:     map[string]string{"GREETING": "hello", "PATH": "/usr/bin:/bin"},
		Workdir: dir,
	})
	if failed != "" {
		t.Fatalf("exec failed: %s", failed)
	}
	if out != "hello from "+dir+"\n" || errOut != "oops\n" || code != 3 {
		t.Fatalf("got stdout=%q stderr=%q code=%d", out, errOut, code)
	}
}

func TestExecMissingBinary(t *testing.T) {
	c := client(t)
	_, _, _, failed := run(t, c, &pb.ExecRequest{Command: []string{"no-such-binary-ember"}, Workdir: t.TempDir()})
	if !strings.Contains(failed, "not found in PATH") {
		t.Fatalf("want a not-found failure, got %q", failed)
	}
}

func TestExecUsesRequestPath(t *testing.T) {
	c := client(t)
	bin := t.TempDir()
	script := filepath.Join(bin, "ember-hello")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho from-request-path\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, _, code, failed := run(t, c, &pb.ExecRequest{
		Command: []string{"ember-hello"},
		Env:     map[string]string{"PATH": bin + ":/usr/bin:/bin"},
		Workdir: t.TempDir(),
	})
	if failed != "" || code != 0 || out != "from-request-path\n" {
		t.Fatalf("got %q code=%d failed=%q", out, code, failed)
	}
}

func TestExecCancelKillsProcessGroup(t *testing.T) {
	c := client(t)
	ctx, cancel := context.WithCancel(context.Background())
	marker := filepath.Join(t.TempDir(), "survived")
	s, err := c.Exec(ctx, &pb.ExecRequest{
		Command: []string{"sh", "-c", "(sleep 2; touch " + marker + ") & echo started; wait"},
		Workdir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recv(); err != nil {
		t.Fatal(err)
	}
	cancel()
	for {
		if _, err := s.Recv(); err != nil {
			break
		}
	}
	// The background child must die with the group.
	if out, _, _, _ := run(t, c, &pb.ExecRequest{Command: []string{"sh", "-c", "sleep 2.5; test -e " + marker + " && echo yes || echo no"}, Workdir: t.TempDir()}); out != "no\n" {
		t.Fatalf("background process survived cancellation")
	}
}

func tarOf(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		body := []byte(h.Linkname)
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(h.Name))
			body = []byte(h.Name)
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			tw.Write(body)
		}
	}
	tw.Close()
	return buf.Bytes()
}

func copyIn(c pb.BackendPluginClient, dest string, data []byte) error {
	s, err := c.CopyIn(context.Background())
	if err != nil {
		return err
	}
	id := "env"
	if err := s.Send(&pb.CopyInChunk{EnvironmentId: &id, DestPath: &dest}); err != nil {
		return err
	}
	for len(data) > 0 {
		n := min(len(data), 7) // small chunks exercise reassembly
		if err := s.Send(&pb.CopyInChunk{Data: data[:n]}); err != nil {
			break
		}
		data = data[n:]
	}
	_, err = s.CloseAndRecv()
	return err
}

func TestCopyInAndOut(t *testing.T) {
	c := client(t)
	dest := filepath.Join(t.TempDir(), "act")
	err := copyIn(c, dest, tarOf(t,
		&tar.Header{Name: "dir/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "dir/script.sh", Typeflag: tar.TypeReg, Mode: 0o755},
		&tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "dir/script.sh"},
	))
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dest, "dir/script.sh"))
	if err != nil || fi.Mode().Perm() != 0o755 {
		t.Fatalf("script: %v %v", fi, err)
	}
	if target, _ := os.Readlink(filepath.Join(dest, "link")); target != "dir/script.sh" {
		t.Fatalf("symlink target %q", target)
	}

	// CopyOut of a file yields one entry named after the file.
	s, err := c.CopyOut(context.Background(), &pb.CopyOutRequest{SrcPath: filepath.Join(dest, "dir/script.sh")})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for {
		ch, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(ch.GetData())
	}
	tr := tar.NewReader(&buf)
	h, err := tr.Next()
	if err != nil || h.Name != "script.sh" {
		t.Fatalf("copyout entry %v %v", h, err)
	}
	if b, _ := io.ReadAll(tr); string(b) != "dir/script.sh" {
		t.Fatalf("copyout body %q", b)
	}
}

func TestCopyOutMissingIsEmptyArchive(t *testing.T) {
	c := client(t)
	s, err := c.CopyOut(context.Background(), &pb.CopyOutRequest{SrcPath: "/nonexistent/ember"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for {
		ch, err := s.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(ch.GetData())
	}
	if _, err := tar.NewReader(&buf).Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want an empty archive, got %v", err)
	}
}

func TestCopyInContainsTraversal(t *testing.T) {
	c := client(t)
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	err := copyIn(c, dest, tarOf(t, &tar.Header{Name: "../escaped", Typeflag: tar.TypeReg, Mode: 0o644}))
	// "../escaped" is cleaned to "/escaped" under dest, so it stays inside.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "escaped")); err == nil {
		t.Fatal("entry escaped the destination")
	}
	if _, err := os.Stat(filepath.Join(dest, "escaped")); err != nil {
		t.Fatalf("entry not placed inside dest: %v", err)
	}
}

func TestParseCmdline(t *testing.T) {
	p := ParseCmdline("console=ttyS0 ember.ip=172.30.0.2/30 ember.gw=172.30.0.1 ember.dns=1.1.1.1,9.9.9.9 ember.hostname=job")
	if p.Addr != "172.30.0.2/30" || p.Gateway != "172.30.0.1" || len(p.DNS) != 2 || p.Hostname != "job" {
		t.Fatalf("%+v", p)
	}
}

func TestExecDoesNotWaitForBackgroundProcesses(t *testing.T) {
	c := client(t)
	start := time.Now()
	out, _, code, failed := run(t, c, &pb.ExecRequest{
		Command: []string{"sh", "-c", "sleep 5 & echo started"},
		Workdir: t.TempDir(),
	})
	if failed != "" || code != 0 || out != "started\n" {
		t.Fatalf("got %q code=%d failed=%q", out, code, failed)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("exec waited %s for a background process", d)
	}
}
