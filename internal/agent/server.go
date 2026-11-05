// Package agent is the guest side of ember: it runs inside each microVM and
// executes commands and file copies for the host.
//
// The agent serves the same BackendPlugin gRPC service the runner speaks
// (Exec, CopyIn and CopyOut only), so the host can relay those calls without
// translating them. environment_id is ignored: one agent serves one VM.
package agent

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Server implements the guest half of the BackendPlugin service.
type Server struct {
	pb.UnimplementedBackendPluginServer
}

func (s *Server) Capabilities(context.Context, *pb.CapabilitiesRequest) (*pb.CapabilitiesResponse, error) {
	return &pb.CapabilitiesResponse{Name: "ember-agent"}, nil
}

func (s *Server) Exec(req *pb.ExecRequest, stream grpc.ServerStreamingServer[pb.ExecOutput]) error {
	argv := req.GetCommand()
	if len(argv) == 0 {
		return status.Error(codes.InvalidArgument, "empty command")
	}
	env := req.GetEnv()
	if env == nil {
		env = map[string]string{}
	}
	if env["PATH"] == "" {
		env["PATH"] = defaultPath
	}

	cred, home, err := lookupUser(req.GetUser())
	if err != nil {
		return sendExecFailed(stream, err.Error())
	}
	if env["HOME"] == "" && home != "" {
		env["HOME"] = home
	}

	bin, err := lookPath(argv[0], env["PATH"])
	if err != nil {
		return sendExecFailed(stream, err.Error())
	}

	dir := req.GetWorkdir()
	if dir == "" {
		dir = "/"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return sendExecFailed(stream, fmt.Sprintf("create workdir: %v", err))
	}
	if cred != nil {
		// A fresh workdir must be usable by the user the step runs as.
		_ = os.Chown(dir, int(cred.Uid), int(cred.Gid))
	}

	cmd := exec.Command(bin, argv[1:]...)
	cmd.Args[0] = argv[0]
	cmd.Dir = dir
	cmd.Env = envList(env)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: cred}

	var mu sync.Mutex
	cmd.Stdout = &chunkWriter{mu: &mu, stream: stream, kind: pb.DataChunk_STDOUT}
	cmd.Stderr = &chunkWriter{mu: &mu, stream: stream, kind: pb.DataChunk_STDERR}

	if err := cmd.Start(); err != nil {
		return sendExecFailed(stream, err.Error())
	}

	// Cancellation of the stream means the job was cancelled or timed out:
	// kill the whole process group, not only the direct child.
	done := make(chan struct{})
	go func() {
		select {
		case <-stream.Context().Done():
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		case <-done:
		}
	}()
	waitErr := cmd.Wait()
	close(done)

	code := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			return sendExecFailed(stream, waitErr.Error())
		}
		code = exitErr.ExitCode()
		if code < 0 {
			code = 128 + int(exitErr.Sys().(syscall.WaitStatus).Signal())
		}
	}
	mu.Lock()
	defer mu.Unlock()
	return stream.Send(&pb.ExecOutput{Output: &pb.ExecOutput_ExecComplete{
		ExecComplete: &pb.ExecComplete{ExitCode: int32(code)},
	}})
}

func sendExecFailed(stream grpc.ServerStreamingServer[pb.ExecOutput], msg string) error {
	return stream.Send(&pb.ExecOutput{Output: &pb.ExecOutput_ExecFailed{
		ExecFailed: &pb.ExecFailed{ErrorMessage: msg},
	}})
}

type chunkWriter struct {
	mu     *sync.Mutex
	stream grpc.ServerStreamingServer[pb.ExecOutput]
	kind   pb.DataChunk_Stream
}

func (w *chunkWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	data := append([]byte(nil), p...)
	if err := w.stream.Send(&pb.ExecOutput{Output: &pb.ExecOutput_Data{
		Data: &pb.DataChunk{Stream: w.kind, Data: data},
	}}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func envList(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

// lookPath resolves name against the PATH the step asked for, not the
// agent's own.
func lookPath(name, path string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: executable not found in PATH", name)
}

// lookupUser maps the runner's user field (name, uid or uid:gid) to
// credentials. Empty means root, the image default.
func lookupUser(spec string) (*syscall.Credential, string, error) {
	if spec == "" || spec == "root" || spec == "0" {
		return nil, "/root", nil
	}
	name, group, _ := strings.Cut(spec, ":")
	u, err := user.Lookup(name)
	if err != nil {
		u, err = user.LookupId(name)
	}
	var uid, gid uint64
	home := ""
	if err == nil {
		uid, _ = strconv.ParseUint(u.Uid, 10, 32)
		gid, _ = strconv.ParseUint(u.Gid, 10, 32)
		home = u.HomeDir
	} else if n, perr := strconv.ParseUint(name, 10, 32); perr == nil {
		uid, gid = n, n
	} else {
		return nil, "", fmt.Errorf("unknown user %q", name)
	}
	if group != "" {
		if g, err := user.LookupGroup(group); err == nil {
			gid, _ = strconv.ParseUint(g.Gid, 10, 32)
		} else if n, perr := strconv.ParseUint(group, 10, 32); perr == nil {
			gid = n
		} else {
			return nil, "", fmt.Errorf("unknown group %q", group)
		}
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, home, nil
}

func (s *Server) CopyIn(stream grpc.ClientStreamingServer[pb.CopyInChunk, pb.CopyInResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "copyin: no header chunk: %v", err)
	}
	if first.DestPath == nil {
		return status.Error(codes.InvalidArgument, "copyin: first chunk has no dest_path")
	}
	dest := first.GetDestPath()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return status.Errorf(codes.Internal, "copyin: %v", err)
	}
	r := &chunkReader{pending: first.GetData(), recv: func() ([]byte, error) {
		c, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		if c.EnvironmentId != nil || c.DestPath != nil {
			return nil, status.Error(codes.InvalidArgument, "copyin: header fields on a later chunk")
		}
		return c.GetData(), nil
	}}
	if err := Untar(r, dest); err != nil {
		if _, ok := status.FromError(err); ok {
			return err
		}
		return status.Errorf(codes.Internal, "copyin: %v", err)
	}
	// Drain anything after the tar end marker so the client sees success.
	_, _ = io.Copy(io.Discard, r)
	return stream.SendAndClose(&pb.CopyInResponse{})
}

type chunkReader struct {
	pending []byte
	recv    func() ([]byte, error)
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		b, err := r.recv()
		if err != nil {
			return 0, err
		}
		r.pending = b
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// Untar extracts a tar stream under dest, refusing entries that would land
// outside it.
func Untar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := within(dest, hdr.Name)
		if err != nil {
			return err
		}
		mode := fs.FileMode(hdr.Mode) & fs.ModePerm
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, mode|0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			// Respect the mode exactly (umask would otherwise strip bits).
			if err := os.Chmod(target, mode); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
			continue
		case tar.TypeLink:
			src, err := within(dest, hdr.Linkname)
			if err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Link(src, target); err != nil {
				return err
			}
		default:
			continue
		}
		if hdr.Uid != 0 || hdr.Gid != 0 {
			_ = os.Lchown(target, hdr.Uid, hdr.Gid)
		}
	}
}

func within(dest, name string) (string, error) {
	clean := filepath.Clean("/" + name)
	target := filepath.Join(dest, clean)
	if target != filepath.Clean(dest) && !strings.HasPrefix(target, filepath.Clean(dest)+"/") {
		return "", status.Errorf(codes.InvalidArgument, "tar entry %q escapes %s", name, dest)
	}
	return target, nil
}

func (s *Server) CopyOut(req *pb.CopyOutRequest, stream grpc.ServerStreamingServer[pb.CopyOutChunk]) error {
	src := req.GetSrcPath()
	fi, err := os.Lstat(src)
	if err != nil {
		return status.Errorf(codes.NotFound, "copyout: %v", err)
	}
	w := &copyOutWriter{stream: stream}
	tw := tar.NewWriter(w)
	if fi.IsDir() {
		err = tw.AddFS(os.DirFS(src))
	} else {
		err = addFile(tw, src, filepath.Base(src), fi)
	}
	if err == nil {
		err = tw.Close()
	}
	if err != nil {
		return status.Errorf(codes.Internal, "copyout: %v", err)
	}
	return w.flush()
}

func addFile(tw *tar.Writer, path, name string, fi fs.FileInfo) error {
	link := ""
	if fi.Mode()&fs.ModeSymlink != 0 {
		var err error
		if link, err = os.Readlink(path); err != nil {
			return err
		}
	}
	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

const chunkSize = 256 * 1024

type copyOutWriter struct {
	stream grpc.ServerStreamingServer[pb.CopyOutChunk]
	buf    []byte
}

func (w *copyOutWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for len(w.buf) >= chunkSize {
		if err := w.stream.Send(&pb.CopyOutChunk{Data: w.buf[:chunkSize]}); err != nil {
			return 0, err
		}
		w.buf = append([]byte(nil), w.buf[chunkSize:]...)
	}
	return len(p), nil
}

func (w *copyOutWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	err := w.stream.Send(&pb.CopyOutChunk{Data: w.buf})
	w.buf = nil
	return err
}
