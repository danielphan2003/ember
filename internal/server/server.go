// Package server implements the Forgejo runner's plugin.v1alpha
// BackendPlugin service: one Firecracker microVM per job.
package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/danielphan2003/ember/internal/config"
	"github.com/danielphan2003/ember/internal/image"
	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"github.com/danielphan2003/ember/internal/vm"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Paths the runner lays files out under inside every VM.
const (
	rootPath      = "/ember"
	actPath       = "/ember/act"
	toolCachePath = "/ember/toolcache"
	tempPath      = "/ember/tmp"
)

// Server is the plugin. Create one with New.
type Server struct {
	pb.UnimplementedBackendPluginServer

	cfg    config.Config
	images *image.Store
	slots  chan config.Slot
	log    *slog.Logger

	// memAvailable reports free host memory in MiB; replaced in tests.
	memAvailable func() (int, error)

	mu   sync.Mutex
	envs map[string]*environment
}

type environment struct {
	mu sync.Mutex // one RPC at a time per environment, as the protocol advises

	id        string
	imageRef  string
	vcpus     int
	memoryMiB int
	diskGiB   int
	timeout   time.Duration

	slot    *config.Slot
	machine *vm.Machine
	img     *image.Image
	timer   *time.Timer
}

// New builds a server. agent is the ember-agent binary to install in every
// root filesystem.
func New(cfg config.Config, agent []byte, log *slog.Logger) *Server {
	s := &Server{
		cfg: cfg,
		images: &image.Store{
			Dir:     filepath.Join(cfg.StateDir, "images"),
			Agent:   agent,
			Refresh: cfg.ImageRefresh,
			MinGiB:  cfg.DiskGiB,
		},
		slots:        make(chan config.Slot, cfg.Slots),
		log:          log,
		memAvailable: memAvailableMiB,
		envs:         map[string]*environment{},
	}
	for _, sl := range cfg.SlotList() {
		s.slots <- sl
	}
	return s
}

// Images exposes the image store (for `ember pull` and pruning).
func (s *Server) Images() *image.Store { return s.images }

func (s *Server) vmDir(id string) string { return filepath.Join(s.cfg.StateDir, "vms", id) }

// CleanStale removes VM directories left by a previous run.
func (s *Server) CleanStale() {
	_ = os.RemoveAll(filepath.Join(s.cfg.StateDir, "vms"))
}

// Shutdown destroys every running VM.
func (s *Server) Shutdown() {
	s.mu.Lock()
	envs := make([]*environment, 0, len(s.envs))
	for _, e := range s.envs {
		envs = append(envs, e)
	}
	s.mu.Unlock()
	for _, e := range envs {
		s.destroy(e)
	}
}

func (s *Server) Capabilities(context.Context, *pb.CapabilitiesRequest) (*pb.CapabilitiesResponse, error) {
	return &pb.CapabilitiesResponse{Name: "ember"}, nil
}

func (s *Server) Create(_ context.Context, req *pb.CreateRequest) (*pb.CreateResponse, error) {
	if len(req.GetServices()) > 0 {
		return nil, status.Error(codes.InvalidArgument,
			"ember does not support service containers: run the service inside the job (it is a full VM)")
	}
	opts := req.GetBackendOptions()
	e := &environment{
		id:        "ember-" + randomHex(6),
		imageRef:  firstNonEmpty(req.GetImage(), req.GetLabelArg(), opts["image"], s.cfg.DefaultImage),
		vcpus:     s.cfg.VCPUs,
		memoryMiB: s.cfg.MemoryMiB,
		diskGiB:   s.cfg.DiskGiB,
	}
	var err error
	if e.vcpus, err = intOption(opts, "vcpus", e.vcpus, 1, 32); err != nil {
		return nil, err
	}
	if e.memoryMiB, err = intOption(opts, "memory_mib", e.memoryMiB, 128, 1<<20); err != nil {
		return nil, err
	}
	if e.diskGiB, err = intOption(opts, "disk_gib", e.diskGiB, 1, 1024); err != nil {
		return nil, err
	}
	if d := req.GetEnvironmentTimeout(); d != nil && d.AsDuration() > 0 {
		e.timeout = d.AsDuration()
	}

	s.mu.Lock()
	s.envs[e.id] = e
	s.mu.Unlock()
	s.log.Info("create", "env", e.id, "image", e.imageRef, "vcpus", e.vcpus, "memory_mib", e.memoryMiB)

	return &pb.CreateResponse{
		EnvironmentId: e.id,
		RootPath:      rootPath,
		ActPath:       actPath,
		ToolCachePath: toolCachePath,
		TempPath:      tempPath,
		Os:            "Linux",
		Arch:          runnerArch(),
	}, nil
}

func (s *Server) lookup(id string) (*environment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.envs[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "environment %q not found", id)
	}
	return e, nil
}

// startLog serialises Start's log lines; the image puller may write from
// another goroutine.
type startLog struct {
	mu     sync.Mutex
	stream grpc.ServerStreamingServer[pb.StartOutput]
	closed bool
}

func (l *startLog) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	_ = l.stream.Send(&pb.StartOutput{Output: &pb.StartOutput_Data{Data: &pb.DataChunk{
		Data: []byte("ember: " + fmt.Sprintf(format, args...) + "\n"),
	}}})
}

func (l *startLog) complete(env map[string]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return l.stream.Send(&pb.StartOutput{Output: &pb.StartOutput_StartComplete{
		StartComplete: &pb.StartComplete{ImageEnv: env},
	}})
}

func (l *startLog) close() {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
}

func (s *Server) Start(req *pb.StartRequest, stream grpc.ServerStreamingServer[pb.StartOutput]) error {
	e, err := s.lookup(req.GetEnvironmentId())
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.machine != nil {
		return status.Error(codes.FailedPrecondition, "environment already started")
	}
	ctx := stream.Context()
	out := &startLog{stream: stream}
	defer out.close()
	began := time.Now()

	img, err := s.images.Ensure(ctx, e.imageRef, func(line string) { out.printf("%s", line) })
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "image %s: %v", e.imageRef, err)
	}
	e.img = img

	slot, err := s.acquire(ctx, e, out)
	if err != nil {
		return err
	}
	e.slot = &slot

	bootStart := time.Now()
	m, err := vm.Boot(vm.Spec{
		Dir:         s.vmDir(e.id),
		Firecracker: s.cfg.Firecracker,
		Kernel:      s.cfg.Kernel,
		BaseRootFS:  img.RootFS,
		DiskBytes:   int64(e.diskGiB) << 30,
		VCPUs:       e.vcpus,
		MemoryMiB:   e.memoryMiB,
		Tap:         slot.Tap,
		MAC:         slot.MAC,
		GuestCIDR:   slot.GuestCIDR(),
		Gateway:     slot.Host.String(),
		DNS:         s.cfg.DNS,
		Hostname:    e.id,
	})
	if err != nil {
		s.release(e)
		return status.Errorf(codes.Internal, "boot: %v", err)
	}
	e.machine = m

	bootCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = m.WaitAgent(bootCtx)
	cancel()
	if err != nil {
		tail := m.ConsoleTail(40)
		s.destroyLocked(e)
		return status.Errorf(codes.Internal, "microVM did not come up: %v\n--- console (last 40 lines) ---\n%s", err, tail)
	}
	if e.timeout > 0 {
		e.timer = time.AfterFunc(e.timeout, func() {
			s.log.Warn("environment timeout", "env", e.id, "after", e.timeout)
			m.Kill()
		})
	}

	out.printf("microVM %s ready: %s, %d vCPU, %d MiB; booted in %s (%s total)",
		e.id, shortDigest(img.Digest), e.vcpus, e.memoryMiB,
		time.Since(bootStart).Round(time.Millisecond), time.Since(began).Round(time.Millisecond))
	s.log.Info("started", "env", e.id, "slot", slot.Tap, "boot", time.Since(bootStart))
	return out.complete(imageEnv(img.Env))
}

// acquire takes a free slot and waits for enough host memory to run the VM.
func (s *Server) acquire(ctx context.Context, e *environment, out *startLog) (config.Slot, error) {
	var slot config.Slot
	select {
	case slot = <-s.slots:
	default:
		out.printf("all %d slots busy; waiting", s.cfg.Slots)
		select {
		case slot = <-s.slots:
		case <-ctx.Done():
			return slot, status.FromContextError(ctx.Err()).Err()
		}
	}
	warned := false
	for {
		free, err := s.memAvailable()
		if err != nil || free >= e.memoryMiB+s.cfg.HostReserveMiB {
			return slot, nil
		}
		if !warned {
			out.printf("waiting for memory: %d MiB available, job needs %d MiB plus %d MiB reserve",
				free, e.memoryMiB, s.cfg.HostReserveMiB)
			warned = true
		}
		select {
		case <-ctx.Done():
			s.slots <- slot
			return slot, status.FromContextError(ctx.Err()).Err()
		case <-time.After(time.Second):
		}
	}
}

func (s *Server) running(id string) (*environment, error) {
	e, err := s.lookup(id)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.machine == nil {
		e.mu.Unlock()
		return nil, status.Errorf(codes.FailedPrecondition, "environment %q is not started", id)
	}
	return e, nil
}

// vmGone turns a transport error into a readable reason when the VM died.
func (e *environment) vmGone(err error) error {
	select {
	case <-e.machine.Exited():
		return fmt.Errorf("the microVM stopped (out of memory, timeout or guest crash)\n--- console (last 20 lines) ---\n%s",
			e.machine.ConsoleTail(20))
	default:
		return err
	}
}

func (s *Server) Exec(req *pb.ExecRequest, stream grpc.ServerStreamingServer[pb.ExecOutput]) error {
	e, err := s.running(req.GetEnvironmentId())
	if err != nil {
		return err
	}
	defer e.mu.Unlock()
	if req.User == nil && e.img.User != "" {
		u := e.img.User
		req.User = &u
	}
	in, err := e.machine.Agent.Exec(stream.Context(), req)
	if err != nil {
		return execFailed(stream, e.vmGone(err))
	}
	for {
		msg, err := in.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if stream.Context().Err() != nil {
				return status.FromContextError(stream.Context().Err()).Err()
			}
			return execFailed(stream, e.vmGone(err))
		}
		if err := stream.Send(msg); err != nil {
			return err
		}
	}
}

func execFailed(stream grpc.ServerStreamingServer[pb.ExecOutput], err error) error {
	return stream.Send(&pb.ExecOutput{Output: &pb.ExecOutput_ExecFailed{
		ExecFailed: &pb.ExecFailed{ErrorMessage: err.Error()},
	}})
}

func (s *Server) CopyIn(stream grpc.ClientStreamingServer[pb.CopyInChunk, pb.CopyInResponse]) error {
	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "copyin: %v", err)
	}
	if first.EnvironmentId == nil || first.DestPath == nil {
		return status.Error(codes.InvalidArgument, "copyin: first chunk must set environment_id and dest_path")
	}
	e, err := s.running(first.GetEnvironmentId())
	if err != nil {
		return err
	}
	defer e.mu.Unlock()

	out, err := e.machine.Agent.CopyIn(stream.Context())
	if err != nil {
		return status.Errorf(codes.Internal, "copyin: %v", e.vmGone(err))
	}
	if err := out.Send(first); err != nil {
		return s.copyInError(e, out, err)
	}
	for {
		c, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if c.EnvironmentId != nil || c.DestPath != nil {
			return status.Error(codes.InvalidArgument, "copyin: environment_id or dest_path on a later chunk")
		}
		if err := out.Send(c); err != nil {
			return s.copyInError(e, out, err)
		}
	}
	if _, err := out.CloseAndRecv(); err != nil {
		return s.copyInError(e, out, err)
	}
	return stream.SendAndClose(&pb.CopyInResponse{})
}

func (s *Server) copyInError(e *environment, out grpc.ClientStreamingClient[pb.CopyInChunk, pb.CopyInResponse], err error) error {
	if errors.Is(err, io.EOF) {
		_, err = out.CloseAndRecv()
	}
	if st, ok := status.FromError(err); ok && st.Code() == codes.InvalidArgument {
		return err
	}
	return status.Errorf(codes.Internal, "copyin: %v", e.vmGone(err))
}

func (s *Server) CopyOut(req *pb.CopyOutRequest, stream grpc.ServerStreamingServer[pb.CopyOutChunk]) error {
	e, err := s.running(req.GetEnvironmentId())
	if err != nil {
		return err
	}
	defer e.mu.Unlock()
	in, err := e.machine.Agent.CopyOut(stream.Context(), req)
	if err != nil {
		return status.Errorf(codes.Internal, "copyout: %v", e.vmGone(err))
	}
	for {
		c, err := in.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
				return err
			}
			return status.Errorf(codes.Internal, "copyout: %v", e.vmGone(err))
		}
		if err := stream.Send(c); err != nil {
			return err
		}
	}
}

func (s *Server) Remove(_ context.Context, req *pb.RemoveRequest) (*pb.RemoveResponse, error) {
	e, err := s.lookup(req.GetEnvironmentId())
	if err != nil {
		return nil, err
	}
	s.destroy(e)
	return &pb.RemoveResponse{}, nil
}

func (s *Server) destroy(e *environment) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s.destroyLocked(e)
}

func (s *Server) destroyLocked(e *environment) {
	if e.timer != nil {
		e.timer.Stop()
	}
	if e.machine != nil {
		e.machine.Destroy()
		e.machine = nil
	}
	s.release(e)
	s.mu.Lock()
	delete(s.envs, e.id)
	s.mu.Unlock()
	_ = os.RemoveAll(s.vmDir(e.id))
	s.log.Info("removed", "env", e.id)
}

func (s *Server) release(e *environment) {
	if e.slot != nil {
		s.slots <- *e.slot
		e.slot = nil
	}
}

func intOption(opts map[string]string, key string, def, lo, hi int) (int, error) {
	v, ok := opts[key]
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, status.Errorf(codes.InvalidArgument, "option %s=%q must be an integer from %d to %d", key, v, lo, hi)
	}
	return n, nil
}

func imageEnv(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func shortDigest(d string) string {
	if _, h, ok := strings.Cut(d, ":"); ok && len(h) > 12 {
		return d[:len(d)-len(h)] + h[:12]
	}
	return d
}

func memAvailableMiB() (int, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "MemAvailable:"); ok {
			kb, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(rest), " kB"))
			return kb / 1024, err
		}
	}
	return 0, errors.New("MemAvailable not found")
}
