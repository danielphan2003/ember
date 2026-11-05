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
	"sync/atomic"
	"time"

	"github.com/danielphan2003/ember/internal/config"
	"github.com/danielphan2003/ember/internal/image"
	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"github.com/danielphan2003/ember/internal/vm"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultLifetime bounds an environment when the runner sends no timeout.
const defaultLifetime = 6 * time.Hour

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

	// memAvailable and diskFreeGiB report host resources; replaced in tests.
	memAvailable func() (int, error)
	diskFreeGiB  func(path string) (int, error)
	memBudget    int // MiB all VMs together may be given

	mu        sync.Mutex
	envs      map[string]*environment
	committed int // MiB promised to started VMs, guarded by mu
}

type environment struct {
	mu sync.Mutex // one RPC at a time per environment, as the protocol advises

	id        string
	imageRef  string
	vcpus     int
	memoryMiB int
	diskGiB   int
	timeout   time.Duration

	slot     *config.Slot
	reserved int // MiB counted in Server.committed
	machine  *vm.Machine
	// live is the running VM, readable without mu so Remove and Shutdown
	// can stop a VM whose agent call is stuck while holding mu.
	live  atomic.Pointer[vm.Machine]
	img   *image.Image
	timer *time.Timer
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
			MaxMiB:  cfg.MaxImageMiB,
		},
		slots:        make(chan config.Slot, cfg.Slots),
		log:          log,
		memAvailable: memAvailableMiB,
		diskFreeGiB:  diskFreeGiB,
		memBudget:    cfg.MemoryBudgetMiB,
		envs:         map[string]*environment{},
	}
	if s.memBudget == 0 {
		total, err := memTotalMiB()
		if err != nil {
			total = cfg.Slots * cfg.MemoryMiB
		}
		s.memBudget = max(total-cfg.HostReserveMiB, cfg.MemoryMiB)
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

// KillAll stops every VM at once without waiting for in-flight calls.
func (s *Server) KillAll() {
	for _, e := range s.snapshot() {
		if m := e.live.Load(); m != nil {
			m.Kill()
		}
	}
}

// Shutdown destroys every VM and frees its slot. Call it after the gRPC
// server has stopped, so no Start still holds an environment.
func (s *Server) Shutdown() {
	s.KillAll()
	for _, e := range s.snapshot() {
		s.destroy(e)
	}
}

func (s *Server) snapshot() []*environment {
	s.mu.Lock()
	defer s.mu.Unlock()
	envs := make([]*environment, 0, len(s.envs))
	for _, e := range s.envs {
		envs = append(envs, e)
	}
	return envs
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
		imageRef:  firstNonEmpty(req.GetImage(), req.GetLabelArg(), s.cfg.DefaultImage),
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
	e.timeout = defaultLifetime
	if d := req.GetEnvironmentTimeout(); d != nil && d.AsDuration() > 0 {
		e.timeout = d.AsDuration()
	}

	s.mu.Lock()
	s.envs[e.id] = e
	s.mu.Unlock()
	// The lifetime runs from Create, so an environment whose Remove never
	// comes (the runner restarted mid-job) still gives its slot back.
	e.timer = time.AfterFunc(e.timeout, func() {
		s.log.Warn("environment lifetime exceeded; removing", "env", e.id, "after", e.timeout)
		if m := e.live.Load(); m != nil {
			m.Kill()
		}
		s.destroy(e)
	})
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

	if free, err := s.diskFreeGiB(s.cfg.StateDir); err == nil && free < s.cfg.MinFreeGiB {
		return status.Errorf(codes.ResourceExhausted,
			"only %d GiB free in %s (min_free_gib is %d); refusing to start a VM", free, s.cfg.StateDir, s.cfg.MinFreeGiB)
	}

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
		s.teardownLocked(e)
		return status.Errorf(codes.Internal, "boot: %v", err)
	}
	e.machine = m
	e.live.Store(m)

	bootCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = m.WaitAgent(bootCtx)
	cancel()
	if err != nil {
		tail := m.ConsoleTail(40)
		s.teardownLocked(e) // the runner still sends Remove
		return status.Errorf(codes.Internal, "microVM did not come up: %v\n--- console (last 40 lines) ---\n%s", err, tail)
	}
	out.printf("microVM %s ready: %s, %d vCPU, %d MiB; booted in %s (%s total)",
		e.id, shortDigest(img.Digest), e.vcpus, e.memoryMiB,
		time.Since(bootStart).Round(time.Millisecond), time.Since(began).Round(time.Millisecond))
	s.log.Info("started", "env", e.id, "slot", slot.Tap, "boot", time.Since(bootStart))
	return out.complete(imageEnv(img.Env))
}

// acquire takes a free slot and reserves the VM's memory. It waits while
// the memory budget is spent or the host is short of memory; meanwhile it
// holds no slot, so a smaller job can still start.
func (s *Server) acquire(ctx context.Context, e *environment, out *startLog) (config.Slot, error) {
	if e.memoryMiB > s.memBudget {
		return config.Slot{}, status.Errorf(codes.InvalidArgument,
			"job asks for %d MiB, more than the %d MiB budget for all VMs", e.memoryMiB, s.memBudget)
	}
	warnedSlots, warnedMem := false, false
	for {
		var slot config.Slot
		select {
		case slot = <-s.slots:
		default:
			if !warnedSlots {
				out.printf("all %d slots busy; waiting", s.cfg.Slots)
				warnedSlots = true
			}
			select {
			case slot = <-s.slots:
			case <-ctx.Done():
				return slot, status.FromContextError(ctx.Err()).Err()
			}
		}
		free, ferr := s.memAvailable()
		s.mu.Lock()
		ok := s.committed+e.memoryMiB <= s.memBudget &&
			(ferr != nil || free >= e.memoryMiB+s.cfg.HostReserveMiB)
		if ok {
			s.committed += e.memoryMiB
			e.reserved = e.memoryMiB
		}
		committed := s.committed
		s.mu.Unlock()
		if ok {
			return slot, nil
		}
		s.slots <- slot
		if !warnedMem {
			out.printf("waiting for memory: %d of %d MiB promised to VMs, %d MiB available on the host; job needs %d MiB",
				committed, s.memBudget, free, e.memoryMiB)
			warnedMem = true
		}
		select {
		case <-ctx.Done():
			return slot, status.FromContextError(ctx.Err()).Err()
		case <-time.After(500 * time.Millisecond):
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
	// Kill first, without the lock: an agent call stuck in a hung guest
	// holds mu, and killing the VM is what unblocks it.
	if m := e.live.Load(); m != nil {
		m.Kill()
	}
	s.destroy(e)
	return &pb.RemoveResponse{}, nil
}

func (s *Server) destroy(e *environment) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s.destroyLocked(e)
}

// destroyLocked tears the environment down and forgets it.
func (s *Server) destroyLocked(e *environment) {
	if e.timer != nil {
		e.timer.Stop()
	}
	s.teardownLocked(e)
	s.mu.Lock()
	_, known := s.envs[e.id]
	delete(s.envs, e.id)
	s.mu.Unlock()
	if known {
		s.log.Info("removed", "env", e.id)
	}
}

// teardownLocked stops the VM and returns its slot, memory and disk, but
// keeps the environment known so the runner's Remove still succeeds.
func (s *Server) teardownLocked(e *environment) {
	if e.machine != nil {
		e.machine.Destroy()
		e.machine = nil
		e.live.Store(nil)
	}
	_ = os.RemoveAll(s.vmDir(e.id))
	if e.slot != nil {
		s.slots <- *e.slot
		e.slot = nil
	}
	if e.reserved > 0 {
		s.mu.Lock()
		s.committed -= e.reserved
		s.mu.Unlock()
		e.reserved = 0
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

func memAvailableMiB() (int, error) { return meminfoMiB("MemAvailable:") }

func meminfoMiB(key string) (int, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), key); ok {
			kb, err := strconv.Atoi(strings.TrimSuffix(strings.TrimSpace(rest), " kB"))
			return kb / 1024, err
		}
	}
	return 0, fmt.Errorf("%s not found in /proc/meminfo", key)
}

func memTotalMiB() (int, error) { return meminfoMiB("MemTotal:") }

func diskFreeGiB(path string) (int, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int(st.Bavail * uint64(st.Bsize) >> 30), nil
}
