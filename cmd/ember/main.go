// Command ember runs Forgejo Actions jobs in Firecracker microVMs.
//
//	ember serve              serve the runner's plugin protocol
//	ember run [-i IMAGE] -- CMD...   boot a VM, run one command, tear it down
//	ember pull IMAGE...      build the cached root filesystem ahead of time
//	ember prune              delete cached images unused for image_keep
//	ember doctor             check that this host can run ember
//	ember host up|down       (root) create or remove the tap devices and firewall rules
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/danielphan2003/ember/internal/agentbin"
	"github.com/danielphan2003/ember/internal/config"
	"github.com/danielphan2003/ember/internal/hostnet"
	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"github.com/danielphan2003/ember/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var version = "dev"

const usage = `ember runs Forgejo Actions jobs in Firecracker microVMs.

Usage:
  ember serve                       serve the runner's plugin protocol
  ember run [-i IMAGE] -- CMD...    boot a VM, run one command, tear it down
  ember pull IMAGE...               build cached root filesystems ahead of time
  ember prune                       delete cached images unused for image_keep
  ember doctor                      check that this host can run ember
  ember host up|down                (root) create or remove taps and firewall rules
  ember version

Every command takes --config PATH (default /etc/ember/config.yaml, or $EMBER_CONFIG).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "run":
		err = cmdRun(args)
	case "pull":
		err = cmdPull(args)
	case "prune":
		err = cmdPrune(args)
	case "doctor":
		err = cmdDoctor(args)
	case "host":
		err = cmdHost(args)
	case "version", "--version":
		fmt.Println("ember", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "ember: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ember:", err)
		os.Exit(1)
	}
}

func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	def := os.Getenv("EMBER_CONFIG")
	if def == "" {
		def = "/etc/ember/config.yaml"
	}
	return fs, fs.String("config", def, "configuration file")
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func listen(addr string) (net.Listener, error) {
	if path, ok := strings.CutPrefix(addr, "unix://"); ok {
		_ = os.Remove(path)
		lis, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		// The runner reaches the socket through the group; see deploy/.
		_ = os.Chmod(path, 0o660)
		return lis, nil
	}
	return net.Listen("tcp", addr)
}

func newGRPC(srv *server.Server) *grpc.Server {
	g := grpc.NewServer(grpc.MaxRecvMsgSize(16 << 20))
	pb.RegisterBackendPluginServer(g, srv)
	h := health.NewServer()
	h.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(g, h)
	return g
}

func cmdServe(args []string) error {
	fs, cfgPath := flags("serve")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	log := newLogger()
	if err := preflight(cfg); err != nil {
		return err
	}
	srv := server.New(cfg, agentbin.Agent(), log)
	srv.CleanStale()
	if removed, err := srv.Images().Prune(cfg.ImageKeep); err == nil && len(removed) > 0 {
		log.Info("pruned images", "count", len(removed))
	}
	lis, err := listen(cfg.Listen)
	if err != nil {
		return err
	}
	g := newGRPC(srv)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Info("shutting down")
		srv.Shutdown()
		g.Stop()
	}()
	log.Info("ember ready", "version", version, "listen", cfg.Listen, "slots", cfg.Slots)
	if err := g.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// preflight fails fast on problems that would otherwise surface as a
// confusing job failure.
func preflight(cfg config.Config) error {
	if len(agentbin.Agent()) == 0 {
		return errors.New("built without the guest agent; build with `just build`")
	}
	for _, p := range []string{cfg.Firecracker, cfg.Kernel, "/dev/kvm"} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("%w (run `ember doctor`)", err)
		}
	}
	return os.MkdirAll(cfg.StateDir, 0o755)
}

func cmdHost(args []string) error {
	fs, cfgPath := flags("host")
	if len(args) < 1 || (args[0] != "up" && args[0] != "down") {
		return errors.New("usage: ember host up|down [--config PATH]")
	}
	_ = fs.Parse(args[1:])
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	logf := func(f string, a ...any) { fmt.Printf(f+"\n", a...) }
	if args[0] == "up" {
		return hostnet.Up(cfg, logf)
	}
	return hostnet.Down(cfg, logf)
}

func cmdPull(args []string) error {
	fs, cfgPath := flags("pull")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	srv := server.New(cfg, agentbin.Agent(), newLogger())
	refs := fs.Args()
	if len(refs) == 0 {
		refs = []string{cfg.DefaultImage}
	}
	for _, ref := range refs {
		img, err := srv.Images().Ensure(context.Background(), ref, func(s string) { fmt.Println(s) })
		if err != nil {
			return err
		}
		fmt.Printf("%s -> %s\n", ref, img.Digest)
	}
	return nil
}

func cmdPrune(args []string) error {
	fs, cfgPath := flags("prune")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	srv := server.New(cfg, agentbin.Agent(), newLogger())
	removed, err := srv.Images().Prune(cfg.ImageKeep)
	for _, r := range removed {
		fmt.Println("removed", r)
	}
	return err
}
