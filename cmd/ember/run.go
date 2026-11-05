package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/danielphan2003/ember/internal/config"
	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// cmdRun talks to a running `ember serve` exactly like the Forgejo runner
// does: Create, Start, Exec, Remove. It is the quickest way to try an image
// or debug a job environment.
func cmdRun(args []string) error {
	fs, cfgPath := flags("run")
	img := fs.String("i", "", "image (default: default_image from the config)")
	vcpus := fs.Int("vcpus", 0, "vCPUs (default from config)")
	mem := fs.Int("memory", 0, "memory in MiB (default from config)")
	quiet := fs.Bool("q", false, "do not print boot and timing lines")
	_ = fs.Parse(args)
	argv := fs.Args()
	if len(argv) == 0 {
		argv = []string{"sh", "-c", "uname -a; cat /etc/os-release | head -2"}
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	target := cfg.Listen
	if p, ok := strings.CutPrefix(target, "unix://"); ok {
		target = "unix:" + p
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewBackendPluginClient(conn)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	opts := map[string]string{}
	if *vcpus > 0 {
		opts["vcpus"] = strconv.Itoa(*vcpus)
	}
	if *mem > 0 {
		opts["memory_mib"] = strconv.Itoa(*mem)
	}
	t0 := time.Now()
	created, err := c.Create(ctx, &pb.CreateRequest{Image: *img, Name: "ember-run", BackendOptions: opts})
	if err != nil {
		return fmt.Errorf("create (is `ember serve` running at %s?): %w", cfg.Listen, err)
	}
	id := created.GetEnvironmentId()
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		_, _ = c.Remove(rctx, &pb.RemoveRequest{EnvironmentId: id})
	}()

	start, err := c.Start(ctx, &pb.StartRequest{EnvironmentId: id})
	if err != nil {
		return err
	}
	var imageEnv map[string]string
	for {
		msg, err := start.Recv()
		if errors.Is(err, io.EOF) {
			return errors.New("start ended without completing")
		}
		if err != nil {
			return err
		}
		if d := msg.GetData(); d != nil {
			if !*quiet {
				os.Stderr.Write(d.GetData())
			}
			continue
		}
		imageEnv = msg.GetStartComplete().GetImageEnv()
		break
	}
	ready := time.Since(t0)

	env := map[string]string{"HOME": "/root"}
	for k, v := range imageEnv {
		env[k] = v
	}
	exec, err := c.Exec(ctx, &pb.ExecRequest{EnvironmentId: id, Command: argv, Env: env, Workdir: "/root"})
	if err != nil {
		return err
	}
	code := 0
	for {
		msg, err := exec.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		switch {
		case msg.GetData() != nil:
			if msg.GetData().GetStream() == pb.DataChunk_STDERR {
				os.Stderr.Write(msg.GetData().GetData())
			} else {
				os.Stdout.Write(msg.GetData().GetData())
			}
		case msg.GetExecComplete() != nil:
			code = int(msg.GetExecComplete().GetExitCode())
		case msg.GetExecFailed() != nil:
			return errors.New(msg.GetExecFailed().GetErrorMessage())
		}
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "ember: ready in %s, command finished at %s\n",
			ready.Round(time.Millisecond), time.Since(t0).Round(time.Millisecond))
	}
	if code != 0 {
		// Clean up before exiting with the command's status.
		rctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, _ = c.Remove(rctx, &pb.RemoveRequest{EnvironmentId: id})
		cancel()
		os.Exit(code)
	}
	return nil
}
