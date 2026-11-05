package server

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/danielphan2003/ember/internal/config"
	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newTestServer(t *testing.T) *Server {
	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	return New(cfg, []byte("agent"), slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestCreateDefaultsAndOptions(t *testing.T) {
	s := newTestServer(t)
	resp, err := s.Create(context.Background(), &pb.CreateRequest{
		LabelArg:       "docker.io/library/alpine:3.22",
		BackendOptions: map[string]string{"vcpus": "4", "memory_mib": "4096"},
	})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.lookup(resp.GetEnvironmentId())
	if err != nil {
		t.Fatal(err)
	}
	if e.imageRef != "docker.io/library/alpine:3.22" || e.vcpus != 4 || e.memoryMiB != 4096 {
		t.Fatalf("%+v", e)
	}
	if resp.GetActPath() != actPath || resp.GetOs() != "Linux" {
		t.Fatalf("%+v", resp)
	}

	// The workflow's container image wins over the label.
	resp, _ = s.Create(context.Background(), &pb.CreateRequest{Image: "debian:trixie", LabelArg: "alpine"})
	if e, _ := s.lookup(resp.GetEnvironmentId()); e.imageRef != "debian:trixie" {
		t.Fatalf("image override ignored: %s", e.imageRef)
	}
}

func TestCreateRejects(t *testing.T) {
	s := newTestServer(t)
	for name, req := range map[string]*pb.CreateRequest{
		"services": {Services: []*pb.ServiceContainer{{Name: "db", Image: "postgres"}}},
		"vcpus":    {BackendOptions: map[string]string{"vcpus": "lots"}},
		"memory":   {BackendOptions: map[string]string{"memory_mib": "1"}},
	} {
		if _, err := s.Create(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: want InvalidArgument, got %v", name, err)
		}
	}
}

func TestUnknownEnvironment(t *testing.T) {
	s := newTestServer(t)
	if _, err := s.Remove(context.Background(), &pb.RemoveRequest{EnvironmentId: "nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("want NotFound, got %v", err)
	}
}

func TestRemoveBeforeStart(t *testing.T) {
	s := newTestServer(t)
	resp, err := s.Create(context.Background(), &pb.CreateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Remove(context.Background(), &pb.RemoveRequest{EnvironmentId: resp.GetEnvironmentId()}); err != nil {
		t.Fatal(err)
	}
	if len(s.slots) != s.cfg.Slots {
		t.Fatalf("slot leaked: %d free of %d", len(s.slots), s.cfg.Slots)
	}
}
