// Command ember-agent runs inside each ember microVM as PID 1.
//
// As PID 1 it mounts the pseudo-filesystems, configures the network from the
// kernel command line, then supervises "ember-agent serve", which answers the
// host over vsock.
//
// For tests it can also serve on a unix socket outside a VM:
//
//	ember-agent serve --listen unix:/tmp/agent.sock
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/danielphan2003/ember/internal/agent"
	pb "github.com/danielphan2003/ember/internal/pluginpb"
	"github.com/mdlayher/vsock"
	"google.golang.org/grpc"
)

// Port is the vsock port the agent listens on; the host connects to it.
const Port = 1024

func main() {
	log.SetFlags(0)
	log.SetPrefix("ember-agent: ")

	if os.Getpid() == 1 {
		if err := agent.Init(); err != nil {
			log.Printf("init: %v", err)
		}
		agent.Supervise([]string{"serve"})
		return
	}

	if len(os.Args) < 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "usage: ember-agent serve [--listen unix:PATH|vsock]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "vsock", "where to listen: vsock or unix:PATH")
	_ = fs.Parse(os.Args[2:])

	var (
		lis net.Listener
		err error
	)
	if path, ok := strings.CutPrefix(*listen, "unix:"); ok {
		_ = os.Remove(path)
		lis, err = net.Listen("unix", path)
	} else {
		lis, err = vsock.Listen(Port, nil)
	}
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	pb.RegisterBackendPluginServer(srv, &agent.Server{})
	log.Printf("ready on %s", lis.Addr())
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
