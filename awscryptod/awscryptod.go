// The awscryptod binary is a daemon that provides the AWSCryptoService gRPC
// service.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "github.com/aschlosberg/myaspire/awscryptod/proto"
	log "github.com/golang/glog"
	"google.golang.org/grpc"
)

func main() {
	sock := flag.String("socket", "/tmp/awscryptod.sock", "Unix socket on which to listen.")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Info("Shutting down gracefully")
		cancel()
	}()

	if err := listen(ctx, *sock); err != nil {
		log.Exit(err)
	}
}

func listen(ctx context.Context, sock string) error {
	lis, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("listen on socket: %v", err)
	}
	log.Infof("Listening on socket %q", sock)

	srv := server()

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		srv.GracefulStop()
		lis.Close()
		close(done)
	}()

	if err := srv.Serve(lis); err != nil {
		return fmt.Errorf("gRPC serve: %v", err)
	}
	<-done
	return nil
}

func server() *grpc.Server {
	srv := grpc.NewServer()
	svc := new(service)
	pb.RegisterAWSCryptoServiceServer(srv, svc)
	return srv
}

type service struct{}
