// The awscryptod binary is a daemon that provides a "Crypto" RPC service.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"os/signal"
	"syscall"

	log "github.com/golang/glog"
	"github.com/spiral/goridge"
)

func main() {
	sock := flag.String("socket", "/tmp/awscryptod.sock", "Unix socket on which to listen.")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Infof("Shutting down on signal: %s", <-sig)
		cancel()
	}()

	if err := serve(ctx, *sock, nil); err != nil {
		log.Exit(err)
	}
}

// serve listens on sock, closing ready (if non-nil) once listening, and then
// accepts net/rpc connections with the goridge Codec.
func serve(ctx context.Context, sock string, ready chan struct{}) error {
	lis, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("listen on socket: %v", err)
	}
	if err := os.Chmod(sock, 0770); err != nil {
		return fmt.Errorf("chmod socket to 770: %v", err)
	}
	if err := os.Chown(sock, os.Getuid(), os.Getgid()); err != nil {
		return fmt.Errorf("chown socket %d:%d: %v", os.Getuid(), os.Getgid(), err)
	}

	if ready != nil {
		close(ready)
	}
	log.Infof("Listening on socket %q", sock)

	rpc.Register(new(Crypto))

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		lis.Close()
		close(done)
	}()

AcceptLoop:
	for {
		conn, err := lis.Accept()

		// It's not possible to use errors.Is() to determine if err is because
		// of a closed connection, but this will be because the context was
		// cancelled.
		// https://github.com/golang/go/issues/4373
		select {
		case <-ctx.Done():
			break AcceptLoop
		default:
		}

		if err != nil {
			log.Warningf("Ignoring net.Listener.Accept() error: %T %v", err, err)
			continue
		}
		go rpc.ServeCodec(goridge.NewCodec(conn))
	}

	<-done
	return nil
}

// Crypto implements a net/rpc service.
type Crypto struct{}
