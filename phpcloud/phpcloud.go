// The phpcloud binary is a daemon that provides a "Crypto" RPC service. It does
// not daemonise itself, but relies on an external mechanism.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	log "github.com/golang/glog"
	"github.com/spiral/goridge"
)

func main() {
	sock := flag.String("socket", "/tmp/phpcloud.sock", "Unix socket on which to listen.")
	healthPort := flag.Int("health_port", 1810, "Port on which to start an HTTP server responding to health checks.")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGKILL, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		log.Infof("Shutting down on signal: %s", <-sig)
		cancel()
	}()

	if err := register(new(Crypto), NewAWS(nil)); err != nil {
		log.Exitf("Register RPC services: %v", err)
	}

	ready := make(chan struct{})
	go func() {
		<-ready
		serveHealthCheck(fmt.Sprintf("127.0.0.1:%d", *healthPort))
	}()

	if err := serve(ctx, *sock, ready); err != nil {
		log.Exit(err)
	}
}

func register(c *Crypto, a *AWS) error {
	return registerWithPrefix("", c, a)
}

// registerWithPrefix allows tests to inject uniquely identifiable services. In
// production, an empty prefix should be used by calling register(), which has
// the same effective outcome as calling net/rpc.Register() with each of the
// service implementations.
//
// registerWithPrefix calls net/rpc.RegisterName with all of the service
// implementations, prepending `prefix` to each of their types. For example,
// with prefix "foo", c will be registered as "fooCrypto".
func registerWithPrefix(prefix string, c *Crypto, a *AWS) error {
	for _, rcvr := range []interface{}{c, a} {
		if reflect.ValueOf(rcvr).IsNil() {
			continue
		}
		name := prefix + reflect.TypeOf(rcvr).Elem().Name()
		if err := rpc.RegisterName(name, rcvr); err != nil {
			return fmt.Errorf("register receiver %q: %v", name, err)
		}
	}
	return nil
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		lis.Close()
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

func serveHealthCheck(addr string) {
	const path = "/health"
	log.Infof("Starting health server on http://%s%s", addr, path)

	http.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("Ok"))
	})
	http.ListenAndServe(addr, nil)
}
