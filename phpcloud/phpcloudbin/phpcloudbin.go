// The phpcloud binary is a daemon that provides a "Crypto" RPC service. It does
// not daemonise itself, but relies on an external mechanism.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/aschlosberg/phpcloud/phpcloud"
	log "github.com/golang/glog"
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

	if err := phpcloud.Register(phpcloud.NewCrypto(), phpcloud.NewAWS(nil)); err != nil {
		log.Exitf("Register RPC services: %v", err)
	}

	ready := make(chan struct{})
	go func() {
		<-ready
		serveHealthCheck(fmt.Sprintf("127.0.0.1:%d", *healthPort))
	}()

	if err := phpcloud.Serve(ctx, *sock, ready); err != nil {
		log.Exit(err)
	}
}

func serveHealthCheck(addr string) {
	const path = "/health"
	log.Infof("Starting health server on http://%s%s", addr, path)

	http.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("Ok"))
	})
	http.ListenAndServe(addr, nil)
}
