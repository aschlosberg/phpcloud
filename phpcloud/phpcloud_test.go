package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/rpc"
	"testing"

	"github.com/spiral/goridge"
)

// cryptoClient is a convenience wrapper around a net/rpc.Client using the
// goridge.ClientCodec.
type cryptoClient struct {
	*rpc.Client
}

func (cc *cryptoClient) HashPassword(req HashPasswordRequest) (*HashPasswordResponse, error) {
	resp := new(HashPasswordResponse)
	if err := cc.Call(`Crypto.HashPassword`, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (cc *cryptoClient) CheckPassword(req CheckPasswordRequest) (*CheckPasswordResponse, error) {
	resp := new(CheckPasswordResponse)
	if err := cc.Call(`Crypto.CheckPassword`, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func client(ctx context.Context, t *testing.T) (_ *cryptoClient, cleanup func()) {
	ctx, cancel := context.WithCancel(ctx)

	suffix := make([]byte, 16)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("crypto/rand.Read() for random suffix; error %v", err)
	}

	sock := fmt.Sprintf("/tmp/phpcloud-%s.sock", hex.EncodeToString(suffix))
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		if err := serve(ctx, sock, ready); err != nil {
			t.Errorf("listen() got err %v; want nil err", err)
		}
		close(done)
	}()
	<-ready

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf(`net.Dial("unix", %q) error %v`, sock, err)
	}

	cc := goridge.NewClientCodec(conn)
	cl := &cryptoClient{
		Client: rpc.NewClientWithCodec(cc),
	}
	return cl, func() {
		cancel()
		<-done
	}
}
