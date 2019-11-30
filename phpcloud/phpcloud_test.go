package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/rpc"
	"testing"

	"github.com/spiral/goridge"
)

// rpcClient is a convenience wrapper around a net/rpc.Client using the
// goridge.ClientCodec.
type rpcClient struct {
	*rpc.Client
	// prefix allows for registering the same service type multiple times,
	// directing Call()s to the correct receiver.
	prefix string
}

func (c *rpcClient) Call(method string, args, reply interface{}) error {
	return c.Client.Call(c.prefix+method, args, reply)
}

func (c *rpcClient) HashPassword(req HashPasswordRequest) (*HashPasswordResponse, error) {
	resp := new(HashPasswordResponse)
	if err := c.Call(`Crypto.HashPassword`, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *rpcClient) CheckPassword(req CheckPasswordRequest) (*CheckPasswordResponse, error) {
	resp := new(CheckPasswordResponse)
	if err := c.Call(`Crypto.CheckPassword`, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *rpcClient) Secret(req SecretRequest) (*SecretResponse, error) {
	resp := new(SecretResponse)
	if err := c.Call(`AWS.Secret`, req, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// defaultTestClient is equivalent to testClient with zero values for service
// implementations.
func defaultTestClient(ctx context.Context, t *testing.T) (_ *rpcClient, cleanup func()) {
	return testClient(ctx, t, new(Crypto), new(AWS))
}

// testClient returns an rpcClient connected to a new socket, created by
// serve(). The provided service implementations are injected.
func testClient(ctx context.Context, t *testing.T, c *Crypto, a *AWS) (_ *rpcClient, cleanup func()) {
	ctx, cancel := context.WithCancel(ctx)

	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand.Read() for unique ID; error %v", err)
	}
	uniq := hex.EncodeToString(buf)
	t.Logf("Unique identifier for sockets and RPC services: %s", uniq)

	if err := registerWithPrefix(uniq, c, a); err != nil {
		t.Fatalf("registerWithPrefix(%q, [services]) error %v", uniq, err)
	}

	sock := fmt.Sprintf("/tmp/phpcloud-%s.sock", uniq)
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := serve(ctx, sock, ready); err != nil {
			t.Fatalf("listen() got err %v; want nil err", err)
		}
	}()
	<-ready

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf(`net.Dial("unix", %q) error %v`, sock, err)
	}

	cc := goridge.NewClientCodec(conn)
	cl := &rpcClient{
		Client: rpc.NewClientWithCodec(cc),
		prefix: uniq,
	}
	return cl, func() {
		cancel()
		<-done
	}
}
