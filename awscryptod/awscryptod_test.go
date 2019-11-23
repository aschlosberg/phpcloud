package main

import (
	"context"
	"fmt"
	"math/rand"
	"testing"

	pb "github.com/aschlosberg/myaspire/awscryptod/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func client(ctx context.Context, t *testing.T) (pb.AWSCryptoServiceClient, func()) {
	ctx, cancel := context.WithCancel(ctx)

	sock := fmt.Sprintf("/tmp/awscryptod-%d.sock", rand.Int())
	done := make(chan struct{})
	go func() {
		if err := listen(ctx, sock); err != nil {
			t.Errorf("listen() got err %v; want nil err", err)
		}
		close(done)
	}()

	conn, err := grpc.DialContext(ctx, "unix:"+sock, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("grpc.DialContext(): %v", err)
	}
	for {
		conn.WaitForStateChange(ctx, connectivity.Idle)
		if conn.GetState() == connectivity.Ready {
			break
		}
	}

	return pb.NewAWSCryptoServiceClient(conn), func() {
		cancel()
		<-done
		if err := conn.Close(); err != nil {
			t.Errorf("grpc.ClientConn.Close() error %v", err)
		}
	}
}
