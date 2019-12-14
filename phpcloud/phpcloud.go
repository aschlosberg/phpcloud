// Package phpcloud provides net/rpc services to offload functionality from PHP
// to Go via the spiral/goridge codec. It has an accompanying PHP client library
// and Docker image.
package phpcloud

import (
	"context"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"reflect"

	log "github.com/golang/glog"
	"github.com/spiral/goridge"
)

// Register registers instances of RPC services.
func Register(c *Crypto, a *AWS) error {
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

// ServeSocketPermission is the POSIX permission to which Serve sets its socket.
const ServeSocketPermission = 0770

// Serve listens on sock, closing ready (if non-nil) once listening, and then
// accepts net/rpc connections with the goridge Codec. It sets ownership of sock
// to the current uid:gid and permissions to ServeSocketPermission. Serve is
// blocking, and respects context cancellation.
func Serve(ctx context.Context, sock string, ready chan struct{}) error {
	lis, err := net.Listen("unix", sock)
	if err != nil {
		return fmt.Errorf("listen on socket: %v", err)
	}
	if err := os.Chmod(sock, ServeSocketPermission); err != nil {
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

// Error implements the error interface.
type Error int

// Pre-defined errors.
const (
	ErrUnknown Error = iota
	ErrUnimplemented
	ErrKeyTypeUnsupported
	ErrKeyBase64
	ErrNotDecrypted
	ErrBlockModeUnsupported
	ErrDetectCiphertextMode
	ErrAllowedDecryptMode
)

func (e Error) Error() string {
	switch e {
	case ErrUnimplemented:
		return "unimplemented"
	case ErrKeyTypeUnsupported:
		return "crypto key-source type not supported"
	case ErrKeyBase64:
		return "invalid base64-encoded data"
	case ErrNotDecrypted:
		return "unable to decrypt"
	case ErrBlockModeUnsupported:
		return "crypto block mode not supported"
	case ErrDetectCiphertextMode:
		return "detect ciphertext mode"
	case ErrAllowedDecryptMode:
		return "disallowed ciphertext mode when decrypting"
	}
	return "unknown error"
}
