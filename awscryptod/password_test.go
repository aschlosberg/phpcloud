package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/aschlosberg/myaspire/argon2"
	pb "github.com/aschlosberg/myaspire/awscryptod/proto"
	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/bcrypt"
)

func TestPassword(t *testing.T) {
	ctx := context.Background()
	cl, cleanup := client(ctx, t)
	defer cleanup()

	password := []byte("password")
	hashReq := &pb.HashPasswordRequest{Password: password}

	hash, err := cl.HashPassword(ctx, hashReq)
	if err != nil {
		t.Fatalf("HashPassword(%+v) error %v", hashReq, err)
	}
	if got := hash.Hash; !bytes.HasPrefix(got, []byte(`$argon2i$`)) {
		t.Fatalf("HashPassowrd(%+v) got %q; want generated with argon2i", hashReq, got)
	}

	tests := []struct {
		name     string
		password []byte
		want     *pb.CheckPasswordResponse
	}{
		{
			name:     "correct password",
			password: password,
			want: &pb.CheckPasswordResponse{
				Match: true,
			},
		},
		{
			name:     "nil password",
			password: nil,
			want: &pb.CheckPasswordResponse{
				Match: false,
			},
		},
		{
			name:     "different password",
			password: []byte("incorrect password"),
			want: &pb.CheckPasswordResponse{
				Match: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkReq := &pb.CheckPasswordRequest{
				Password: tt.password,
				Hash:     hash.Hash,
			}

			got, err := cl.CheckPassword(ctx, checkReq)
			if err != nil {
				t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
			}
			if !proto.Equal(got, tt.want) {
				t.Errorf("CheckPassword(%+v) got %+v; want %+v", checkReq, got, tt.want)
			}
		})
	}
}

func TestPasswordUpdate(t *testing.T) {
	password := []byte("password")
	incorrect := []byte("wrong password")

	bcryptHash, err := bcrypt.GenerateFromPassword(password, 3)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword(%q) error %v", password, err)
	}

	// argon2i is, according to x/crypto/argon2 docs, the preferred method for
	// password hashing. Therefore we update any argon2id hashes.
	conf := argon2.ID.Config()
	argon2idHash, err := conf.Hash(password)
	if err != nil {
		t.Fatalf("argon2.Config(%+v).Hash(%q) error %v", conf, password, err)
	}
	if !bytes.HasPrefix(argon2idHash, []byte(`$argon2id$`)) {
		t.Fatalf("bad test setup; got Argon2 hash %q; want with prefix %q to confirm that it is updated", argon2idHash, argon2id)
	}

	ctx := context.Background()
	cl, cleanup := client(ctx, t)
	defer cleanup()

	// bcrypt prefix has a variety of values to signal broken/fixed versions. We
	// need to support all of them. They follow the form $2v$ where v is the
	// version.
	tests := []struct {
		name string
		hash []byte
	}{
		{
			name: "2a",
			hash: append([]byte(`$2a$`), bcryptHash[4:]...),
		},
		{
			name: "2b",
			hash: append([]byte(`$2b$`), bcryptHash[4:]...),
		},
		{
			name: "2x",
			hash: append([]byte(`$2x$`), bcryptHash[4:]...),
		},
		{
			name: "2y",
			hash: append([]byte(`$2y$`), bcryptHash[4:]...),
		},
		{
			name: "argon2id",
			hash: argon2idHash,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkReq := &pb.CheckPasswordRequest{
				Password: password,
				Hash:     tt.hash,
			}

			got, err := cl.CheckPassword(ctx, checkReq)
			if err != nil {
				t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
			}
			if !got.Match || !got.Update || !bytes.HasPrefix(got.Updated, []byte(`$argon2i$`)) {
				t.Errorf("CheckPassword(%+v) got %+v; want match==true && update==true and updated hash with argon2i", checkReq, got)
			}

			t.Run("updated hash", func(t *testing.T) {
				checkReq := &pb.CheckPasswordRequest{
					Password: password,
					Hash:     got.Updated,
				}
				got, err = cl.CheckPassword(ctx, checkReq)
				if err != nil {
					t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
				}
				want := &pb.CheckPasswordResponse{Match: true}
				if !proto.Equal(got, want) {
					t.Errorf("CheckPassword(%+v) got %+v; want %+v", checkReq, got, want)
				}
			})

			t.Run("no update on mismatch", func(t *testing.T) {
				checkReq := &pb.CheckPasswordRequest{
					Password: incorrect,
					Hash:     tt.hash,
				}
				got, err = cl.CheckPassword(ctx, checkReq)
				if err != nil {
					t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
				}
				want := &pb.CheckPasswordResponse{Match: false, Update: false}
				if !proto.Equal(got, want) {
					t.Errorf("CheckPassword(%+v) got %+v; want %+v", checkReq, got, want)
				}
			})
		})
	}
}
