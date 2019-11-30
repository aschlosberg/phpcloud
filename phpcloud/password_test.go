package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/aschlosberg/phpcloud/argon2"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/bcrypt"
)

func TestPassword(t *testing.T) {
	ctx := context.Background()
	cl, cleanup := client(ctx, t)
	defer cleanup()

	const password = "password"
	hashReq := HashPasswordRequest{Password: password}

	hash, err := cl.HashPassword(hashReq)
	if err != nil {
		t.Fatalf("HashPassword(%+v) error %v", hashReq, err)
	}
	if got := hash.Hash; !strings.HasPrefix(got, `$argon2i$`) {
		t.Fatalf("HashPassowrd(%+v) got %q; want generated with argon2i", hashReq, got)
	}

	tests := []struct {
		name     string
		password string
		want     *CheckPasswordResponse
	}{
		{
			name:     "correct password",
			password: password,
			want: &CheckPasswordResponse{
				Match: true,
			},
		},
		{
			name:     "empty password",
			password: "",
			want: &CheckPasswordResponse{
				Match: false,
			},
		},
		{
			name:     "different password",
			password: "incorrect password",
			want: &CheckPasswordResponse{
				Match: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkReq := CheckPasswordRequest{
				Password: tt.password,
				Hash:     hash.Hash,
			}

			got, err := cl.CheckPassword(checkReq)
			if err != nil {
				t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("CheckPassword(%+v) (-want +got):\n%s", checkReq, diff)
			}
		})
	}
}

func TestPasswordUpdate(t *testing.T) {
	const (
		password  = "password"
		incorrect = "wrong password"
	)

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(password), 3)
	if err != nil {
		t.Fatalf("bcrypt.GenerateFromPassword(%q) error %v", password, err)
	}

	// argon2i is, according to x/crypto/argon2 docs, the preferred method for
	// password hashing. Therefore we update any argon2id hashes.
	conf := argon2.ID.Config()
	argon2idHash, err := conf.Hash([]byte(password))
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
			checkReq := CheckPasswordRequest{
				Password: password,
				Hash:     string(tt.hash),
			}

			got, err := cl.CheckPassword(checkReq)
			if err != nil {
				t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
			}
			if !got.Match || !got.Update || !strings.HasPrefix(got.UpdatedHash, `$argon2i$`) {
				t.Errorf("CheckPassword(%+v) got %+v; want match==true && update==true and updated hash with argon2i", checkReq, got)
			}

			t.Run("updated hash", func(t *testing.T) {
				checkReq := CheckPasswordRequest{
					Password: password,
					Hash:     got.UpdatedHash,
				}
				got, err = cl.CheckPassword(checkReq)
				if err != nil {
					t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
				}
				want := &CheckPasswordResponse{Match: true}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("CheckPassword(%+v) (-want +got):\n%s", checkReq, diff)
				}
			})

			t.Run("no update on mismatch", func(t *testing.T) {
				checkReq := CheckPasswordRequest{
					Password: incorrect,
					Hash:     string(tt.hash),
				}
				got, err = cl.CheckPassword(checkReq)
				if err != nil {
					t.Fatalf("CheckPassword(%+v) error %v", checkReq, err)
				}
				want := &CheckPasswordResponse{Match: false, Update: false}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("CheckPassword(%+v) (-want +got):\n%s", checkReq, diff)
				}
			})
		})
	}
}
