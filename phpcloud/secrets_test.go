package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"github.com/google/go-cmp/cmp"
)

type secretIDOut map[string]*secretsmanager.GetSecretValueOutput
type secretIDErr map[string]error

type secretStub struct {
	secretsmanageriface.SecretsManagerAPI

	calls int
	out   secretIDOut
	errs  secretIDErr
}

func newSecretStub(out secretIDOut, errs secretIDErr) *secretStub {
	if out == nil {
		out = make(secretIDOut)
	}
	if errs == nil {
		errs = make(secretIDErr)
	}
	return &secretStub{
		out:  out,
		errs: errs,
	}
}

func (s *secretStub) GetSecretValue(in *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	s.calls++
	if in.SecretId == nil {
		return nil, errors.New("nil SecretId")
	}
	id := *in.SecretId

	o := s.out[id]
	err, ok := s.errs[*in.SecretId]
	if o == nil && !ok {
		err = errors.New("not found")
	}

	if err != nil {
		err = fmt.Errorf("secret %q: %v", id, err)
	}
	return o, err
}

func TestSecret(t *testing.T) {
	ctx := context.Background()

	stub := newSecretStub(
		secretIDOut{
			"protected": {
				SecretString: aws.String("protected string"),
				SecretBinary: []byte("protected binary"),
				VersionId:    aws.String("v0"),
			},
			"secret": {
				SecretString: aws.String("secret string"),
				VersionId:    aws.String("v1"),
			},
			"top-secret": {
				SecretBinary: []byte("top-secret binary"),
				VersionId:    aws.String("v2"),
			},
		},
		nil,
	)

	tests := []struct {
		id   string
		want *SecretResponse
	}{
		{
			id: "protected",
			want: &SecretResponse{
				String:    "protected string",
				Binary:    []byte("protected binary"),
				VersionID: "v0",
			},
		},
		{
			id: "secret",
			want: &SecretResponse{
				String:    "secret string",
				VersionID: "v1",
			},
		},
		{
			id: "top-secret",
			want: &SecretResponse{
				Binary:    []byte("top-secret binary"),
				VersionID: "v2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			cl, cleanup := testClient(ctx, t, nil, NewAWS(stub))
			defer cleanup()

			for i := 0; i < 10; i++ {
				t.Run("", func(t *testing.T) {
					req := SecretRequest{ID: tt.id}
					got, err := cl.Secret(req)
					if err != nil {
						t.Fatalf("AWS.Secret(%+v) got error %v; want nil err", req, err)
					}

					if diff := cmp.Diff(tt.want, got); diff != "" {
						t.Errorf("AWS.Secret(%+v) (-want +got):\n%s", req, diff)
					}
				})
			}
		})
	}

	if got, want := stub.calls, len(tests); got != want {
		t.Errorf("local cache may not be functioning correctly; AWS.Secret() called secretsmanger.GetSecretValue() %d times; want %d", got, want)
	}
}

func TestSecretErrors(t *testing.T) {
	ctx := context.Background()

	stub := newSecretStub(
		nil,
		secretIDErr{
			"way-too-secret": errors.New("permission denied"),
		},
	)

	tests := []struct {
		id              string
		wantErrContains string
	}{
		{
			id:              "way-too-secret",
			wantErrContains: "permission denied",
		},
		{
			id:              "non-existent",
			wantErrContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			cl, cleanup := testClient(ctx, t, nil, NewAWS(stub))
			defer cleanup()

			req := SecretRequest{ID: tt.id}
			_, err := cl.Secret(req)
			if err == nil || !strings.Contains(err.Error(), tt.wantErrContains) {
				t.Errorf("AWS.Secret(%+v) got err %v; want non-nil, containing %q", req, err, tt.wantErrContains)
				time.Sleep(time.Second)
			}
		})
	}
}
