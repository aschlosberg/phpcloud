package phpcloud

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func rawKeySrc(key []byte) string {
	return fmt.Sprintf(`%s%s`, RawKey, base64.StdEncoding.EncodeToString(key))
}

func TestEncryptionLoop(t *testing.T) {
	cl, cleanup := defaultTestClient(context.Background(), t)
	defer cleanup()

	reusableKey := mathRandBytes(256 / 8)

	tests := []struct {
		name           string
		key, rotateKey []byte
		// Attempt to decrypt with prependDecryptKeys before the original key.
		prependDecryptKeys [][]byte
		// If true, attempt to decrypt with only prependDecryptKeys, i.e.
		// they're not prepended as much as simply used. Allows for an API in
		// which it the rotation key doesn't have to be passed as a decrypt key
		// too, but won't fail.
		excludeEncryptKey            bool
		plaintext, authenticatedData string
		wantRotation                 bool
	}{
		{
			name:      "256-bit encryption only",
			key:       mathRandBytes(256 / 8),
			plaintext: "hello world",
		},
		{
			name:              "256-bit with authenticated data",
			key:               mathRandBytes(256 / 8),
			plaintext:         "big secret",
			authenticatedData: "not so secret",
		},
		{
			name:      "128-bit encryption only",
			key:       mathRandBytes(128 / 8),
			plaintext: "hello smaller world",
		},
		{
			name:              "128-bit with authenticated data",
			key:               mathRandBytes(128 / 8),
			plaintext:         "lesser secret",
			authenticatedData: "public knowledge",
		},
		{
			name:      "try other keys first",
			key:       mathRandBytes(256 / 8),
			plaintext: "need to know",
			prependDecryptKeys: [][]byte{
				mathRandBytes(128 / 8),
				mathRandBytes(256 / 8),
				// must fail gracefully on invalid keys
				mathRandBytes(512 / 8),
				{},
				[]byte("x"),
			},
		},
		{
			name:              "rotate key",
			key:               mathRandBytes(128 / 8),
			plaintext:         "old secrets",
			authenticatedData: "old but not secret",
			rotateKey:         mathRandBytes(256 / 8),
			wantRotation:      true,
		},
		{
			name:               "already-rotated key",
			key:                reusableKey,
			prependDecryptKeys: [][]byte{mathRandBytes(128 / 8)},
			plaintext:          "eyes only",
			rotateKey:          reusableKey,
			wantRotation:       false,
		},
		{
			// As a last-ditch attempt, the rotation key is used as a decryption
			// key.
			name:               "already-rotated key not included in decrypt",
			key:                reusableKey,
			prependDecryptKeys: [][]byte{mathRandBytes(256 / 8)},
			excludeEncryptKey:  true,
			rotateKey:          reusableKey,
			wantRotation:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := rawKeySrc(tt.key)

			encReq := EncryptRequest{
				DataToEncrypt:             tt.plaintext,
				AuthenticatedNotEncrypted: tt.authenticatedData,
				KeySource:                 src,
			}
			ciphertext, err := cl.EncryptAESGCM(encReq)
			if err != nil {
				t.Fatalf("Crypto.EncryptAESGCM(%+v) error %v", encReq, err)
			}

			var keySrcs []string
			for _, key := range tt.prependDecryptKeys {
				keySrcs = append(keySrcs, rawKeySrc(key))
			}
			if !tt.excludeEncryptKey {
				keySrcs = append(keySrcs, src)
			}

			decReq := DecryptRequest{
				EncryptedData:   ciphertext.EncryptedData,
				KeySources:      keySrcs,
				RotateKeySource: rawKeySrc(tt.rotateKey),
			}
			got, err := cl.Decrypt(decReq)
			if err != nil {
				t.Fatalf("Crypto.Decrypt(%+v) error %v", decReq, err)
			}

			rotatedCipherText := got.ReEncryptedData
			got.ReEncryptedData = ""
			want := &DecryptResponse{
				DecryptedData:     tt.plaintext,
				AuthenticatedData: tt.authenticatedData,
			}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Crypto.Decrypt(%+v) diff (-want +got):\n%s", decReq, diff)
			}

			t.Run("rotated-key ciphertext", func(t *testing.T) {
				if gotRot, wantRot := rotatedCipherText != "", tt.wantRotation; gotRot != wantRot {
					t.Errorf("Crypto.Decrypt(%+v) got ReEncryptedData %q; want key rotation? %t", decReq, rotatedCipherText, wantRot)
				}
				if rotatedCipherText == "" {
					return
				}

				decRotatedReq := DecryptRequest{
					EncryptedData: rotatedCipherText,
					KeySources:    []string{rawKeySrc(tt.rotateKey)},
				}
				got, err := cl.Decrypt(decRotatedReq)
				if err != nil {
					t.Fatalf("Crypto.Decrypt(%+v) error %v", decRotatedReq, err)
				}

				// Note that this is the exact same `want` as used for the
				// primary tests.
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Crypto.Decrypt(%+v) diff (-want +got):\n%s", decReq, diff)
				}
			})
		})
	}
}

func TestEncryptErrors(t *testing.T) {
	// Don't test via the client because we want to assert errors.
	cl := NewCrypto()

	tests := []struct {
		keySrc string
		want   error
	}{
		{
			keySrc: fmt.Sprintf("%snot-base64", RawKey),
			want:   ErrKeyBase64,
		},
		{
			// Although this will have to be removed when implemented, at least
			// confirm that the error isn't because of something else.
			keySrc: fmt.Sprintf("%s%s", Passphrase, base64.StdEncoding.EncodeToString([]byte("x"))),
			want:   ErrUnimplemented,
		},
		{
			keySrc: "unsupported-prefix:foo",
			want:   ErrKeyTypeUnsupported,
		},
	}

	for _, tt := range tests {
		req := EncryptRequest{
			KeySource:     tt.keySrc,
			DataToEncrypt: "secret",
		}

		err := cl.EncryptAESGCM(req, nil)
		if !errors.Is(err, tt.want) {
			t.Errorf("Crypto.EncryptAESGCM(%+v) got error %v; want errors.Is(_, %v)", req, err, tt.want)
		}
	}
}

func TestDecryptErrors(t *testing.T) {
	// Don't test via the client because we want to assert errors.
	cl := NewCrypto()

	encKey := rawKeySrc(mathRandBytes(256 / 8))
	ciphertext := new(EncryptResponse)
	req := EncryptRequest{
		DataToEncrypt: "secret",
		KeySource:     encKey,
	}
	if err := cl.EncryptAESGCM(req, ciphertext); err != nil {
		t.Fatalf("Crypto.EncryptAESGCM(%+v) error %v", req, err)
	}

	tests := []struct {
		req             DecryptRequest
		want            error
		wantErrContains string
	}{
		{
			req: DecryptRequest{
				EncryptedData: "foo",
			},
			wantErrContains: "base64-decode",
		},
		{
			req: DecryptRequest{
				EncryptedData: base64.StdEncoding.EncodeToString([]byte("not a marshalled proto")),
			},
			wantErrContains: "unmarshal",
		},
		{
			req: DecryptRequest{
				EncryptedData: ciphertext.EncryptedData,
				KeySources:    []string{"invalid"},
			},
			want: ErrKeyTypeUnsupported,
		},
		{
			req: DecryptRequest{
				EncryptedData: ciphertext.EncryptedData,
				KeySources:    []string{rawKeySrc(mathRandBytes(128 / 8))},
			},
			want: ErrNotDecrypted,
		},
		{
			req: DecryptRequest{
				EncryptedData:   ciphertext.EncryptedData,
				KeySources:      []string{encKey},
				RotateKeySource: "invalid",
			},
			want: ErrKeyTypeUnsupported,
		},
	}

	for i, tt := range tests {
		if tt.want == nil && tt.wantErrContains == "" {
			t.Errorf("bad test[%d] setup; needs either non-nil error or non-empty substring", i)
		}

		// Unlike encryption errors, we need a response to populate for when
		// decryption is successful but key rotation is not.
		err := cl.Decrypt(tt.req, new(DecryptResponse))
		if err == nil {
			t.Errorf("Crypto.Decrypt(%+v) got nil error; want non-nil", tt.req)
			continue
		}
		if !strings.Contains(err.Error(), tt.wantErrContains) {
			t.Errorf("Crypto.Decrypt(%+v) got error %v; want with substring %q", tt.req, err, tt.wantErrContains)
		}
		if tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("Crypto.Decrypt(%+v) got error %v; want errors.Is(_, %v)", tt.req, err, tt.want)
		}
	}
}
