package phpcloud

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	pb "github.com/aschlosberg/phpcloud/phpcloud/proto"
	"github.com/google/go-cmp/cmp"
)

func rawKeySrc(key []byte) string {
	return fmt.Sprintf(`%s%s`, RawKey, base64.StdEncoding.EncodeToString(key))
}

func cmpHexOpt() cmp.Option {
	return cmp.Transformer(`bytehex`, hex.EncodeToString)
}

// testRotationAndClearReEncrypted tests that gotPrimary.ReEncryptedData is
// non-nil i.f.f. wantRotation==true. If re-encryption occurred then the new
// ciphertext is tested to ensure that it decrypts to wantIfRotated.
func testRotation(t *testing.T, gotPrimary *DecryptResponse, wantRotation bool, wantIfRotated *DecryptResponse, keySrcs []string) {
	t.Helper()

	t.Run("key or algorithm rotation", func(t *testing.T) {
		t.Helper()

		gotRotation := len(gotPrimary.ReEncryptedData) > 0
		if gotRotation != wantRotation {
			t.Fatalf("Decrypt() got re-encrypted data %t; want %t", gotRotation, wantRotation)
		}
		if !gotRotation {
			return
		}

		cr := NewCrypto()
		req := DecryptRequest{
			EncryptedData: gotPrimary.ReEncryptedData,
			KeySources:    keySrcs,
			AllowedModes: map[pb.Ciphertext_Mode]bool{
				pb.Ciphertext_AESGCM: true,
			},
		}
		got := new(DecryptResponse)
		if err := cr.Decrypt(req, got); err != nil {
			t.Fatalf("Decrypt(re-encrypted data) error %v", err)
		}

		if diff := cmp.Diff(wantIfRotated, got, cmpHexOpt()); diff != "" {
			t.Errorf("Decrypt(re-encrypted data) diff (-want +got):\n%s", diff)
		}
	})
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
				DataToEncrypt:             []byte(tt.plaintext),
				AuthenticatedNotEncrypted: []byte(tt.authenticatedData),
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

			want := &DecryptResponse{
				DecryptedData:     []byte(tt.plaintext),
				AuthenticatedData: []byte(tt.authenticatedData),
			}
			testRotation(t, got, tt.wantRotation, want, []string{rawKeySrc(tt.rotateKey)})
			got.ReEncryptedData = nil

			if diff := cmp.Diff(want, got, cmpHexOpt()); diff != "" {
				t.Errorf("Crypto.Decrypt(%+v) diff (-want +got):\n%s", decReq, diff)
			}
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
			DataToEncrypt: []byte("secret"),
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
		DataToEncrypt: []byte("secret"),
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
		// The first two tests target the padding schema used to differentiate
		// Crypto.EncryptAESGCM() output from raw AES-ECB data, which will
		// always have length 16n (AES block size is 128 bits). TL;DR the output
		// length will never be a multiple of 16, and the final byte indicates
		// how many to strip.
		{
			req: DecryptRequest{
				// Attempts to strip 99 bytes of padding.
				EncryptedData: append([]byte("invalid padding"), 0, 99),
			},
			want: ErrDetectCiphertextMode,
		},
		{
			req: DecryptRequest{
				// Strips the single byte of padding, resulting in an invalid
				// proto.
				EncryptedData: append([]byte("invalid proto"), 1),
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
		{
			req: DecryptRequest{
				EncryptedData: ciphertext.EncryptedData,
				KeySources:    []string{encKey},
				AllowedModes: map[pb.Ciphertext_Mode]bool{
					// Generally we use this to only allow GCM (see field
					// comment) but this suffices to test the mechanism.
					pb.Ciphertext_AESECB: true,
				},
			},
			want: ErrAllowedDecryptMode,
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

func encryptECB(b cipher.Block, plaintext []byte) []byte {
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	if pad == aes.BlockSize {
		pad = 0
	}
	buf := append([]byte(plaintext), make([]byte, pad)...)

	var ciphertext []byte
	for i := 0; i+aes.BlockSize <= len(buf); i += aes.BlockSize {
		dst := make([]byte, aes.BlockSize)
		b.Encrypt(dst, buf[i:i+aes.BlockSize])
		ciphertext = append(ciphertext, dst...)
	}
	return ciphertext
}

func TestNISTECTVectors(t *testing.T) {
	// The encryption is never going to be used outside the tests, but it needs
	// to function properly to create input for Crypto.decryptAESECB.
	// Source: https://csrc.nist.gov/publications/detail/sp/800-38a/final

	const (
		k128 = `2b7e151628aed2a6abf7158809cf4f3c`
		k192 = `8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b`
		k256 = `603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4`
	)

	// plaintext -> key -> ciphertext
	vectors := map[string]map[string]string{
		`6bc1bee22e409f96e93d7e117393172a`: map[string]string{
			k128: `3ad77bb40d7a3660a89ecaf32466ef97`,
			k192: `bd334f1d6e45f25ff712a214571fa5cc`,
			k256: `f3eed1bdb5d2a03c064b5a7e3db181f8`,
		},
		`ae2d8a571e03ac9c9eb76fac45af8e51`: map[string]string{
			k128: `f5d3d58503b9699de785895a96fdbaaf`,
			k192: `974104846d0ad3ad7734ecb3ecee4eef`,
			k256: `591ccb10d410ed26dc5ba74a31362870`,
		},
		`30c81c46a35ce411e5fbc1191a0a52ef`: map[string]string{
			k128: `43b1cd7f598ece23881b00e3ed030688`,
			k192: `ef7afd2270e2e60adce0ba2face6444e`,
			k256: `b6ed21b99ca6f4f9f153e7b1beafed1d`,
		},
		`f69f2445df4f9b17ad2b417be66c3710`: map[string]string{
			k128: `7b0c785e27e8ad3f8223207104725dd4`,
			k192: `9a4b41ba738d6c72fb16691603c18e0e`,
			k256: `23304b7a39f9f3ff067d8d8f9e24ecc7`,
		},
	}

	decode := func(s string) []byte {
		buf, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("bad test setup; hex.DecodeString(%q) error %v", s, err)
		}
		return buf
	}

	cr := NewCrypto()

	for pt, keyCT := range vectors {
		ptBuf := decode(pt)
		for key, ct := range keyCT {
			keyBuf := decode(key)
			ctBuf := decode(ct)

			block, err := aes.NewCipher(keyBuf)
			if err != nil {
				t.Fatalf("bad test setup; aes.NewCipher(%s) error %v", key, err)
			}

			if got, want := encryptECB(block, ptBuf), ctBuf; !reflect.DeepEqual(got, want) {
				t.Errorf("encryptECB(key[%s], %s) got %x; want %x", key, pt, got, want)
			}

			req := DecryptRequest{
				EncryptedData: ctBuf,
				KeySources:    []string{rawKeySrc(keyBuf)},
			}
			got := new(DecryptResponse)
			if err := cr.Decrypt(req, got); err != nil {
				t.Errorf("Crypto.Decrypt(key[%s], %s) error %v", key, ct, req, err)
				continue
			}

			want := &DecryptResponse{
				DecryptedData: ptBuf,
			}

			// ECB must always be rotated to a better algorithm.
			testRotation(t, got, true, want, []string{rawKeySrc(keyBuf)})
			got.ReEncryptedData = nil

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Crypto.Decrypt(key[%s], %s) diff (-want +got): %s", key, ct, diff)
			}
		}
	}
}

func TestDecryptECB(t *testing.T) {
	key := mathRandBytes(256 / 8)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher(%x) error %v", key, err)
	}

	plaintext := []string{
		"world",
		"hello",
		"",
		"x",
		"0123456789abcdef", // exact block size
		"0123456789abcdefhello",
	}

	pairs := make(map[string][]byte)
	for _, p := range plaintext {
		// Input has to be a full block.
		pairs[p] = encryptECB(block, []byte(p))
	}

	t.Run("ECB sanity checks", func(t *testing.T) {
		getBlock := func(pt string, i int) []byte {
			ct, ok := pairs[pt]
			if !ok {
				t.Errorf("bad test setup: getBlock(%q, %d) for non-existent pair", pt, i)
			}

			start := i * aes.BlockSize
			end := (i + 1) * aes.BlockSize

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("bad test setup: getBlock(%q, %d) indexed ciphertext(%v)[%d:%d] into %v panic: %v", pt, i, ct, start, end, r)
				}
			}()
			return ct[start:end]
		}

		tests := []struct {
			p0, p1           string
			p0Block, p1Block int
		}{
			{
				p0:      "0123456789abcdef",
				p0Block: 0,
				p1:      "0123456789abcdefhello",
				p1Block: 0,
			},
			{
				p0:      "hello",
				p0Block: 0,
				p1:      "0123456789abcdefhello",
				p1Block: 1,
			},
		}

		for _, tt := range tests {
			t.Run(fmt.Sprintf("%q %d %q %d", tt.p0, tt.p0Block, tt.p1, tt.p1Block), func(t *testing.T) {
				b0 := getBlock(tt.p0, tt.p0Block)
				b1 := getBlock(tt.p1, tt.p1Block)
				if !cmp.Equal(b0, b1) {
					t.Errorf("ECB ciphertext-block mismatch %q block %d != %q block %d", tt.p0, tt.p0Block, tt.p1, tt.p1Block)
				}
			})
		}
	})

	for pt, ct := range pairs {
		t.Run(pt, func(t *testing.T) {
			cl, cleanup := defaultTestClient(context.Background(), t)
			defer cleanup()

			req := DecryptRequest{
				EncryptedData: ct,
				KeySources:    []string{rawKeySrc(key)},
			}

			got, err := cl.Decrypt(req)
			if err != nil {
				t.Fatalf("Crypto.Decrypt(%+v) error %v", req, err)
			}

			want := &DecryptResponse{
				DecryptedData: []byte(pt),
			}

			// ECB must always be rotated to a better algorithm.
			testRotation(t, got, true, want, []string{rawKeySrc(key)})
			got.ReEncryptedData = nil

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Crypto.Decrypt(%+v) diff (-want +got):\n%s", req, diff)
			}
		})
	}
}

func TestFuzzDecrypt(t *testing.T) {
	// We have to account for multiple ciphertext types with no real indication
	// of what they are. This led to ECB ciphertext being a valid pb.Ciphertext
	// proto when "unmarshalled".
	rand.Seed(42)

	var keys [][]byte
	for _, n := range []int{256 / 8, 192 / 8, 128 / 8} {
		for i := 0; i < 10; i++ {
			keys = append(keys, mathRandBytes(n))
		}
	}

	var keySrcs []string
	for _, k := range keys {
		keySrcs = append(keySrcs, rawKeySrc(k))
	}

	plaintexts := [][]byte{nil, []byte{}}
	for i := 0; i < 2000; i++ {
		n := rand.Intn(1<<12) + 1
		plaintexts = append(plaintexts, mathRandBytes(n))
	}

	authenticated := [][]byte{nil, []byte{}}
	for i := 0; i < len(plaintexts)-2; i++ {
		n := rand.Intn(1<<12) + 1
		authenticated = append(authenticated, mathRandBytes(n))
	}

	cl := NewCrypto()

	// Many of the tests use t.Fatalf instead of t.Errorf so that they don't
	// flood the screen if there is a bug common to all few thousand of them. It
	// means we have to play whack-a-mole with bugs, but this is a rare case in
	// which that's simply easier.

	t.Run("ECB", func(t *testing.T) {
		t.Skip("ECB decryption does not yet have a padding schema.")

		var n int
		defer func() {
			t.Logf("%d tests", n)
		}()

		for iK, k := range keys {
			block, err := aes.NewCipher(k)
			if err != nil {
				t.Errorf("aes.NewCipher(%x) error %v", k, err)
				continue
			}

			for iPT, pt := range plaintexts {
				n++

				req := DecryptRequest{
					EncryptedData: encryptECB(block, pt),
					KeySources:    keySrcs,
				}
				got := new(DecryptResponse)
				if err := cl.Decrypt(req, got); err != nil {
					t.Fatalf("Crypto.Decrypt() error %v", err)
					continue
				}

				want := &DecryptResponse{
					DecryptedData: pt,
				}
				if diff := cmp.Diff(want, got, cmpHexOpt()); diff != "" {
					t.Fatalf("Key[%d] Plaintext[%d] Crypto.Decrypt() mismatch; got length %d; want %d", iK, iPT, len(got.DecryptedData), len(want.DecryptedData))
				}
			}
		}
	})

	t.Run("GCM", func(t *testing.T) {
		var n int
		defer func() {
			t.Logf("%d tests", n)
		}()

		// We need to be able to detect the different between raw AES-ECB and
		// the output of Crypto.EncryptAESGCM(). See the function for the
		// padding schema, but TL;DR is that output length can be anything
		// except for a multiple of the AES block size. This checks that we have
		// sufficient fuzzing coverage for this.
		paddingLenMod := make([]bool, aes.BlockSize)
		defer func() {
			for i, got := range paddingLenMod {
				if i == 0 {
					// Tested at the point of occurrence so we know the input
					// data, to report it in the error message.
					continue
				}
				if !got {
					t.Errorf("Insufficient test coverage; no output of length%aes.BlockSize == %d", i)
				}
			}
		}()

		for iK, k := range keys {
			for iPT, pt := range plaintexts {
				n++

				encReq := EncryptRequest{
					DataToEncrypt:             pt,
					AuthenticatedNotEncrypted: authenticated[iPT],
					KeySource:                 rawKeySrc(k),
				}
				encResp := new(EncryptResponse)
				if err := cl.EncryptAESGCM(encReq, encResp); err != nil {
					t.Errorf("Crypto.Encrypt(%+v) error %v", encReq, err)
					continue
				}

				mod := len(encResp.EncryptedData) % aes.BlockSize
				paddingLenMod[mod] = true
				if mod == 0 {
					t.Fatalf("Crypto.Encrypt(%+v) output length %d is a multiple of aes.BlockSize; can be confused with AES-ECB", encReq, n)
				}

				decReq := DecryptRequest{
					EncryptedData: encResp.EncryptedData,
					KeySources:    keySrcs,
				}
				got := new(DecryptResponse)
				if err := cl.Decrypt(decReq, got); err != nil {
					t.Fatalf("Crypto.Decrypt() error %v", err)
				}

				want := &DecryptResponse{
					DecryptedData:     pt,
					AuthenticatedData: authenticated[iPT],
				}
				if diff := cmp.Diff(want, got, cmpHexOpt()); diff != "" {
					t.Fatalf("Key[%d] Plaintext[%d] Crypto.Decrypt() mismatch", iK, iPT)
				}
			}
		}
	})
}
