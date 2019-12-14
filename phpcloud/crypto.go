package phpcloud

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	pb "github.com/aschlosberg/phpcloud/phpcloud/proto"
	"github.com/golang/protobuf/proto"
)

// Crypto implements a net/rpc service providing cryptographic methods.
type Crypto struct{}

// NewCrypto returns a new Crypto service.
func NewCrypto() *Crypto {
	return new(Crypto)
}

// A KeySourceType is a type of source for cryptographic keys.
type KeySourceType string

// KeySourceTypes of the form "[type]:[base64-key-material]" indicate how the
// key material should be interpreted.
const (
	RawKey     KeySourceType = `raw:`
	Passphrase KeySourceType = `passphrase:`
)

// string returns t as a string. It allows for centralised modification of type
// conversion.
func (t KeySourceType) string() string {
	return string(t)
}

func (c *Crypto) key(src string) ([]byte, error) {
	var key []byte
	var raw bool

	for _, prefix := range []string{RawKey.string(), Passphrase.string()} {
		if !strings.HasPrefix(src, prefix) {
			continue
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(src, prefix))
		if err != nil {
			// Don't annotate err because we risk leaking key material.
			return nil, ErrKeyBase64
		}
		key = b
		raw = prefix == string(RawKey)
	}
	if key == nil {
		return nil, ErrKeyTypeUnsupported
	}

	if !raw {
		return nil, ErrUnimplemented
	}

	return key, nil
}

// EncryptRequest is the request argument for Crypto.Encrypt*.
type EncryptRequest struct {
	DataToEncrypt             []byte
	AuthenticatedNotEncrypted []byte
	KeySource                 string
}

// EncryptResponse is the response argument for Crypto.Encrypt*.
type EncryptResponse struct {
	EncryptedData []byte
}

// EncryptAESGCM encrypts the request with AES-GCM.
func (c *Crypto) EncryptAESGCM(req EncryptRequest, resp *EncryptResponse) error {
	key, err := c.key(req.KeySource)
	if err != nil {
		return err
	}

	aead, err := c.aesGCM(key)
	if err != nil {
		return nil
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %v", err)
	}

	buf, err := proto.Marshal(&pb.Ciphertext{
		Mode:              pb.Ciphertext_AESGCM,
		Nonce:             nonce,
		Sealed:            aead.Seal(nil, nonce, req.DataToEncrypt, req.AuthenticatedNotEncrypted),
		AuthenticatedData: req.AuthenticatedNotEncrypted,
	})
	if err != nil {
		return fmt.Errorf("marshal ciphertext proto: %v", err)
	}

	// Decryption needs to handle data from this function, as well as AESECB
	// from MariaDB's AES_ENCRYPT(). However, the latter will be raw binary that
	// could properly unmarshal as a ciphertext proto with AESGCM as the Mode
	// (it happened during testing)! To avoid this, ensure that our ciphertext
	// never has a length that is a multiple of the AES block size (16 bytes).

	// The final byte of padding indicates the size of the padding.
	if len(buf)%aes.BlockSize == aes.BlockSize-1 {
		buf = append(buf, 0, 2) // len == 16n+1
	} else {
		buf = append(buf, 1) // len%16 != 0
	}

	resp.EncryptedData = buf
	return nil
}

func (c *Crypto) aes(key []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("insantiate AES cipher: %v", err)
	}
	return block, nil
}

func (c *Crypto) aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := c.aes(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("instantiate GCM AEAD: %v", err)
	}
	return aead, nil
}

// DecryptRequest is the request argument for Crypto.Decrypt.
type DecryptRequest struct {
	EncryptedData   []byte
	KeySources      []string
	RotateKeySource string

	// AllowedModes specifies the Modes that are allowed, and can be used to
	// disable ECB fallback, which allows for circumventing GCM authentication
	// checks.
	AllowedModes map[pb.Ciphertext_Mode]bool
}

// DecryptResponse is the response argument for Crypto.Decrypt.
type DecryptResponse struct {
	DecryptedData     []byte
	AuthenticatedData []byte

	ReEncryptedData []byte
}

// Decrypt decrypts the request.
func (c *Crypto) Decrypt(req DecryptRequest, resp *DecryptResponse) error {
	if req.RotateKeySource != "" {
		req.KeySources = append(req.KeySources, req.RotateKeySource)
	}

	// See the end of c.Encrypt() for an explanation of why and how it pads
	// the ciphertext. TL;DR it will never be a multiple of aes.Blocksize, and
	// the final byte indicates the length of padding to strip.
	ciphertext := new(pb.Ciphertext)
	if len(req.EncryptedData)%aes.BlockSize == 0 {
		ciphertext = &pb.Ciphertext{
			Mode:   pb.Ciphertext_AESECB,
			Sealed: req.EncryptedData,
		}
	} else {
		n := len(req.EncryptedData)
		pad := int(req.EncryptedData[n-1])
		if pad > n {
			return ErrDetectCiphertextMode
		}

		buf := req.EncryptedData[:n-pad]
		if err := proto.Unmarshal(buf, ciphertext); err != nil {
			return fmt.Errorf("unmarshal ciphertext proto: %v", err)
		}
	}

	if req.AllowedModes != nil && !req.AllowedModes[ciphertext.Mode] {
		return ErrAllowedDecryptMode
	}

	var usedSrc string
	for _, src := range req.KeySources {
		key, err := c.key(src)
		if err != nil {
			// We could simply continue here and try the next key, but an error
			// in parsing a key source implies that the user has a bug so should
			// be notified.
			return err
		}

		plaintext, additional, err := c.decrypt(key, ciphertext)
		if err != nil {
			continue
		}
		usedSrc = src
		resp.DecryptedData = plaintext
		resp.AuthenticatedData = additional
		break
	}

	if usedSrc == "" {
		return ErrNotDecrypted
	}

	keyOK := req.RotateKeySource == "" || usedSrc == req.RotateKeySource
	algoOK := ciphertext.Mode == pb.Ciphertext_AESGCM
	if keyOK && algoOK {
		return nil
	}

	// We need to reencrypt because the key needs rotation, and/or the algorithm
	// needs upgrading. However, of the three possible permutations, only one
	// allows for key reuse.
	var reEncKey string
	if keyOK {
		reEncKey = usedSrc
	} else {
		reEncKey = req.RotateKeySource
	}

	encReq := EncryptRequest{
		DataToEncrypt:             resp.DecryptedData,
		AuthenticatedNotEncrypted: resp.AuthenticatedData,
		KeySource:                 reEncKey,
	}
	encResp := new(EncryptResponse)
	if err := c.EncryptAESGCM(encReq, encResp); err != nil {
		// Unlike most other places where %v is explicitly used, it's OK to
		// expose this error with %w because it's already part of our API.
		return fmt.Errorf("re-encrypt data to rotate key: %w", err)
	}
	resp.ReEncryptedData = encResp.EncryptedData

	return nil
}

func (c *Crypto) decrypt(key []byte, ct *pb.Ciphertext) ([]byte, []byte, error) {
	switch ct.Mode {
	case pb.Ciphertext_AESGCM:
		return c.decryptAESGCM(key, ct)
	case pb.Ciphertext_AESECB:
		pt, err := c.decryptAESECB(key, ct)
		return pt, nil, err
	default:
		return nil, nil, ErrBlockModeUnsupported
	}
}

func (c *Crypto) decryptAESGCM(key []byte, ct *pb.Ciphertext) ([]byte, []byte, error) {
	aead, err := c.aesGCM(key)
	if err != nil {
		return nil, nil, err
	}
	pt, err := aead.Open(nil, ct.Nonce, ct.Sealed, ct.AuthenticatedData)
	if err != nil {
		return nil, nil, fmt.Errorf("open AEAD seal: %v", err)
	}
	return pt, ct.AuthenticatedData, nil
}

func (c *Crypto) decryptAESECB(key []byte, ct *pb.Ciphertext) ([]byte, error) {
	block, err := c.aes(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 0, len(ct.Sealed))

	dst := make([]byte, aes.BlockSize)
	for i, max := 0, len(ct.Sealed)-aes.BlockSize; i <= max; i += aes.BlockSize {
		block.Decrypt(dst, ct.Sealed[i:i+aes.BlockSize])
		plaintext = append(plaintext, dst...)
	}
	// TODO replace the TrimRight with the correct padding schema for MariaDB's
	// AES_ENCRYPT. Also enable (remove t.Skip) from the fuzz test. Also update
	// tests to reflect the schema.
	return bytes.TrimRight(plaintext, "\x00"), nil
}
