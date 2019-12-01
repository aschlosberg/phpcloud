package main

import (
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

func (c *Crypto) key(src string) ([]byte, error) {
	var key []byte
	var raw bool

	for _, prefix := range []string{string(RawKey), string(Passphrase)} {
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
	DataToEncrypt             string
	AuthenticatedNotEncrypted string
	KeySource                 string
}

// EncryptResponse is the response argument for Crypto.Encrypt*.
type EncryptResponse struct {
	EncryptedData string
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
		Sealed:            aead.Seal(nil, nonce, []byte(req.DataToEncrypt), []byte(req.AuthenticatedNotEncrypted)),
		AuthenticatedData: []byte(req.AuthenticatedNotEncrypted),
	})
	if err != nil {
		return fmt.Errorf("marshal ciphertext proto: %v", err)
	}
	resp.EncryptedData = base64.StdEncoding.EncodeToString(buf)
	return nil
}

func (c *Crypto) aesGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("insantiate AES cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("instantiate GCM AEAD: %v", err)
	}
	return aead, nil
}

// DecryptRequest is the request argument for Crypto.Decrypt.
type DecryptRequest struct {
	EncryptedData   string
	KeySources      []string
	RotateKeySource string
}

// DecryptResponse is the response argument for Crypto.Decrypt.
type DecryptResponse struct {
	DecryptedData     string
	AuthenticatedData string

	ReEncryptedData string
}

// Decrypt decrypts the request.
func (c *Crypto) Decrypt(req DecryptRequest, resp *DecryptResponse) error {
	if req.RotateKeySource != "" {
		req.KeySources = append(req.KeySources, req.RotateKeySource)
	}

	buf, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return fmt.Errorf("base64-decode encrypted data: %v", err)
	}
	ciphertext := new(pb.Ciphertext)
	if err := proto.Unmarshal(buf, ciphertext); err != nil {
		return fmt.Errorf("unmarshal ciphertext proto: %v", err)
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
		resp.DecryptedData = string(plaintext)
		resp.AuthenticatedData = string(additional)
		break
	}

	if usedSrc == "" {
		return ErrNotDecrypted
	}
	if usedSrc == req.RotateKeySource || req.RotateKeySource == "" {
		return nil
	}

	encReq := EncryptRequest{
		DataToEncrypt:             resp.DecryptedData,
		AuthenticatedNotEncrypted: resp.AuthenticatedData,
		KeySource:                 req.RotateKeySource,
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
	return nil, ErrUnimplemented
}
