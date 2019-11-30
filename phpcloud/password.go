package main

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/aschlosberg/myaspire/argon2"
	log "github.com/golang/glog"
	"golang.org/x/crypto/bcrypt"
)

// HashPasswordRequest is the request argument for Crypto.HashPassword.
type HashPasswordRequest struct {
	Password []byte
}

// HashPasswordResponse is the response argument for Crypto.HashPassword.
type HashPasswordResponse struct {
	Hash []byte
}

// HashPassword returns req.Password, hashed with Argon2i.
func (c *Crypto) HashPassword(req HashPasswordRequest, resp *HashPasswordResponse) error {
	hash, err := argon2.Hash(req.Password)
	if err != nil {
		return fmt.Errorf("hashing password: %v", err)
	}
	resp.Hash = hash
	return nil
}

var (
	bcryptA  = []byte(`$2a$`)
	bcryptB  = []byte(`$2b$`)
	bcryptX  = []byte(`$2x$`)
	bcryptY  = []byte(`$2y$`)
	argon2id = []byte(`$argon2id$`)
	argon2i  = []byte(`$argon2i$`)
)

// CheckPasswordRequest is the request argument for Crypto.CheckPassword.
type CheckPasswordRequest struct {
	Password, Hash []byte
}

// CheckPasswordResponse is the response argument for Crypto.CheckPassword.
type CheckPasswordResponse struct {
	Match bool

	// If `Update==true`, the stored hash should be changed to `UpdatedHash` for
	// improved security.
	Update      bool
	UpdatedHash []byte

	DebugReason string
}

// CheckPassword confirms that the password matches the hash. It supports both
// bcrypt and Argon2. If the password matches, and the hash is anything other
// than argon2i, an updated hash is returned by internally calling HashPassword.
func (c *Crypto) CheckPassword(req CheckPasswordRequest, resp *CheckPasswordResponse) error {
	var match, updateIfMatch bool
	var reason string

	switch {
	case bytes.HasPrefix(req.Hash, bcryptA):
		fallthrough
	case bytes.HasPrefix(req.Hash, bcryptB):
		fallthrough
	case bytes.HasPrefix(req.Hash, bcryptX):
		fallthrough
	case bytes.HasPrefix(req.Hash, bcryptY):
		match = bcrypt.CompareHashAndPassword(req.Hash, req.Password) == nil
		updateIfMatch = true
	case bytes.HasPrefix(req.Hash, argon2id):
		updateIfMatch = true
		fallthrough
	case bytes.HasPrefix(req.Hash, argon2i):
		var err error
		match, err = argon2.Compare(req.Hash, req.Password)
		var e argon2.Error
		if errors.As(err, &e) {
			reason = err.Error()
		}
	}

	*resp = CheckPasswordResponse{
		Match:       match,
		DebugReason: reason,
		Update:      match && updateIfMatch,
	}
	if !resp.Update {
		return nil
	}

	updated := new(HashPasswordResponse)
	if err := c.HashPassword(HashPasswordRequest{Password: req.Password}, updated); err != nil {
		// We shouldn't block a user from logging in merely because we
		// couldn't update the hash.
		log.Errorf("Update password: %v", err)
		resp.DebugReason = err.Error()
	} else {
		resp.UpdatedHash = updated.Hash
	}
	return nil
}
