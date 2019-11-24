// Package argon2 wraps the x/crypto/argon2 package to provide password-hashing
// functionality along with secure checking of hashes.
package argon2

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"

	"golang.org/x/crypto/argon2"
)

const (
	// Version is the Argon2 version implemented by the wrapped x/crypto/argon2
	// package.
	Version = argon2.Version
	// SaltLen is the number of bytes used in generating salts. It is defined
	// purely for documentary purposes.
	SaltLen = 16
)

// A Mode corresponds to an Argon2 Mode.
type Mode string

// Supported Argon2 Modes.
const (
	ID Mode = "argon2id"
	I  Mode = "argon2i"
)

// Config returns a default Config for the Mode, as recommended in the
// crypto/argon2 documentation.
func (m Mode) Config() *Config {
	switch m {
	case ID:
		return &Config{
			mode:    ID,
			Time:    1,
			Memory:  64 * 1024,
			Threads: 4,
			HashLen: 32,
		}
	case I:
		return &Config{
			mode:    I,
			Time:    3,
			Memory:  32 * 1024,
			Threads: 4,
			HashLen: 32,
		}
	}
	return nil
}

// Config carries parameters to be propagated to crypto/argon2 functions. Do not
// instantiate Config directly—rather use Function.Config() as it provides
// secure-by-default values.
type Config struct {
	mode Mode

	Time, Memory uint32
	Threads      uint8
	// HashLen corresponds to keyLen in the crypto/argon2 function parameters.
	HashLen uint32
}

// Error implements the error interface.
type Error int

// Pre-defined errors.
const (
	ErrUnknown Error = iota
	ErrInvalidMode
	ErrInvalidPrefix
	ErrInvalidVersion
	ErrInvalidConfig
	ErrSaltTooShort
)

func (e Error) Error() string {
	switch e {
	case ErrInvalidMode:
		return fmt.Sprintf(`invalid Argon2 mode; must be %s or %s`, ID, I)
	case ErrInvalidPrefix:
		return `hash with invalid prefix`
	case ErrInvalidVersion:
		return fmt.Sprintf(`hash with invalid Argon2 version; must be %d`, Version)
	case ErrInvalidConfig:
		return `hash prefix with invalid config`
	case ErrSaltTooShort:
		return `salt must be at least 8 bytes`
	}
	return "unknown error"
}

// prefix returns the Config as a prefix string for the final hash.
func (c *Config) prefix() string {
	return fmt.Sprintf(`$%s$v=%d$m=%d,t=%d,p=%d$`, c.mode, Version, c.Memory, c.Time, c.Threads)
}

// Hash returns a hashed password using the Config and a salt generated from
// crypto/rand.
func (c *Config) Hash(password []byte) ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("create salt from crypto/rand: %v", err)
	}
	return c.hashWithSalt(password, salt)
}

// hashWithSalt returns a hashed password using the Config and a specified salt.
func (c *Config) hashWithSalt(password, salt []byte) ([]byte, error) {
	fn := argon2.IDKey
	switch c.mode {
	case ID:
		fn = argon2.IDKey
	case I:
		fn = argon2.Key
	default:
		return nil, ErrInvalidMode
	}

	var b bytes.Buffer
	// TODO determine a more precise value for Grow().
	b.Grow(128)
	b.WriteString(c.prefix())
	b.Write(encode64(salt))
	b.WriteRune('$')
	b.Write(encode64(fn(password, salt, c.Time, c.Memory, c.Threads, c.HashLen)))
	return b.Bytes(), nil
}

func encode64(buf []byte) []byte {
	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(buf)))
	base64.RawStdEncoding.Encode(out, buf)
	return out
}

// Hash hashes the password with the default Config for argon2i. According to
// x/crypto/argon2 docs, argon2i is the preferred method for password hashing.
func Hash(password []byte) ([]byte, error) {
	return I.Config().Hash(password)
}

// Compare hashes password and returns true i.f.f. it results in hash.
func Compare(hash, password []byte) (bool, error) {
	c, salt, err := parse(hash)
	if err != nil {
		return false, err
	}
	if len(salt) < 8 {
		return false, ErrSaltTooShort
	}

	passHash, err := c.hashWithSalt(password, salt)
	if err != nil {
		return false, fmt.Errorf("hash password for comparison: %w", err)
	}

	return subtle.ConstantTimeCompare(passHash, hash) == 1, nil
}

var (
	dollar = []byte(`$`)
	comma  = []byte(`,`)
	equal  = []byte(`=`)
	ver    = fmt.Sprintf("v=%d", Version)
)

func parse(hash []byte) (*Config, []byte, error) {
	parts := bytes.Split(hash, dollar)
	if len(parts) != 6 || len(parts[0]) != 0 {
		return nil, nil, ErrInvalidPrefix
	}

	mode := Mode(parts[1])
	if mode != ID && mode != I {
		return nil, nil, ErrInvalidMode
	}

	if string(parts[2]) != ver {
		return nil, nil, ErrInvalidVersion
	}

	cParts := bytes.Split(parts[3], comma)
	if len(cParts) != 3 {
		return nil, nil, ErrInvalidConfig
	}
	conf := make(map[string]int)
	for _, p := range cParts {
		keyVal := bytes.Split(p, equal)
		if len(keyVal) != 2 {
			return nil, nil, ErrInvalidConfig
		}
		val, err := strconv.Atoi(string(keyVal[1]))
		if err != nil {
			return nil, nil, ErrInvalidConfig
		}
		conf[string(keyVal[0])] = val
	}

	salt := make([]byte, base64.RawStdEncoding.DecodedLen(len(parts[4])))
	base64.RawStdEncoding.Decode(salt, parts[4])

	return &Config{
		mode:    mode,
		Memory:  uint32(conf["m"]),
		Time:    uint32(conf["t"]),
		Threads: uint8(conf["p"]),
		HashLen: uint32(base64.RawStdEncoding.DecodedLen(len(parts[5]))),
	}, salt, nil
}
