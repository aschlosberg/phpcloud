package argon2

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"testing"
)

func TestReferenceCases(t *testing.T) {
	// This test does not follow idiomatic Go style because it aims to provide
	// copy-and-paste functionality from the reference implementation. The
	// hashtest() and argon2_verify() calls are copied and pasted (CC0 1.0
	// Universal license) with the only changes being those to allow for
	// compilation and linting (converting C to Go).

	// Variables / constants required for the copy-pasted hashtest() calls to
	// compile.
	var version interface{}
	const (
		Argon2I  = Key
		Argon2ID = IDKey
	)

	hashtest := func(_ interface{}, tm, m uint32, p uint8, password, salt, hex, prefix, hash string, fn Function) {
		t.Run(`hashtest`, func(t *testing.T) {
			conf := fn.Config()
			conf.Time = tm
			conf.Memory = 1 << m
			conf.Threads = p
			conf.HashLen = uint32(len(hex)) / 2

			want := prefix + hash
			got, err := conf.hashWithSalt([]byte(password), []byte(salt))
			if err != nil {
				t.Fatalf(`Config(%+v).hashWithSalt(%q, %q) error %v`, conf, password, salt, err)
			}
			if string(got) != want {
				t.Errorf("Config(%+v).hashWithSalt(%q, %q)\ngot:  %q\nwant: %q", conf, password, salt, got, want)
			}

			comparisonTests(t, got, []byte(password))
		})
	}

	hashtest(version, 2, 16, 1, "password", "somesalt",
		"c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
		"$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
		"$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", Argon2I)
	hashtest(version, 2, 20, 1, "password", "somesalt",
		"d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
		"$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ",
		"$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E", Argon2I)
	hashtest(version, 2, 18, 1, "password", "somesalt",
		"296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
		"$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ",
		"$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s", Argon2I)
	hashtest(version, 2, 8, 1, "password", "somesalt",
		"89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
		"$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ",
		"$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8", Argon2I)
	hashtest(version, 2, 8, 2, "password", "somesalt",
		"4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
		"$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ",
		"$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E", Argon2I)
	hashtest(version, 1, 16, 1, "password", "somesalt",
		"d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
		"$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ",
		"$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8", Argon2I)
	hashtest(version, 4, 16, 1, "password", "somesalt",
		"aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
		"$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ",
		"$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls", Argon2I)
	hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
		"14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
		"$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
		"$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4", Argon2I)
	hashtest(version, 2, 16, 1, "password", "diffsalt",
		"b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
		"$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ",
		"$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE", Argon2I)

	hashtest(version, 2, 16, 1, "password", "somesalt",
		"09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
		"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
		"$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc", Argon2ID)
	hashtest(version, 2, 18, 1, "password", "somesalt",
		"78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c",
		"$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ",
		"$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow", Argon2ID)
	hashtest(version, 2, 8, 1, "password", "somesalt",
		"9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
		"$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ",
		"$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", Argon2ID)
	hashtest(version, 2, 8, 2, "password", "somesalt",
		"6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
		"$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ",
		"$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc", Argon2ID)
	hashtest(version, 1, 16, 1, "password", "somesalt",
		"f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
		"$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ",
		"$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg", Argon2ID)
	hashtest(version, 4, 16, 1, "password", "somesalt",
		"9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c",
		"$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ",
		"$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw", Argon2ID)
	hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
		"0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde",
		"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
		"$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94", Argon2ID)
	hashtest(version, 2, 16, 1, "password", "diffsalt",
		"bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c",
		"$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ",
		"$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw", Argon2ID)

	argon2Verify := func(prefix, hash, password string, want error) {
		t.Run("argon2Verify", func(t *testing.T) {
			fullHash := []byte(prefix + hash)
			got, err := Compare(fullHash, []byte(password))
			if got != false {
				t.Errorf(`Compare(%q, %q) got true; want false`, fullHash, password)
			}
			if !errors.Is(err, want) {
				t.Errorf(`Compare(%q, %q) got err %v; want %v`, fullHash, password, err, want)
			}
		})
	}

	// Handle an invalid encoding correctly (it is missing a $)
	argon2Verify("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ",
		"$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
		"password", ErrInvalidPrefix)

	// Handle an invalid encoding correctly (it is missing a $)
	argon2Verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
		"wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
		"password", ErrInvalidPrefix)

	// Handle an invalid encoding correctly (salt is too short)
	argon2Verify("$argon2i$v=19$m=65536,t=2,p=1$",
		"$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
		"password", ErrSaltTooShort)

	// Handle an mismatching hash (the encoded password is "passwore")
	argon2Verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ",
		"$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM",
		"password", nil)
}

func comparisonTests(t *testing.T, hash, password []byte) {
	t.Helper()

	t.Run("Compare", func(t *testing.T) {
		tests := []struct {
			desc    string
			compare []byte
			want    bool
		}{
			{
				desc:    "correct password",
				compare: password,
				want:    true,
			},
			{
				desc:    "suffix",
				compare: password[1:],
				want:    false,
			},
			{
				desc:    "prefix",
				compare: password[:len(password)-2],
				want:    false,
			},
			{
				desc:    "prepended",
				compare: append([]byte{0}, password...),
				want:    false,
			},
			{
				desc:    "appended",
				compare: append(password, 0),
				want:    false,
			},
			{
				desc:    "nil",
				compare: nil,
				want:    false,
			},
			{
				desc:    "arbitrary",
				compare: []byte("h4x0r"),
				want:    false,
			},
		}

		for _, tt := range tests {
			gotEq, err := Compare(hash, tt.compare)
			if err != nil {
				t.Errorf(`%s: Compare(%q, %q) got error %v`, tt.desc, hash, tt.compare, err)
				continue
			}
			if gotEq != tt.want {
				t.Errorf(`%s: Compare(%q, %q) got %t; want %t`, tt.desc, hash, tt.compare, gotEq, tt.want)
			}
		}
	})
}

func TestDefaultFunction(t *testing.T) {
	got, err := Hash([]byte{})
	if err != nil {
		t.Fatalf(`Hash("") error %v`, err)
	}
	if wantPrefix := []byte("$argon2id$"); !bytes.HasPrefix(got, wantPrefix) {
		t.Errorf("Hash() uses incorrect mode; got %q; want with prefix %q", got, wantPrefix)
	}
}

func TestSaltLen(t *testing.T) {
	hash, err := Hash([]byte{})
	if err != nil {
		t.Fatalf(`Hash("") error %v`, err)
	}
	_, salt, err := parse(hash)
	if err != nil {
		t.Fatalf(`parse(%q) error %v`, hash, err)
	}
	if got, want := len(salt), SaltLen; got != want {
		t.Errorf(`Hash("") got %q with salt length %d; want length %d`, hash, got, want)
	}
}

func TestHashFuzz(t *testing.T) {
	for _, fn := range []Function{IDKey, Key} {
		t.Run(string(fn), func(t *testing.T) {

			for _, password := range [][]byte{[]byte("foo"), []byte("bar"), []byte("password"), []byte(`*#LSKD^#)LKSUF*(SKelkf283`)} {
				t.Run(fmt.Sprintf("password %s", password), func(t *testing.T) {

					for i := 0; i < 100; i++ {
						c := fn.Config()
						c.Memory = uint32(rand.Intn(200) + 200)
						c.Time = uint32(rand.Intn(2) + 1)
						c.Threads = uint8(rand.Intn(2) + 1)
						c.HashLen = uint32(rand.Intn(16) + 16)

						hash, err := c.Hash(password)
						if err != nil {
							t.Errorf("Config(%s).Hash(%q) error %v", c.prefix(), password, err)
							continue
						}
						comparisonTests(t, hash, password)
					}

				})
			}
		})
	}
}

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		hash string
		want Error
	}{
		{
			name: "empty string",
			hash: "",
			want: ErrInvalidPrefix,
		},
		{
			name: "unsupported function argon2d",
			hash: `$argon2d$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG`,
			want: ErrInvalidMode,
		},
		{
			name: "different version 18",
			hash: `$argon2i$v=18$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG`,
			want: ErrInvalidVersion,
		},
		{
			name: "extraneous config x=42",
			hash: `$argon2i$v=19$m=65536,x=42,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG`,
			want: ErrInvalidConfig,
		},
		{
			name: "missing config t",
			hash: `$argon2i$v=19$m=65536,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG`,
			want: ErrInvalidConfig,
		},
		{
			name: "invalid config key-val pair p4",
			hash: `$argon2i$v=19$m=65536,t=2,p4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG`,
			want: ErrInvalidConfig,
		},
		{
			name: "invalid config string value m=foo",
			hash: `$argon2i$v=19$m=foo,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG`,
			want: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compare([]byte(tt.hash), nil)
			if got != false {
				t.Error("Compare() with non-nil error got true; want false")
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("Compare(%q, nil) got err %v; want %v", tt.hash, err, tt.want)
			}

			// This does little other than provide coverage for error strings,
			// which would otherwise falsely lower the coverage report.
			_ = tt.want.Error()
		})
	}
}

func TestInvalidConfig(t *testing.T) {
	t.Run("user-instantiated", func(t *testing.T) {
		c := new(Config)
		_, err := c.Hash(nil)
		if want := ErrInvalidFunction; !errors.Is(err, want) {
			t.Errorf("user-instantiated *Config, Hash(nil) got err %v; want %v", err, want)
		}
	})

	t.Run("unsupported function", func(t *testing.T) {
		const fn = Function("argon2d")
		if got := fn.Config(); got != nil {
			t.Errorf(`Function(%s).Config() got %+v; want nil`, fn, got)
		}
	})
}
