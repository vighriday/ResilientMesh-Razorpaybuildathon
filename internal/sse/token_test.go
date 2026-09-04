package sse

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestNewSessionTokenIsUnpredictableAndURLSafe(t *testing.T) {
	t.Parallel()
	const iterations = 512
	seen := make(map[string]struct{}, iterations)

	for i := 0; i < iterations; i++ {
		token, hash, err := NewSessionToken()
		if err != nil {
			t.Fatalf("NewSessionToken: %v", err)
		}
		if _, dup := seen[token]; dup {
			t.Fatal("NewSessionToken repeated a token")
		}
		seen[token] = struct{}{}

		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("token is not unpadded base64url: %v", err)
		}
		if len(raw) != SessionTokenEntropyBytes {
			t.Fatalf("token carries %d bytes of entropy, want %d", len(raw), SessionTokenEntropyBytes)
		}
		if strings.ContainsAny(token, "+/=") {
			// The token travels in a query string on the EventSource path.
			t.Fatalf("token contains characters that need URL escaping: %q", token)
		}
		if len(hash) != tokenHashLen {
			t.Fatalf("hash length = %d, want %d", len(hash), tokenHashLen)
		}
		if _, err := hex.DecodeString(hash); err != nil {
			t.Fatalf("hash is not hex: %v", err)
		}
		if strings.Contains(hash, token) {
			t.Fatal("the stored digest must not contain the token")
		}
		if !VerifyToken(token, hash) {
			t.Fatal("a freshly minted token failed verification")
		}
	}
}

func TestHashTokenIsDeterministicAndSensitive(t *testing.T) {
	t.Parallel()
	const token = "3Jm9Qy8hV1sT2uW4xZ6bC0dE5fG7hJ9kL1mN3pQ5rS7"
	if HashToken(token) != HashToken(token) {
		t.Fatal("HashToken is not deterministic")
	}
	if HashToken(token) == HashToken(token+"a") {
		t.Fatal("HashToken collided on a one-character difference")
	}
	if HashToken(token) == HashToken(strings.ToUpper(token)) {
		t.Fatal("HashToken is case-insensitive; the credential space would collapse")
	}
}

func TestVerifyTokenFailsClosed(t *testing.T) {
	t.Parallel()
	token, hash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	other, otherHash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}

	cases := []struct {
		name  string
		token string
		hash  string
	}{
		{"empty token", "", hash},
		{"empty hash", token, ""},
		// A session row that was never issued a token must not be openable by
		// anyone who can present an empty credential.
		{"both empty", "", ""},
		{"another session's token", other, hash},
		{"another session's hash", token, otherHash},
		{"truncated hash", token, hash[:len(hash)-1]},
		{"hash with trailing space", token, hash + " "},
		{"uppercased hash", token, strings.ToUpper(hash)},
		{"token with trailing newline", token + "\n", hash},
		{"token with leading space", " " + token, hash},
		{"raw digest presented as the token", hash, hash},
		{"oversized token", strings.Repeat("a", MaxSessionTokenLen+1), hash},
		{"hash of the hash", token, HashToken(hash)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if VerifyToken(tc.token, tc.hash) {
				t.Fatal("VerifyToken accepted a credential it must reject")
			}
		})
	}

	if !VerifyToken(token, hash) {
		t.Fatal("VerifyToken rejected the matching pair")
	}
}

func TestVerifyTokenBoundsInputBeforeHashing(t *testing.T) {
	t.Parallel()
	// A megabyte of query string must be rejected on length, not hashed. The
	// assertion is behavioural: the boundary is exact and one byte either side
	// of it decides the outcome for a token that could never match anyway.
	_, hash, err := NewSessionToken()
	if err != nil {
		t.Fatalf("NewSessionToken: %v", err)
	}
	atLimit := strings.Repeat("a", MaxSessionTokenLen)
	if !VerifyToken(atLimit, HashToken(atLimit)) {
		t.Fatal("a token exactly at the length bound must still verify")
	}
	over := strings.Repeat("a", MaxSessionTokenLen+1)
	if VerifyToken(over, HashToken(over)) {
		t.Fatal("a token past the length bound must be rejected even if its digest matches")
	}
	if VerifyToken(strings.Repeat("a", 1<<20), hash) {
		t.Fatal("VerifyToken accepted an unbounded credential")
	}
}
