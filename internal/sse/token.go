package sse

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	// SessionTokenEntropyBytes is the raw entropy behind a stream credential.
	// 256 bits removes brute force from the threat model entirely, which matters
	// because the token is the only thing standing between an attacker and the
	// live event stream of a checkout they can guess the session id for.
	SessionTokenEntropyBytes = 32

	// MaxSessionTokenLen bounds the attacker-controlled string that reaches the
	// hash function. A well-formed token is 43 characters; the slack tolerates
	// a future format change without tolerating a multi-megabyte query string.
	MaxSessionTokenLen = 128

	// tokenHashLen is the length of a hex-encoded SHA-256 digest.
	tokenHashLen = sha256.Size * 2
)

// NewSessionToken mints a stream credential and the digest to store beside it.
// The token is returned exactly once, to the checkout that created the session;
// only the digest is ever persisted.
//
// Storing the digest rather than the token is what makes a database read
// unusable against the stream. Sessions live in the same PostgreSQL instance as
// incidents and the audit ledger, so anything that can read a row — a backup, a
// replica, an over-broad analytics grant, a log of a query result — would
// otherwise hand out replayable credentials for every checkout in flight. With
// only the digest at rest, that reader learns nothing it can present to the
// endpoint, and the pre-image gap is unbridgeable rather than merely
// inconvenient.
//
// The encoding is unpadded base64url because the token travels in a query
// string on the EventSource path: '+', '/', and '=' would each need escaping,
// and a token that survives one round of URL encoding but not two is a support
// ticket waiting to happen.
func NewSessionToken() (token, hash string, err error) {
	buf := make([]byte, SessionTokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("sse: read session token entropy: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, HashToken(token), nil
}

// HashToken derives the at-rest form of a stream credential. It hashes the
// presented text rather than the decoded entropy so that verification needs no
// decoding step, and therefore has no decoder to be confused by a
// differently-encoded string that decodes to the same bytes.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// VerifyToken reports whether token is the pre-image of hash.
//
// The comparison is constant-time even though comparing two SHA-256 digests is
// not, on its own, timing-sensitive: a digest is not a secret and cannot be
// guessed a byte at a time, because an attacker cannot steer the digest without
// already knowing the pre-image. It is written this way so the shape of the
// check stays correct under a change nobody remembers to re-audit — the day
// someone stores a token in a form that is comparable directly, an early-exit
// compare here would quietly become an oracle.
//
// Length screening happens before hashing: the bounds are public facts about the
// format, so rejecting on them leaks nothing while keeping unbounded input away
// from the hash.
func VerifyToken(token, hash string) bool {
	if token == "" || len(token) > MaxSessionTokenLen {
		return false
	}
	if len(hash) != tokenHashLen {
		return false
	}
	computed := HashToken(token)
	return subtle.ConstantTimeCompare([]byte(computed), []byte(hash)) == 1
}
