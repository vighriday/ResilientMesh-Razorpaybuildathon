// Package attest turns the audit ledger into evidence that travels.
//
// The hash chain already makes the ledger tamper-evident, but it has a
// practical limit: checking that one entry is genuine means walking every entry
// before it. That is fine for an operator with the database and useless for
// everyone else. A merchant disputing a chargeback cannot hand a bank five
// hundred unrelated payment records, and would not be allowed to if they wanted
// to; an auditor asking whether one mandate debit was permitted should not have
// to be given every other merchant's traffic to find out.
//
// A Merkle tree over the same entries fixes that. The root is one 32-byte
// commitment to the whole ledger, and any single entry can be proved to be
// under that root with about log2(n) hashes. For the 538-entry ledger of a
// demonstration run that is ten hashes rather than five hundred and thirty
// eight records, and the proof reveals nothing about any other entry.
//
// This is what makes a recovery decision portable. The system can emit a small
// bundle that says "this payment was retried, here is the rule that permitted
// it, and here is the arithmetic proving that record is in the published
// ledger", and the recipient can check it offline with no access to the
// database, no API call, and no trust in the party that produced it.
package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// Domain separation tags, following the construction RFC 6962 uses for
// certificate transparency.
//
// Without them a tree is vulnerable to a second-preimage attack: an attacker
// who can choose leaf content could supply a leaf whose bytes equal the
// concatenation of two legitimate node hashes, and a verifier would accept an
// internal node as though it were a leaf. Tagging leaves and interior nodes
// with different prefixes makes the two hash spaces disjoint, so no leaf can
// ever collide with a node.
const (
	leafPrefix = 0x00
	nodePrefix = 0x01
)

// ErrEmptyTree is returned when a root or a proof is requested from a tree with
// no leaves. An empty ledger has no root rather than a zero root: returning
// zeroes would let "nothing was recorded" be presented as a valid commitment.
var ErrEmptyTree = errors.New("attest: the tree has no leaves")

// ErrIndexOutOfRange means a proof was requested for a leaf that does not exist.
var ErrIndexOutOfRange = errors.New("attest: leaf index out of range")

// Tree is an immutable Merkle tree over ledger entry digests.
//
// Levels are stored rather than recomputed because a single evidence pack asks
// for several proofs against the same tree, and rebuilding the tree per proof
// turns a linear job into a quadratic one on a ledger that only grows.
type Tree struct {
	levels [][][32]byte // levels[0] is the leaf level
}

// LeafHash computes the tagged hash of one ledger entry digest.
//
// The input is the entry's own chain hash, so the tree commits to exactly what
// the chain commits to. Building the tree over raw entry content instead would
// create a second definition of "this entry", and two definitions of the same
// thing eventually disagree.
func LeafHash(entryHash [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte{leafPrefix})
	_, _ = h.Write(entryHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func nodeHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte{nodePrefix})
	_, _ = h.Write(left[:])
	_, _ = h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// New builds a tree over entry digests in ledger order.
//
// An odd level promotes its final node unchanged rather than duplicating it.
// Duplication is the well-known CVE-2012-2459 shape, where two different leaf
// counts produce the same root and a block can be forged; promotion avoids it
// without needing the tree to be padded to a power of two.
func New(entryHashes [][32]byte) *Tree {
	if len(entryHashes) == 0 {
		return &Tree{}
	}
	leaves := make([][32]byte, len(entryHashes))
	for i, h := range entryHashes {
		leaves[i] = LeafHash(h)
	}
	levels := [][][32]byte{leaves}
	for cur := leaves; len(cur) > 1; {
		next := make([][32]byte, 0, (len(cur)+1)/2)
		for i := 0; i < len(cur); i += 2 {
			if i+1 == len(cur) {
				next = append(next, cur[i])
				continue
			}
			next = append(next, nodeHash(cur[i], cur[i+1]))
		}
		levels = append(levels, next)
		cur = next
	}
	return &Tree{levels: levels}
}

// Size reports how many leaves the tree commits to.
func (t *Tree) Size() int {
	if len(t.levels) == 0 {
		return 0
	}
	return len(t.levels[0])
}

// Root returns the single commitment to the whole ledger.
func (t *Tree) Root() ([32]byte, error) {
	if t.Size() == 0 {
		return [32]byte{}, ErrEmptyTree
	}
	top := t.levels[len(t.levels)-1]
	return top[0], nil
}

// RootHex returns the root as lowercase hex, which is the form that is
// published, printed and pasted.
func (t *Tree) RootHex() (string, error) {
	r, err := t.Root()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(r[:]), nil
}

// Step is one sibling along the path from a leaf to the root.
//
// Right records which side the sibling sits on. Without it a verifier would
// have to guess the concatenation order, and guessing wrong is indistinguishable
// from a forged proof.
type Step struct {
	Hash  string `json:"hash"`
	Right bool   `json:"right"`
}

// Proof is everything needed to check one entry against a published root,
// carrying no information about any other entry.
type Proof struct {
	// LeafIndex is the entry's position in ledger order.
	LeafIndex int `json:"leaf_index"`
	// TreeSize pins which ledger the proof was cut against. A proof is only
	// meaningful against the root of a tree of exactly this size, and omitting
	// it would let a proof from a shorter prefix be replayed against a longer
	// ledger.
	TreeSize  int    `json:"tree_size"`
	EntryHash string `json:"entry_hash"`
	Path      []Step `json:"path"`
	Root      string `json:"root"`
}

// ProofFor cuts an inclusion proof for one leaf.
func (t *Tree) ProofFor(index int) (Proof, error) {
	if t.Size() == 0 {
		return Proof{}, ErrEmptyTree
	}
	if index < 0 || index >= t.Size() {
		return Proof{}, fmt.Errorf("%w: %d not in [0,%d)", ErrIndexOutOfRange, index, t.Size())
	}

	var path []Step
	idx := index
	for level := 0; level < len(t.levels)-1; level++ {
		cur := t.levels[level]
		sibling := idx ^ 1
		// A promoted final node has no sibling at this level, so the path skips
		// it and the index halves. Emitting a step here would make the verifier
		// hash a node that the builder never hashed.
		if sibling < len(cur) {
			path = append(path, Step{
				Hash:  hex.EncodeToString(cur[sibling][:]),
				Right: sibling > idx,
			})
		}
		idx /= 2
	}

	root, err := t.RootHex()
	if err != nil {
		return Proof{}, err
	}
	leaf := t.levels[0][index]
	return Proof{
		LeafIndex: index,
		TreeSize:  t.Size(),
		EntryHash: hex.EncodeToString(leaf[:]),
		Path:      path,
		Root:      root,
	}, nil
}

// VerifyProof recomputes the root from an entry digest and a path.
//
// It takes the entry's chain hash rather than the leaf hash, so a caller checks
// the thing it actually has: the digest printed in the ledger. Tagging is
// applied here, which means a caller cannot accidentally verify against an
// untagged leaf and defeat the domain separation.
func VerifyProof(entryHash [32]byte, p Proof) bool {
	if p.TreeSize <= 0 || p.LeafIndex < 0 || p.LeafIndex >= p.TreeSize {
		return false
	}
	cur := LeafHash(entryHash)
	if hex.EncodeToString(cur[:]) != p.EntryHash {
		return false
	}
	for _, step := range p.Path {
		raw, err := hex.DecodeString(step.Hash)
		if err != nil || len(raw) != 32 {
			return false
		}
		var sib [32]byte
		copy(sib[:], raw)
		if step.Right {
			cur = nodeHash(cur, sib)
		} else {
			cur = nodeHash(sib, cur)
		}
	}
	return hex.EncodeToString(cur[:]) == p.Root
}

// ParseHash decodes a hex digest from the ledger into the fixed-size form the
// tree works in, rejecting anything that is not exactly 32 bytes.
func ParseHash(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("attest: %q is not hex: %w", s, err)
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("attest: expected a 32-byte digest, got %d bytes", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
