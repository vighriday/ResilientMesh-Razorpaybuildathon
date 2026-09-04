package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

func hashes(n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		out[i] = sha256.Sum256([]byte(fmt.Sprintf("entry-%d", i)))
	}
	return out
}

func TestEveryLeafProvesAgainstTheRoot(t *testing.T) {
	// Sizes chosen to cover both shapes: powers of two, and the odd counts that
	// force a node to be promoted rather than paired.
	for _, n := range []int{1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 100, 538, 1000} {
		leaves := hashes(n)
		tree := New(leaves)
		if tree.Size() != n {
			t.Fatalf("n=%d: size %d", n, tree.Size())
		}
		for i := 0; i < n; i++ {
			p, err := tree.ProofFor(i)
			if err != nil {
				t.Fatalf("n=%d i=%d: %v", n, i, err)
			}
			if !VerifyProof(leaves[i], p) {
				t.Fatalf("n=%d i=%d: a proof cut by the tree did not verify against its own root", n, i)
			}
		}
	}
}

func TestAProofIsLogarithmicRatherThanLinear(t *testing.T) {
	// The whole reason for the tree: an evidence pack for one payment must not
	// grow with the size of the ledger it came from.
	leaves := hashes(538)
	tree := New(leaves)
	p, err := tree.ProofFor(269)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Path) > 12 {
		t.Fatalf("path of %d steps for 538 leaves; expected about log2(538) = 10", len(p.Path))
	}
	if len(p.Path) < 8 {
		t.Fatalf("path of %d steps is implausibly short for 538 leaves", len(p.Path))
	}
}

func TestAForgedEntryDoesNotVerify(t *testing.T) {
	leaves := hashes(64)
	tree := New(leaves)
	p, err := tree.ProofFor(20)
	if err != nil {
		t.Fatal(err)
	}
	forged := sha256.Sum256([]byte("this entry was never in the ledger"))
	if VerifyProof(forged, p) {
		t.Fatal("a digest that is not in the tree verified against the root")
	}
}

func TestATamperedPathDoesNotVerify(t *testing.T) {
	leaves := hashes(64)
	tree := New(leaves)
	p, err := tree.ProofFor(20)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("a flipped sibling", func(t *testing.T) {
		bad := p
		bad.Path = append([]Step(nil), p.Path...)
		raw, _ := hex.DecodeString(bad.Path[0].Hash)
		raw[0] ^= 0xff
		bad.Path[0].Hash = hex.EncodeToString(raw)
		if VerifyProof(leaves[20], bad) {
			t.Fatal("a proof with an altered sibling verified")
		}
	})

	t.Run("a flipped side", func(t *testing.T) {
		// Direction is part of the proof. If a verifier guessed the
		// concatenation order instead of being told, an attacker could reorder
		// siblings freely.
		bad := p
		bad.Path = append([]Step(nil), p.Path...)
		bad.Path[0].Right = !bad.Path[0].Right
		if VerifyProof(leaves[20], bad) {
			t.Fatal("a proof with a reversed sibling side verified")
		}
	})

	t.Run("a truncated path", func(t *testing.T) {
		bad := p
		bad.Path = p.Path[:len(p.Path)-1]
		if VerifyProof(leaves[20], bad) {
			t.Fatal("a proof missing its final step verified")
		}
	})

	t.Run("a substituted root", func(t *testing.T) {
		bad := p
		other := New(hashes(64 + 1))
		bad.Root, _ = other.RootHex()
		if VerifyProof(leaves[20], bad) {
			t.Fatal("a proof verified against a root from a different ledger")
		}
	})
}

func TestALeafCannotImpersonateAnInteriorNode(t *testing.T) {
	// Second-preimage resistance, which is the reason leaves and nodes carry
	// different tags. Without the tags a leaf whose content happened to equal
	// two concatenated node hashes would hash identically to that interior
	// node, and a subtree could be presented as a single entry.
	leaves := hashes(4)
	tree := New(leaves)

	l0, l1 := tree.levels[0][0], tree.levels[0][1]
	interior := tree.levels[1][0]

	// Construct exactly the preimage a naive implementation would produce.
	naive := sha256.New()
	_, _ = naive.Write(l0[:])
	_, _ = naive.Write(l1[:])
	var collision [32]byte
	copy(collision[:], naive.Sum(nil))

	if collision == interior {
		t.Fatal("an interior node hashes as the untagged concatenation of its children, " +
			"so a leaf could impersonate it")
	}

	// And a leaf must not hash as its raw content either.
	raw := sha256.Sum256([]byte("entry-0"))
	if LeafHash(raw) == raw {
		t.Fatal("a leaf hash equals its input")
	}
}

func TestDifferentLeafCountsProduceDifferentRoots(t *testing.T) {
	// The duplicate-last-node construction (CVE-2012-2459) makes trees of size
	// n and n+1 collide for some n. Promotion must not reintroduce that.
	seen := map[string]int{}
	for n := 1; n <= 200; n++ {
		root, err := New(hashes(n)).RootHex()
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[root]; dup {
			t.Fatalf("ledgers of %d and %d entries share a root", prev, n)
		}
		seen[root] = n
	}
}

func TestTheRootIsStableForTheSameLedger(t *testing.T) {
	leaves := hashes(77)
	a, err := New(leaves).RootHex()
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(leaves).RootHex()
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("two builds of one ledger disagree: %s vs %s", a, b)
	}
}

func TestChangingOneEntryChangesTheRoot(t *testing.T) {
	leaves := hashes(64)
	before, _ := New(leaves).RootHex()

	altered := append([][32]byte(nil), leaves...)
	altered[31] = sha256.Sum256([]byte("edited"))
	after, _ := New(altered).RootHex()

	if before == after {
		t.Fatal("editing an entry left the root unchanged")
	}
}

func TestAnEmptyLedgerHasNoRoot(t *testing.T) {
	// Not a zero root. "Nothing was recorded" must not be presentable as a
	// valid commitment to an empty history.
	tree := New(nil)
	if _, err := tree.Root(); !errors.Is(err, ErrEmptyTree) {
		t.Fatalf("Root() error = %v, want ErrEmptyTree", err)
	}
	if _, err := tree.ProofFor(0); !errors.Is(err, ErrEmptyTree) {
		t.Fatalf("ProofFor() error = %v, want ErrEmptyTree", err)
	}
}

func TestOutOfRangeLeavesAreRejected(t *testing.T) {
	tree := New(hashes(8))
	for _, i := range []int{-1, 8, 9999} {
		if _, err := tree.ProofFor(i); !errors.Is(err, ErrIndexOutOfRange) {
			t.Errorf("ProofFor(%d) error = %v, want ErrIndexOutOfRange", i, err)
		}
	}
}

func TestAProofIsRejectedWhenItsIndexContradictsItsSize(t *testing.T) {
	leaves := hashes(16)
	tree := New(leaves)
	p, _ := tree.ProofFor(3)
	for _, bad := range []Proof{
		func() Proof { q := p; q.TreeSize = 0; return q }(),
		func() Proof { q := p; q.LeafIndex = -1; return q }(),
		func() Proof { q := p; q.LeafIndex = q.TreeSize; return q }(),
	} {
		if VerifyProof(leaves[3], bad) {
			t.Errorf("a proof with index %d of %d verified", bad.LeafIndex, bad.TreeSize)
		}
	}
}

func TestParseHashRejectsAnythingThatIsNotADigest(t *testing.T) {
	for _, s := range []string{"", "zz", "abcd", hex.EncodeToString(make([]byte, 31))} {
		if _, err := ParseHash(s); err == nil {
			t.Errorf("ParseHash(%q) accepted a value that is not a 32-byte digest", s)
		}
	}
	good := hex.EncodeToString(make([]byte, 32))
	if _, err := ParseHash(good); err != nil {
		t.Errorf("ParseHash rejected a valid digest: %v", err)
	}
}

func TestProofsRevealNothingAboutOtherEntries(t *testing.T) {
	// The privacy property that makes an evidence pack shareable: a merchant
	// hands a bank one payment's proof, and the bank learns the sibling
	// digests, which are hashes, and nothing else.
	leaves := hashes(538)
	tree := New(leaves)
	p, err := tree.ProofFor(100)
	if err != nil {
		t.Fatal(err)
	}
	other := hex.EncodeToString(leaves[101][:])
	for _, step := range p.Path {
		if step.Hash == other {
			t.Fatal("a proof carried another entry's ledger digest verbatim")
		}
	}
}

func BenchmarkProofFor538(b *testing.B) {
	tree := New(hashes(538))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := tree.ProofFor(i % 538); err != nil {
			b.Fatal(err)
		}
	}
}
