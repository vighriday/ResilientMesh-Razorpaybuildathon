package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/hriday/razorpay-resilient-mesh/internal/attest"
	"github.com/hriday/razorpay-resilient-mesh/internal/domain"
)

// The evidence command answers a question an operator is actually asked.
//
// A merchant disputing a chargeback, or a compliance team answering an auditor,
// needs to show what happened to one payment and to show that the record is
// genuine. The hash chain proves the ledger has not been rewritten, but
// verifying a single entry against it means walking every entry before it, so
// the only honest answer used to be "here is the whole ledger", which is
// unshareable: it contains every other merchant's traffic.
//
// A Merkle inclusion proof is the missing piece. It is about log2(n) sibling
// hashes, it can be checked with no database and no API call, and the siblings
// are digests, so the bundle discloses nothing about the payments it does not
// describe.
//
// The bundle is deliberately plain JSON with the verification recipe written
// into it. Evidence that can only be checked by the tool that produced it is
// not evidence.
const evidenceSchema = "resilientmesh.evidence.v1"

type evidenceBundle struct {
	Schema      string `json:"schema"`
	GeneratedAt string `json:"generated_at"`
	PaymentID   string `json:"payment_id"`
	IncidentID  string `json:"incident_id"`

	Incident domain.Incident        `json:"incident"`
	Attempts []domain.AttemptRecord `json:"attempts"`
	Mandate  *domain.MandateRecord  `json:"mandate,omitempty"`

	Ledger evidenceLedger `json:"ledger"`

	HowToVerify []string `json:"how_to_verify"`
}

type evidenceLedger struct {
	MerkleRoot string           `json:"merkle_root"`
	TreeSize   int              `json:"tree_size"`
	ChainHead  string           `json:"chain_head"`
	Genesis    string           `json:"genesis"`
	Algorithm  string           `json:"algorithm"`
	Entries    []evidenceRecord `json:"entries"`
}

type evidenceRecord struct {
	Seq        int64        `json:"seq"`
	Kind       string       `json:"kind"`
	Actor      string       `json:"actor"`
	At         string       `json:"at"`
	AtUnixNano string       `json:"at_unix_nano"`
	IncidentID string       `json:"incident_id"`
	DetailB64  string       `json:"detail_b64"`
	PrevHash   string       `json:"prev_hash"`
	Hash       string       `json:"hash"`
	Proof      attest.Proof `json:"inclusion_proof"`
}

// cmdEvidence builds a portable bundle for one payment.
func cmdEvidence(ctx context.Context, c *conn, g globals, paymentID, outPath string, out io.Writer) error {
	if paymentID == "" {
		return badUsage("evidence needs a payment id")
	}

	incidents, err := c.pg.ListIncidents(ctx, 2000)
	if err != nil {
		return fmt.Errorf("reading incidents: %w", err)
	}
	var target domain.Incident
	found := false
	for _, in := range incidents {
		if in.PaymentID == paymentID || in.ID == paymentID {
			target, found = in, true
			break
		}
	}
	if !found {
		return fmt.Errorf("no incident found for %q", paymentID)
	}

	// The tree is built over the whole ledger, because a proof is only
	// meaningful against the root of the ledger it was cut from. Reading every
	// entry to prove one is the cost paid once, here, by the party that already
	// has the database, so that the recipient never has to.
	var (
		hashes []([32]byte)
		all    []domain.AuditEntry
		prev   = domain.GenesisHash
		broken int64
	)
	err = c.pg.StreamAudit(ctx, func(e domain.AuditEntry) error {
		if broken == 0 && !e.VerifyAgainst(prev) {
			broken = e.Seq
		}
		prev = e.Hash
		h, parseErr := attest.ParseHash(e.Hash)
		if parseErr != nil {
			return parseErr
		}
		hashes = append(hashes, h)
		all = append(all, e)
		return nil
	})
	if err != nil {
		return fmt.Errorf("reading the ledger: %w", err)
	}
	if broken != 0 {
		// Refusing here rather than emitting a bundle with a caveat. Evidence
		// cut from a ledger already known to be broken is worse than none: it
		// would carry a valid-looking proof of membership in a compromised set.
		return fmt.Errorf("refusing to build evidence: the audit chain is broken at sequence %d", broken)
	}
	if len(hashes) == 0 {
		return fmt.Errorf("the ledger is empty, so there is nothing to prove")
	}

	tree := attest.New(hashes)
	root, err := tree.RootHex()
	if err != nil {
		return fmt.Errorf("committing the ledger: %w", err)
	}

	bundle := evidenceBundle{
		Schema:      evidenceSchema,
		GeneratedAt: c.clock.Now().UTC().Format(time.RFC3339),
		PaymentID:   target.PaymentID,
		IncidentID:  target.ID,
		Incident:    target,
		Ledger: evidenceLedger{
			MerkleRoot: root,
			TreeSize:   tree.Size(),
			ChainHead:  prev,
			Genesis:    domain.GenesisHash,
			Algorithm: "entry digest: sha256 over each field absorbed as an 8-byte big-endian " +
				"length followed by its bytes, in the order seq, incident_id, kind, actor, " +
				"detail, at (unix nanoseconds), prev_hash. tree: sha256 with 0x00 prefixed to " +
				"leaves and 0x01 prefixed to interior nodes, odd levels promoted rather than " +
				"duplicated.",
		},
		HowToVerify: []string{
			"1. For each entry, recompute its digest from the fields in this bundle and check it equals hash.",
			"2. Fold each inclusion_proof path into that digest and check the result equals merkle_root.",
			"3. Compare merkle_root against the root the operator published independently.",
			"Step 1 catches an edited record. Step 2 catches a record that was never in the ledger.",
			"Step 3 is what stops the party that produced this bundle from choosing both.",
		},
	}

	if attempts, aerr := c.pg.ListAttempts(ctx, target.ID); aerr == nil {
		bundle.Attempts = attempts
	}
	if target.SubscriptionID != "" {
		if m, merr := c.pg.GetMandate(ctx, target.SubscriptionID); merr == nil {
			bundle.Mandate = &m
		}
	}

	for i, e := range all {
		if e.IncidentID != target.ID {
			continue
		}
		proof, perr := tree.ProofFor(i)
		if perr != nil {
			return fmt.Errorf("cutting an inclusion proof for entry %d: %w", e.Seq, perr)
		}
		bundle.Ledger.Entries = append(bundle.Ledger.Entries, evidenceRecord{
			Seq: e.Seq, Kind: string(e.Kind), Actor: e.Actor,
			At:         e.At.UTC().Format(time.RFC3339Nano),
			AtUnixNano: strconv.FormatInt(e.At.UTC().UnixNano(), 10),
			IncidentID: e.IncidentID,
			DetailB64:  base64.StdEncoding.EncodeToString(e.Detail),
			PrevHash:   e.PrevHash, Hash: e.Hash, Proof: proof,
		})
	}
	if len(bundle.Ledger.Entries) == 0 {
		return fmt.Errorf("no ledger entries reference incident %s", target.ID)
	}

	body, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding the bundle: %w", err)
	}
	body = append(body, '\n')

	if outPath != "" {
		if dir := filepath.Dir(outPath); dir != "." && dir != "" {
			if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
				return mkErr
			}
		}
		if wErr := os.WriteFile(outPath, body, 0o644); wErr != nil {
			return wErr
		}
	}

	if g.jsonOut && outPath == "" {
		_, err = out.Write(body)
		return err
	}

	tw := newTable(out)
	fmt.Fprintf(tw, "payment\t%s\n", bundle.PaymentID)
	fmt.Fprintf(tw, "incident\t%s\n", bundle.IncidentID)
	fmt.Fprintf(tw, "entries proved\t%d\n", len(bundle.Ledger.Entries))
	fmt.Fprintf(tw, "ledger size\t%d entries\n", bundle.Ledger.TreeSize)
	fmt.Fprintf(tw, "path length\t%d sibling hashes\n", len(bundle.Ledger.Entries[0].Proof.Path))
	fmt.Fprintf(tw, "merkle root\t%s\n", bundle.Ledger.MerkleRoot)
	fmt.Fprintf(tw, "bundle size\t%d bytes\n", len(body))
	if outPath != "" {
		fmt.Fprintf(tw, "written to\t%s\n", outPath)
	}
	fmt.Fprintf(tw, "note\tcheckable offline, and it discloses no other payment\n")
	return tw.Flush()
}
