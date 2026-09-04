// Package testsecret composes credential-shaped fixtures at run time.
//
// Tests for redaction, gateway authentication and DSN parsing need values
// shaped exactly like real credentials, or they assert nothing. Writing those
// shapes as source literals puts strings in the repository that no secret
// scanner can distinguish from a genuine leak. The usual escape is to teach the
// scanner to skip test files — but test files are among the likeliest places
// for a working key to be pasted "just to see it run", so a scanner with that
// exemption is not a scanner.
//
// The shapes are therefore assembled from fragments here. `git grep rzp_live_`
// or a search for a credentialed connection string over this tree stays a true
// positive, and the fixtures stay as realistic as the assertions require.
//
// Nothing in this package is secret. Every value is synthetic, deterministic,
// and inert: the key ids address no account and the DSNs address no host that
// exists outside a test process. The package is imported only from _test files,
// so it links into no shipped binary.
package testsecret

// Scheme fragments. A URL scheme on its own carries no credential, so these are
// safe as literals; it is the userinfo that follows which must never be written
// beside one.
const (
	// PG is the postgres URL prefix, exported so a DSN fixture can be written
	// as PG + "user:pass@host/db" and stay readable at the call site.
	PG = "postgres" + "://"
	// PGX is the alternate scheme libpq accepts, needed because a redactor that
	// only handled one of the two would leak the other.
	PGX = "postgresql" + "://"
	// Redis is the redis URL prefix.
	Redis = "redis" + "://"
)

// Fragments of the Razorpay key format, split so that no contiguous literal in
// this file matches a scanner pattern either.
const (
	keyPrefix  = "rzp"
	liveMarker = "live"
	testMarker = "test"
)

// LiveKeyID returns a value shaped like a production Razorpay key id.
//
// Used where a test must prove that a production-shaped key is redacted,
// rejected or never logged. Callers pass their own suffix so two tests cannot
// silently assert against the same fixture.
func LiveKeyID(suffix string) string {
	return keyPrefix + "_" + liveMarker + "_" + suffix
}

// TestKeyID returns a value shaped like a sandbox Razorpay key id.
func TestKeyID(suffix string) string {
	return keyPrefix + "_" + testMarker + "_" + suffix
}

// TestKeyPrefix returns the sandbox key prefix, for tests asserting that
// configuration refuses a key from the wrong environment.
func TestKeyPrefix() string {
	return keyPrefix + "_" + testMarker + "_"
}

// LiveKeyPrefix returns the production key prefix.
func LiveKeyPrefix() string {
	return keyPrefix + "_" + liveMarker + "_"
}

// PostgresDSN builds a URL-form DSN carrying a username and password.
//
// query is appended after "?" when non-empty. The parts are taken separately
// rather than as one string so that the credential never exists as a literal in
// the calling test either.
func PostgresDSN(user, password, hostport, database, query string) string {
	dsn := PG + user + ":" + password + "@" + hostport + "/" + database
	if query != "" {
		dsn += "?" + query
	}
	return dsn
}
