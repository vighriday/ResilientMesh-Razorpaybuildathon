//go:build !race

package modelcheck

// raceEnabled reports whether the race detector is compiled in. The exploration
// is single-goroutine by construction, so the detector observes nothing here
// and only multiplies the cost of the sweep; the heavy tests use this to run a
// bounded exploration under -race and the exhaustive one everywhere else.
const raceEnabled = false
