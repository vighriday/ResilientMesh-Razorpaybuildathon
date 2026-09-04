//go:build race

package modelcheck

// raceEnabled reports whether the race detector is compiled in. See the
// !race build of this file for why the distinction is made at all.
const raceEnabled = true
