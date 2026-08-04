// Package buildinfo carries build-time metadata injected via -ldflags.
package buildinfo

// Injected at build time by the Makefile. Defaults apply to `go build` and
// `go run` invocations that bypass it.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String returns a single-line build identifier.
func String() string {
	return Version + " (" + Commit + ", built " + Date + ")"
}
