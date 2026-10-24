// Package platform holds the collector's cross-cutting plumbing: build
// information, configuration, logging and the health endpoint.
package platform

// Build information. Release builds set these with -ldflags -X; see Taskfile.yml.
var (
	Version = "dev"
	Commit  = "none"
)
