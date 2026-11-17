// Package platform holds the collector's cross-cutting plumbing: build
// information, configuration, logging and the health endpoint.
package platform

// Build information. Release builds set these with -ldflags -X; see Taskfile.yml.
var (
	Version = "dev"
	Commit  = "none"
	// Package is how this binary was packaged: deb, rpm or container. Only
	// the package build sets it; a binary built by hand has none and cannot
	// enrol (the core binds a code to the package).
	Package = ""
)
