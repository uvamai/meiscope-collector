// Package tlsguard holds only a test: it fails the build if any Go file
// outside pkg/probe weakens TLS (InsecureSkipVerify, or a MinVersion or
// version constant below TLS 1.2). pkg/probe is the one exception: its
// connection is inspection-only (founder decision, 2 Nov 2026; the CodeQL
// alerts on it are dismissed with that reason).
package tlsguard
