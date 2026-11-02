// Command pcapcheck checks a packet capture of a probe run (tcpdump -w):
// for every TCP stream to the given server ports, the client must send
// nothing after the server's certificate except one alert (see
// internal/wirecheck). It prints one line per stream and exits 1 on any
// violation, or when fewer than -min-tls streams started TLS.
//
//	pcapcheck -min-tls 12 zoo.pcap 15432 13306 ...
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/uvamai/meiscope-collector/internal/wirecheck"
)

func main() {
	minTLS := flag.Int("min-tls", 1, "fail unless at least this many streams started TLS")
	flag.Parse()
	if flag.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "usage: pcapcheck [-min-tls N] FILE.pcap PORT...")
		os.Exit(2)
	}
	var ports []int
	for _, a := range flag.Args()[1:] {
		p, err := strconv.Atoi(a)
		if err != nil {
			fmt.Fprintf(os.Stderr, "port %q: %v\n", a, err)
			os.Exit(2)
		}
		ports = append(ports, p)
	}
	b, err := os.ReadFile(filepath.Clean(flag.Arg(0)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	streams, err := wirecheck.ReadStreams(bytes.NewReader(b), ports)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bad, tlsStreams := 0, 0
	for _, s := range streams {
		r, err := wirecheck.CheckClient(s.Bytes)
		status := "ok"
		if err != nil {
			status, bad = "VIOLATION: "+err.Error(), bad+1
		}
		if r.TLS {
			tlsStreams++
		}
		fmt.Printf("%-22s -> %-16s pre-TLS %4d bytes, client TLS records %v: %s\n", s.Client, s.Server, r.PreTLS, r.Records, status)
	}
	fmt.Printf("%d streams, %d started TLS, %d violations\n", len(streams), tlsStreams, bad)
	if bad > 0 || tlsStreams < *minTLS {
		if tlsStreams < *minTLS {
			fmt.Printf("expected at least %d TLS streams\n", *minTLS)
		}
		os.Exit(1)
	}
}
