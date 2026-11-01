package ct

import (
	"fmt"
	"io"
	"sort"
)

// Coverage compares what the collector found for a domain with crt.sh's
// list of unexpired certificates (the WP0.4 acceptance baseline: at least
// 95 % of names and certificates). Certificates are compared by serial
// number, because crt.sh merges a precertificate and its certificate into
// one row and both share the serial.
type Coverage struct {
	Domain        string
	BaselineCerts int
	CoveredCerts  int
	BaselineNames int
	CoveredNames  int
	MissingCerts  []string // serials (hex)
	MissingNames  []string
	// ExtraCerts are serials the collector found that crt.sh did not list.
	ExtraCerts int
}

// CertPercent is the share of baseline certificates found (100 when the
// baseline is empty).
func (c Coverage) CertPercent() float64 { return pct(c.CoveredCerts, c.BaselineCerts) }

// NamePercent is the share of baseline names found.
func (c Coverage) NamePercent() float64 { return pct(c.CoveredNames, c.BaselineNames) }

func pct(n, d int) float64 {
	if d == 0 {
		return 100
	}
	return 100 * float64(n) / float64(d)
}

// ComputeCoverage compares found with the crt.sh rows for one domain.
func ComputeCoverage(domain string, found []Found, baseline []CrtShEntry) Coverage {
	ds := Domains{normalizeName(domain)}
	gotSerials, gotNames := map[string]bool{}, map[string]bool{}
	for _, f := range found {
		if f.Serial != "" {
			gotSerials[f.Serial] = true
		}
		for _, n := range f.Evidence.DNSNames {
			if ds.Match(n) != "" {
				gotNames[n] = true
			}
		}
	}
	wantSerials, wantNames := map[string]bool{}, map[string]bool{}
	for _, r := range baseline {
		names := r.Names()
		matched := false
		for _, n := range names {
			if ds.Match(n) != "" {
				wantNames[n] = true
				matched = true
			}
		}
		if matched {
			wantSerials[normalizeSerial(r.SerialNumber)] = true
		}
	}
	cov := Coverage{Domain: ds[0], BaselineCerts: len(wantSerials), BaselineNames: len(wantNames)}
	for s := range wantSerials {
		if gotSerials[s] {
			cov.CoveredCerts++
		} else {
			cov.MissingCerts = append(cov.MissingCerts, s)
		}
	}
	for s := range gotSerials {
		if !wantSerials[s] {
			cov.ExtraCerts++
		}
	}
	for n := range wantNames {
		if gotNames[n] {
			cov.CoveredNames++
		} else {
			cov.MissingNames = append(cov.MissingNames, n)
		}
	}
	sort.Strings(cov.MissingCerts)
	sort.Strings(cov.MissingNames)
	return cov
}

// Write prints a human-readable report.
func (c Coverage) Write(w io.Writer) {
	fmt.Fprintf(w, "domain:        %s\n", c.Domain)
	fmt.Fprintf(w, "certificates:  %d of %d crt.sh baseline (%.1f %%), %d found that crt.sh did not list\n",
		c.CoveredCerts, c.BaselineCerts, c.CertPercent(), c.ExtraCerts)
	fmt.Fprintf(w, "names:         %d of %d crt.sh baseline (%.1f %%)\n", c.CoveredNames, c.BaselineNames, c.NamePercent())
	for _, s := range c.MissingCerts {
		fmt.Fprintf(w, "missing cert:  serial %s\n", s)
	}
	for _, n := range c.MissingNames {
		fmt.Fprintf(w, "missing name:  %s\n", n)
	}
}
