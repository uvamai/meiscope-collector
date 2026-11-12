package scanexport

import (
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
)

// Tenable export: the CSV export of Nessus, Tenable Vulnerability
// Management or Tenable Security Center scan results. Certificate rows are
// plugin 10863 "SSL Certificate Information", whose Plugin Output prints the
// certificate (subject, issuer, serial, validity, key, fingerprints).
const (
	TenableName   = "tenable"
	TenableSource = "tenable"
	// TenablePlugin is the certificate information plugin.
	TenablePlugin = "10863"
)

func init() {
	register(format{
		name:    TenableName,
		source:  TenableSource,
		summary: "certificates from Tenable (Nessus, Tenable VM, Tenable.sc) CSV exports, plugin 10863",
		header: func(c map[string]int) bool {
			_, plugin := c["plugin id"]
			_, plugin2 := c["plugin"]
			_, out := c["plugin output"]
			_, out2 := c["plugin text"]
			_, port := c["port"]
			return (plugin || plugin2) && (out || out2) && port
		},
		row: tenableRow,
	})
}

func tenableRow(get func(...string) string) (rowResult, string) {
	if get("Plugin ID", "Plugin") != TenablePlugin {
		return rowResult{}, StatOtherChecks
	}
	r := rowResult{
		host:    get("Host", "IP Address", "IP"),
		dnsName: get("DNS Name", "FQDN"),
		check:   TenablePlugin,
		cert:    parseTenableOutput(get("Plugin Output", "Plugin Text")),
	}
	p, err := strconv.Atoi(get("Port"))
	if err != nil {
		return rowResult{}, StatBadPort
	}
	r.port = p
	return r, ""
}

var tenableAttrs = map[string]string{
	"common name": "CN", "organization unit": "OU", "organizational unit": "OU", "organization": "O",
	"locality": "L", "state/province": "ST", "state": "ST", "country": "C",
}

// parseTenableOutput reads the Plugin Output of plugin 10863, for example
//
//	Subject Name:
//	Common Name: www.example.test
//	Issuer Name:
//	Organization: Synthetic Test
//	Serial Number: 2A 01
//	Not Valid After: Nov 30 00:00:00 2026 GMT
//	SHA-1 Fingerprint: 89 43 ...
//
// Only the first certificate is read (the output describes the server's
// leaf certificate).
func parseTenableOutput(s string) certFields {
	c := newCertFields()
	section := ""
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch key {
		case "subject name":
			section = "subject"
			continue
		case "issuer name":
			section = "issuer"
			continue
		case "public key info", "extensions", "extension", "fingerprints", "signature":
			section = key
			continue
		case "serial number":
			if c.serial == "" {
				c.serial = adapter.NormalizeHexSerial(val)
				c.seen = c.seen || c.serial != ""
			}
			section = ""
			continue
		case "signature algorithm":
			if c.sigAlg == "" {
				c.sigAlg = val
			}
			continue
		case "not valid before":
			c.notBefore = parseTime(val)
			continue
		case "not valid after":
			c.notAfter = parseTime(val)
			c.seen = c.seen || c.notAfter != nil
			continue
		case "sha-1 fingerprint":
			c.sha1 = adapter.NormalizeFingerprint(val, 20)
			c.seen = c.seen || c.sha1 != ""
			continue
		case "sha-256 fingerprint":
			c.sha256 = adapter.NormalizeFingerprint(val, 32)
			continue
		case "dns", "dns name":
			if section == "extensions" || section == "extension" {
				c.dnsNames = append(c.dnsNames, strings.ToLower(val))
			}
			continue
		}
		switch section {
		case "subject", "issuer":
			if attr, ok := tenableAttrs[key]; ok && val != "" {
				if section == "subject" {
					c.subject[attr] = val
				} else {
					c.issuer[attr] = val
				}
				c.seen = true
			}
		case "public key info":
			switch key {
			case "algorithm":
				c.keyAlg = val
			case "key length":
				c.keyBits = keyLength(val)
			}
		}
	}
	return c
}
