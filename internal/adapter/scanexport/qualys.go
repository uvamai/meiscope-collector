package scanexport

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/uvamai/meiscope-collector/internal/adapter"
)

// Qualys export: the CSV scan report of Qualys VMDR (VM scan results).
// Certificate rows are QID 86002 "SSL Certificate - Information", whose
// Results column prints the server's certificates as OpenSSL-style
// "(n)name<TAB>value" lines, n being the certificate's position in the
// chain (0 is the leaf).
const (
	QualysName   = "qualys"
	QualysSource = "qualys"
	// QualysQID is the certificate information QID.
	QualysQID = "86002"
)

func init() {
	register(format{
		name:    QualysName,
		source:  QualysSource,
		summary: "certificates from Qualys VMDR scan report CSV exports, QID 86002",
		header: func(c map[string]int) bool {
			_, qid := c["qid"]
			_, res := c["results"]
			_, ip := c["ip"]
			_, port := c["port"]
			return qid && res && ip && port
		},
		row: qualysRow,
	})
}

func qualysRow(get func(...string) string) (rowResult, string) {
	if get("QID") != QualysQID {
		return rowResult{}, StatOtherChecks
	}
	r := rowResult{
		host:    get("IP"),
		dnsName: get("DNS", "FQDN"),
		check:   QualysQID,
		cert:    parseQualysResults(get("Results")),
	}
	p, err := strconv.Atoi(get("Port"))
	if err != nil {
		return rowResult{}, StatBadPort
	}
	r.port = p
	return r, ""
}

var (
	qualysIndex  = regexp.MustCompile(`^\((\d+)\)`)
	qualysSerial = regexp.MustCompile(`\(0x([0-9a-fA-F]+)\)`)
	qualysAttrs  = map[string]string{
		"commonname": "CN", "organizationalunitname": "OU", "organizationname": "O",
		"localityname": "L", "stateorprovincename": "ST", "countryname": "C",
	}
)

// parseQualysResults reads the leaf certificate (index 0) of a QID 86002
// Results cell.
func parseQualysResults(s string) certFields {
	c := newCertFields()
	section := ""
	idx := "0"
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if m := qualysIndex.FindStringSubmatch(line); m != nil {
			idx = m[1]
			line = line[len(m[0]):]
		}
		if idx != "0" {
			continue
		}
		var k, v string
		if i := strings.IndexByte(line, '\t'); i >= 0 {
			k, v = line[:i], line[i+1:]
		} else {
			k = line
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch {
		case key == "issuer name":
			section = "issuer"
			continue
		case key == "subject name":
			section = "subject"
			continue
		case strings.HasPrefix(key, "certificate ") || strings.HasPrefix(key, "x509v3"):
			if strings.Contains(key, "subject alternative name") {
				c.dnsNames = append(c.dnsNames, splitDNSNames(val)...)
			}
			section = ""
			continue
		case key == "serial number":
			if m := qualysSerial.FindStringSubmatch(val); m != nil {
				val = m[1]
			}
			c.serial = adapter.NormalizeHexSerial(val)
			c.seen = c.seen || c.serial != ""
			section = ""
			continue
		case key == "signature algorithm":
			if c.sigAlg == "" {
				c.sigAlg = val
			}
			section = ""
			continue
		case key == "valid from":
			c.notBefore = parseTime(val)
			section = ""
			continue
		case key == "valid till":
			c.notAfter = parseTime(val)
			c.seen = c.seen || c.notAfter != nil
			section = ""
			continue
		case key == "public key algorithm":
			c.keyAlg = val
			section = ""
			continue
		case strings.HasSuffix(key, "public key") && strings.Contains(val, "bit"):
			c.keyBits = keyLength(val)
			continue
		case strings.Contains(key, "fingerprint") && (strings.Contains(key, "sha1") || strings.Contains(key, "sha-1")):
			c.sha1 = adapter.NormalizeFingerprint(val, 20)
			c.seen = c.seen || c.sha1 != ""
			continue
		case strings.Contains(key, "fingerprint") && (strings.Contains(key, "sha256") || strings.Contains(key, "sha-256")):
			c.sha256 = adapter.NormalizeFingerprint(val, 32)
			continue
		}
		if attr, ok := qualysAttrs[strings.ReplaceAll(key, " ", "")]; ok && val != "" && section != "" {
			if section == "subject" {
				c.subject[attr] = val
			} else {
				c.issuer[attr] = val
			}
			c.seen = true
		}
	}
	return c
}
