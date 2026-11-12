package scope

import (
	"errors"
	"strings"
	"testing"
)

// TestDenyEntriesValidated: every Policy.Deny entry must be one the runner
// understands; one unparseable entry refuses the whole scope, so an
// exclusion is never silently dropped.
func TestDenyEntriesValidated(t *testing.T) {
	pub, priv := keys(t)
	verify := func(deny ...string) error {
		s := validScope()
		s.Policy.Deny = deny
		_, err := Verify(sign(t, priv, s), pub, now)
		return err
	}
	if err := verify("192.0.2.7", "198.51.100.0/24", "2001:db8::/32", "2001:db8::1", "::ffff:192.0.2.9",
		"mail.example.test", ".corp.example.test", "Payroll.Example.Test.", "localhost", "10.0.0.1/8"); err != nil {
		t.Fatalf("valid deny list refused: %v", err)
	}
	for name, entry := range map[string]string{
		"empty":            "",
		"blank":            "   ",
		"bad cidr":         "192.0.2.0/33",
		"cidr of a name":   "example.test/24",
		"wildcard":         "*.example.test",
		"bracketed v6":     "[2001:db8::1]",
		"zoned v6":         "fe80::1%eth0",
		"ip with port":     "192.0.2.1:443",
		"url":              "https://example.test",
		"range":            "192.0.2.1-192.0.2.9",
		"short range":      "192.0.2.1-9",
		"truncated ip":     "192.0.2",
		"list in one":      "a.example.test,b.example.test",
		"space inside":     "a example.test",
		"double dot":       "..example.test",
		"label too long":   strings.Repeat("a", 64) + ".test",
		"unicode":          "bücher.example",
		"trailing garbage": "192.0.2.1;rm",
	} {
		err := verify("192.0.2.7", entry)
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "deny entry 1") {
			t.Errorf("%s (%q): got %v, want ErrInvalid naming deny entry 1", name, entry, err)
		}
	}
}
