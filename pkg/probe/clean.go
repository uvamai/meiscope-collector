package probe

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxStringLen caps any single string taken from a certificate or a server.
const MaxStringLen = 256

// Clean returns s with invalid UTF-8, control, format (including bidi
// overrides) and private-use characters replaced by U+FFFD, truncated to
// MaxStringLen runes. Server and certificate text is untrusted data; callers
// that show it to people or agents pass it through Clean first.
func Clean(s string) string {
	var b strings.Builder
	n := 0
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		if n == MaxStringLen {
			b.WriteString("…[truncated]")
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Co) {
			r = utf8.RuneError
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
