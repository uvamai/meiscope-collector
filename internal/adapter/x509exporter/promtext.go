package x509exporter

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// sample is one sample of the Prometheus text exposition format (0.0.4).
type sample struct {
	name   string
	labels map[string]string
	value  float64
}

// maxSamples bounds the samples read from one scrape.
const maxSamples = 500000

// parseText parses the Prometheus text format, keeping only samples whose
// name is in keep. Malformed lines are counted, not fatal.
func parseText(b []byte, keep map[string]bool) ([]sample, int, error) {
	var out []sample
	bad := 0
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		name, rest := metricName(line)
		if name == "" {
			bad++
			continue
		}
		if !keep[name] {
			continue
		}
		s, err := parseSample(name, rest)
		if err != nil {
			bad++
			continue
		}
		if len(out) == maxSamples {
			return nil, bad, fmt.Errorf("more than %d samples", maxSamples)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, bad, err
	}
	return out, bad, nil
}

func metricName(line string) (string, string) {
	i := 0
	for i < len(line) {
		c := line[i]
		if c == '_' || c == ':' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	return line[:i], line[i:]
}

var errSyntax = errors.New("syntax")

func parseSample(name, rest string) (sample, error) {
	s := sample{name: name, labels: map[string]string{}}
	if strings.HasPrefix(rest, "{") {
		var err error
		rest, err = parseLabels(rest[1:], s.labels)
		if err != nil {
			return s, err
		}
	}
	fields := strings.Fields(rest)
	if len(fields) < 1 || len(fields) > 2 {
		return s, errSyntax
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return s, errSyntax
	}
	s.value = v
	return s, nil
}

// parseLabels parses `a="x",b="y"}` and returns what follows the brace.
func parseLabels(s string, into map[string]string) (string, error) {
	for {
		s = strings.TrimLeft(s, " \t")
		if strings.HasPrefix(s, "}") {
			return s[1:], nil
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			return "", errSyntax
		}
		key := strings.TrimSpace(s[:eq])
		s = strings.TrimLeft(s[eq+1:], " \t")
		if !strings.HasPrefix(s, `"`) {
			return "", errSyntax
		}
		var val strings.Builder
		i := 1
		closed := false
		for i < len(s) {
			c := s[i]
			if c == '\\' && i+1 < len(s) {
				switch s[i+1] {
				case 'n':
					val.WriteByte('\n')
				case '\\', '"':
					val.WriteByte(s[i+1])
				default:
					val.WriteByte('\\')
					val.WriteByte(s[i+1])
				}
				i += 2
				continue
			}
			if c == '"' {
				closed = true
				i++
				break
			}
			val.WriteByte(c)
			i++
		}
		if !closed {
			return "", errSyntax
		}
		into[key] = val.String()
		s = strings.TrimLeft(s[i:], " \t")
		s = strings.TrimPrefix(s, ",")
	}
}
