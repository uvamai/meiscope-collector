// Package submittest provides a fake core for tests: it serves POST
// /collector/v1/observations, validating every request body against the
// vendored api/collector.yaml, and GET /collector/v1/owned-domains.
package submittest

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Spec is a loaded OpenAPI document with a JSON Schema validator for the
// subset of keywords collector.yaml uses. An unknown validation keyword is
// an error, so a schema change the validator does not understand fails the
// tests instead of being skipped.
type Spec struct {
	schemas map[string]any
}

// LoadSpec reads an OpenAPI YAML file.
func LoadSpec(path string) (*Spec, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	if len(schemas) == 0 {
		return nil, fmt.Errorf("%s: no components.schemas", path)
	}
	return &Spec{schemas: schemas}, nil
}

// Validate checks a JSON document against components.schemas[name].
func (s *Spec) Validate(name string, doc []byte) error {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	sch, ok := s.schemas[name]
	if !ok {
		return fmt.Errorf("no schema %q", name)
	}
	return s.validate(sch, v, "$")
}

var annotations = map[string]bool{
	"description": true, "title": true, "example": true, "examples": true,
	"default": true, "deprecated": true, "readOnly": true, "writeOnly": true,
}

func (s *Spec) validate(schema, v any, path string) error {
	sch, ok := schema.(map[string]any)
	if !ok {
		return fmt.Errorf("%s: schema is not an object", path)
	}
	if ref, ok := sch["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/schemas/")
		target, ok := s.schemas[name]
		if !ok {
			return fmt.Errorf("%s: unresolved $ref %s", path, ref)
		}
		return s.validate(target, v, path)
	}
	keys := make([]string, 0, len(sch))
	for k := range sch {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := s.keyword(sch, k, v, path); err != nil {
			return err
		}
	}
	return nil
}

// keyword applies one schema keyword to v.
func (s *Spec) keyword(sch map[string]any, k string, v any, path string) error {
	val := sch[k]
	switch k {
	case "type":
		return checkType(val.(string), v, path)
	case "required":
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		for _, r := range val.([]any) {
			if _, ok := obj[r.(string)]; !ok {
				return fmt.Errorf("%s: missing required property %q", path, r)
			}
		}
	case "properties":
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		props := val.(map[string]any)
		for name, pv := range obj {
			if ps, ok := props[name]; ok {
				if err := s.validate(ps, pv, path+"."+name); err != nil {
					return err
				}
			}
		}
	case "additionalProperties":
		obj, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		if b, ok := val.(bool); ok && !b {
			props, _ := sch["properties"].(map[string]any)
			for name := range obj {
				if _, ok := props[name]; !ok {
					return fmt.Errorf("%s: additional property %q not allowed", path, name)
				}
			}
			return nil
		}
		return fmt.Errorf("%s: unsupported additionalProperties %v", path, val)
	case "items":
		arr, ok := v.([]any)
		if !ok {
			return nil
		}
		for i, it := range arr {
			if err := s.validate(val, it, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case "minItems", "maxItems":
		arr, ok := v.([]any)
		if !ok {
			return nil
		}
		n := toInt(val)
		if (k == "minItems" && len(arr) < n) || (k == "maxItems" && len(arr) > n) {
			return fmt.Errorf("%s: %d items violates %s %d", path, len(arr), k, n)
		}
	case "minLength", "maxLength":
		str, ok := v.(string)
		if !ok {
			return nil
		}
		n, l := toInt(val), utf8.RuneCountInString(str)
		if (k == "minLength" && l < n) || (k == "maxLength" && l > n) {
			return fmt.Errorf("%s: length %d violates %s %d", path, l, k, n)
		}
	case "minimum", "maximum":
		num, ok := v.(json.Number)
		if !ok {
			return nil
		}
		f, _ := new(big.Float).SetString(num.String())
		lim := new(big.Float).SetInt64(int64(toInt(val)))
		if c := f.Cmp(lim); (k == "minimum" && c < 0) || (k == "maximum" && c > 0) {
			return fmt.Errorf("%s: %s violates %s %v", path, num, k, val)
		}
	case "pattern":
		str, ok := v.(string)
		if !ok {
			return nil
		}
		if !regexp.MustCompile(val.(string)).MatchString(str) {
			return fmt.Errorf("%s: %q does not match %s", path, str, val)
		}
	case "enum":
		for _, e := range val.([]any) {
			if fmt.Sprint(e) == fmt.Sprint(v) {
				return nil
			}
		}
		return fmt.Errorf("%s: %v not in enum %v", path, v, val)
	case "const":
		if fmt.Sprint(val) != fmt.Sprint(v) {
			return fmt.Errorf("%s: %v is not %v", path, v, val)
		}
	case "format":
		return checkFormat(val.(string), v, path)
	case "allOf":
		for i, sub := range val.([]any) {
			if err := s.validate(sub, v, fmt.Sprintf("%s(allOf %d)", path, i)); err != nil {
				return err
			}
		}
	case "if":
		if s.validate(val, v, path) == nil {
			if then, ok := sch["then"]; ok {
				return s.validate(then, v, path)
			}
		} else if els, ok := sch["else"]; ok {
			return s.validate(els, v, path)
		}
	case "then", "else":
		// Evaluated with "if".
	default:
		if !annotations[k] {
			return fmt.Errorf("%s: validator does not support keyword %q", path, k)
		}
	}
	return nil
}

func checkType(t string, v any, path string) error {
	ok := false
	switch t {
	case "object":
		_, ok = v.(map[string]any)
	case "array":
		_, ok = v.([]any)
	case "string":
		_, ok = v.(string)
	case "boolean":
		_, ok = v.(bool)
	case "number":
		_, ok = v.(json.Number)
	case "integer":
		if n, isNum := v.(json.Number); isNum {
			_, err := n.Int64()
			ok = err == nil
		}
	default:
		return fmt.Errorf("%s: unsupported type %q", path, t)
	}
	if !ok {
		return fmt.Errorf("%s: %v is not of type %s", path, v, t)
	}
	return nil
}

func checkFormat(f string, v any, path string) error {
	str, ok := v.(string)
	if !ok {
		return nil
	}
	switch f {
	case "byte":
		if _, err := base64.StdEncoding.DecodeString(str); err != nil {
			return fmt.Errorf("%s: not base64: %w", path, err)
		}
	case "date-time":
		if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
			return fmt.Errorf("%s: not date-time: %w", path, err)
		}
	default:
		return fmt.Errorf("%s: unsupported format %q", path, f)
	}
	return nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	panic(fmt.Sprintf("not a number: %v", v))
}
