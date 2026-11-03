package tlsguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allowedDir is the only place weak TLS settings may appear.
const allowedDir = "pkg/probe"

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// findings lists weak TLS settings in src (one Go file).
func findings(fset *token.FileSet, f *ast.File) []string {
	var out []string
	report := func(n ast.Node, what string) { out = append(out, fset.Position(n.Pos()).String()+": "+what) }
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.KeyValueExpr:
			if k, ok := x.Key.(*ast.Ident); ok {
				switch k.Name {
				case "InsecureSkipVerify":
					if v, ok := x.Value.(*ast.Ident); !ok || v.Name != "false" {
						report(x, "InsecureSkipVerify")
					}
				case "MinVersion":
					if !strongVersion(x.Value) {
						report(x, "MinVersion below TLS 1.2 (or not a TLS 1.2/1.3 constant)")
					}
				}
			}
		case *ast.AssignStmt:
			for i, l := range x.Lhs {
				if s, ok := l.(*ast.SelectorExpr); ok && i < len(x.Rhs) {
					switch s.Sel.Name {
					case "InsecureSkipVerify":
						if v, ok := x.Rhs[i].(*ast.Ident); !ok || v.Name != "false" {
							report(x, "InsecureSkipVerify")
						}
					case "MinVersion":
						if !strongVersion(x.Rhs[i]) {
							report(x, "MinVersion below TLS 1.2 (or not a TLS 1.2/1.3 constant)")
						}
					}
				}
			}
		}
		return true
	})
	return out
}

func strongVersion(e ast.Expr) bool {
	s, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	p, ok := s.X.(*ast.Ident)
	return ok && p.Name == "tls" && (s.Sel.Name == "VersionTLS12" || s.Sel.Name == "VersionTLS13")
}

func TestNoWeakTLSOutsideProbe(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var bad []string
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == allowedDir || strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		bad = append(bad, findings(fset, f)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 50 {
		t.Fatalf("only %d Go files scanned from %s; the walk is wrong", files, root)
	}
	for _, b := range bad {
		t.Errorf("weak TLS outside %s: %s", allowedDir, b)
	}
}

// The guard itself must catch every form it claims to.
func TestGuardCatches(t *testing.T) {
	src := `package x
import "crypto/tls"
var a = &tls.Config{InsecureSkipVerify: true}
var b = &tls.Config{MinVersion: tls.VersionTLS11}
var c = &tls.Config{MinVersion: 0x0301}
var d = &tls.Config{MaxVersion: tls.VersionTLS11} // allowed: a legacy test server
var ok1 = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: false}
var ok2 = &tls.Config{MinVersion: tls.VersionTLS13}
func f(cfg *tls.Config, v bool) {
	cfg.InsecureSkipVerify = v
	cfg.MinVersion = tls.VersionSSL30
	cfg.MinVersion = tls.VersionTLS12
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := findings(fset, f)
	// a, b, c and the two bad assignments.
	if len(got) != 5 {
		t.Fatalf("%d findings, want 5:\n%s", len(got), strings.Join(got, "\n"))
	}
}
