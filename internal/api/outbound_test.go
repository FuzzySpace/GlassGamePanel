package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestNoOutboundClients(t *testing.T) {
	root := moduleRoot(t)
	banned := []string{
		"http.Client",
		"http.Get(",
		"http.Post(",
		"http.Head(",
		"net.Dial(",
		"DialContext(",
		"websocket.DefaultDialer",
		"exec.Command(",
		".Dispatch(",
		"10.10.1.43",
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(b)
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, s := range banned {
			if s == "http.Client" && (rel == "internal/auth/jwks.go" || rel == "internal/ptero/client.go" || rel == "internal/wings/client.go") {
				continue
			}
			// Noop.Dispatch is the illegal counter. The real path dials through internal/wings.
			if s == ".Dispatch(" && strings.HasPrefix(rel, "internal/executor/") {
				continue
			}
			if strings.Contains(text, s) {
				t.Errorf("%s contains %q", rel, s)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	jwksPath := filepath.Join(root, "internal", "auth", "jwks.go")
	b, err := os.ReadFile(jwksPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if !strings.Contains(text, "http.Client") {
		t.Fatal("jwks verifier must use an HTTP client for the Portal JWKS GET")
	}
	for _, s := range []string{"wings", "pterodactyl", "stripe", "whmcs", ".Dispatch(", "10.10.1.43"} {
		if strings.Contains(strings.ToLower(text), s) {
			t.Fatalf("jwks client mentions %q", s)
		}
	}
	pteroPath := filepath.Join(root, "internal", "ptero", "client.go")
	pb, err := os.ReadFile(pteroPath)
	if err != nil {
		t.Fatal(err)
	}
	pteroText := string(pb)
	if !strings.Contains(pteroText, "http.Client") || !strings.Contains(pteroText, "http.MethodGet") {
		t.Fatal("source application client must GET with an HTTP client")
	}
	for _, s := range []string{"http.MethodPost", "http.MethodPut", "http.MethodPatch", "http.MethodDelete", ".Dispatch(", "http.Get(", "http.Post("} {
		if strings.Contains(pteroText, s) {
			t.Fatalf("source application client contains %q", s)
		}
	}
	wingsPath := filepath.Join(root, "internal", "wings", "client.go")
	wb, err := os.ReadFile(wingsPath)
	if err != nil {
		t.Fatal(err)
	}
	wingsText := string(wb)
	if !strings.Contains(wingsText, "http.Client") || !strings.Contains(wingsText, "http.MethodPost") || !strings.Contains(wingsText, "CheckRedirect") || !strings.Contains(wingsText, "Proxy: nil") {
		t.Fatal("wings daemon client must POST with an HTTP client that rejects redirects and proxies")
	}
	for _, s := range []string{"http.Get(", "http.Post(", ".Dispatch("} {
		if strings.Contains(wingsText, s) {
			t.Fatalf("wings daemon client contains %q", s)
		}
	}
}
