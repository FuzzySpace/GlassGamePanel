package freewingstest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRefuseFixtures(t *testing.T) {
	root := moduleRoot(t)
	script := filepath.Join(root, "packaging", "free", "tests", "refuse_unowned_servers.sh")
	cmd := exec.Command("bash", script)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("free wings refuse fixtures: %v\n%s", err, out)
	}
}

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
