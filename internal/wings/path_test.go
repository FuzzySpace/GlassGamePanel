package wings

import (
	"strings"
	"testing"
)

func TestCleanVolumeFileAllowsModJar(t *testing.T) {
	got, err := CleanVolumeFile("mods/fabric-api.jar")
	if err != nil || got != "/mods/fabric-api.jar" {
		t.Fatalf("got %q err %v", got, err)
	}
	again, err := CleanVolumeFile(got)
	if err != nil || again != got {
		t.Fatalf("not idempotent %q %v", again, err)
	}
	got, err = CleanVolumeFile("/plugins/Vault.zip")
	if err != nil || got != "/plugins/Vault.zip" {
		t.Fatalf("plugins %q %v", got, err)
	}
	got, err = CleanVolumeFile("mods/subdir/pack.JAR")
	if err != nil || got != "/mods/subdir/pack.JAR" {
		t.Fatalf("nested %q %v", got, err)
	}
}

func TestCleanVolumeFileRefusesEscapeAndHostPaths(t *testing.T) {
	refused := []string{
		"",
		"/",
		"mods",
		"mods/",
		"../mods/fabric-api.jar",
		"mods/../../etc/passwd",
		"/mods/../../etc/passwd",
		"plugins/../mods/fabric-api.jar",
		"/etc/passwd",
		"/etc/systemd/system/panel.service",
		"/lib/systemd/system/foo.service",
		"/usr/lib/systemd/system/foo.service",
		"/usr/bin/bash",
		"//etc/passwd",
		"//mods/fabric-api.jar",
		`mods\..\..\etc\passwd`,
		"C:/mods/fabric-api.jar",
		"/server.properties",
		"server.properties",
		"mods/fabric-api.txt",
		"mods/install.sh",
		"mods/evil.service",
		"mods/run.bash",
		"plugins/foo.socket",
		"mods/.hidden.jar",
		"mods/.jar",
		"Mods/fabric-api.jar",
		"mods/foo.jar/../../etc/passwd",
		"mods/foo bar.jar",
		"mods/foo%2e%2e/x.jar",
		"mods/systemd-plugin.jar",
		"/var/lib/systemd/foo.jar",
		"/root/mods/fabric-api.jar",
		"/tmp/mods/fabric-api.jar",
		"opt/mods/fabric-api.jar",
	}
	for _, raw := range refused {
		if _, err := CleanVolumeFile(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if _, err := CleanVolumeFile(strings.Repeat("a", 513)); err == nil {
		t.Fatal("accepted overlong path")
	}
}

func TestModArchive(t *testing.T) {
	ok := append([]byte{0x50, 0x4b, 0x03, 0x04}, make([]byte, 26)...)
	if !ModArchive(ok) {
		t.Fatal("zip header refused")
	}
	if ModArchive(nil) || ModArchive([]byte("#!/bin/bash\n")) || ModArchive([]byte{0x50, 0x4b, 0x03, 0x04}) {
		t.Fatal("non-archive accepted")
	}
	over := make([]byte, MaxWriteBytes+1)
	copy(over, []byte{0x50, 0x4b, 0x03, 0x04})
	if ModArchive(over) {
		t.Fatal("oversize archive accepted")
	}
}
