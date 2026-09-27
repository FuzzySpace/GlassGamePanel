package wings

import (
	"errors"
	"strings"
)

const (
	// MaxWriteBytes is the largest archive PUT /files/content will read
	// or send to Wings. It covers a mod jar such as fabric-api without
	// accepting an unbounded body.
	MaxWriteBytes = 32 << 20
)

// ErrPathPolicy means the path is outside the mod volume policy.
// Callers must not dial Wings for this path.
var ErrPathPolicy = errors.New("path outside volume policy")

var zipLocalHeader = []byte{0x50, 0x4b, 0x03, 0x04}

// ModArchive reports whether b is a non-empty zip/jar local-file payload
// within MaxWriteBytes. A shell script renamed to .jar is refused.
func ModArchive(b []byte) bool {
	return len(b) >= 30 && len(b) <= MaxWriteBytes && hasPrefix(b, zipLocalHeader)
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// CleanVolumeFile accepts a server-volume path under mods/ or plugins/
// whose final segment is a .jar or .zip. It returns the Wings file path
// with a single leading slash. It refuses traversal, host paths, and
// unit/systemd paths. It does not call path.Clean, so ".." is never resolved.
func CleanVolumeFile(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 512 {
		return "", ErrPathPolicy
	}
	if strings.Contains(raw, "..") || strings.Contains(raw, "//") || strings.Contains(raw, `\`) || strings.Contains(raw, ":") {
		return "", ErrPathPolicy
	}
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == '-', c == '/':
		default:
			return "", ErrPathPolicy
		}
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "systemd") {
		return "", ErrPathPolicy
	}
	switch {
	case strings.HasSuffix(lower, ".service"),
		strings.HasSuffix(lower, ".socket"),
		strings.HasSuffix(lower, ".mount"),
		strings.HasSuffix(lower, ".timer"),
		strings.HasSuffix(lower, ".target"),
		strings.HasSuffix(lower, ".slice"),
		strings.HasSuffix(lower, ".scope"),
		strings.HasSuffix(lower, ".device"),
		strings.HasSuffix(lower, ".automount"),
		strings.HasSuffix(lower, ".swap"):
		return "", ErrPathPolicy
	}
	if strings.HasPrefix(raw, "/") {
		if strings.HasPrefix(raw, "//") || strings.Count(raw, "/") < 2 {
			return "", ErrPathPolicy
		}
	}
	trimmed := strings.TrimLeft(raw, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) < 2 {
		return "", ErrPathPolicy
	}
	switch parts[0] {
	case "mods", "plugins":
	default:
		return "", ErrPathPolicy
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.Contains(strings.ToLower(p), "systemd") {
			return "", ErrPathPolicy
		}
	}
	base := parts[len(parts)-1]
	ext := extOf(base)
	if ext != ".jar" && ext != ".zip" {
		return "", ErrPathPolicy
	}
	stem := base[:len(base)-len(ext)]
	if stem == "" || strings.HasPrefix(stem, ".") {
		return "", ErrPathPolicy
	}
	return "/" + strings.Join(parts, "/"), nil
}

func extOf(name string) string {
	i := strings.LastIndex(name, ".")
	if i <= 0 {
		return ""
	}
	return strings.ToLower(name[i:])
}
