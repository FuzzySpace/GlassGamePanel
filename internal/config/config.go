package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/FuzzySpace/GlassGamePanel/internal/alloc"
)

const (
	DefaultListenAddr = "127.0.0.1:8080"
	DefaultJWTIss     = "https://portal-test.glasshosting.internal"
	DefaultJWTAud     = "https://panel-api-test.glasshosting.internal"
	// DefaultJWTJWKSURL is the TEST Portal JWKS. portal-test nginx returns 403 for /.well-known/*.
	DefaultJWTJWKSURL = "https://portal-test.glasshosting.internal/oidc/jwks.json"
	DefaultPublicBase = "https://panel-api-test.glasshosting.internal"
	MaxMutateRPM      = 60
	MaxReadRPM        = 300
	TestHost          = "panel-api-test.glasshosting.internal"
	ProdHost          = "panel-api.glasshosting.com"

	// Phase B hard ceiling. import and import_and_cutover are never accepted.
	MigrateModeInventoryOnly = "inventory_only"
	MigrateModeDryRun        = "dry_run"
	WingsExecutorNoop        = "noop"
	// WingsExecutorReal is accepted by this build. Unset stays noop.
	// Live TEST and prod must not set it without a later stamp.
	WingsExecutorReal = "real"
	// ManagedInventoryCHINodeID is the panel node that owns managed-inventory SIDs.
	// It must never appear in the create allowlist or the Wings allowlist.
	ManagedInventoryCHINodeID = "1"
)

// Config is the TEST runtime configuration. There is no prod mode.
type Config struct {
	Env           string
	ListenAddr    string
	JWTSecret     []byte
	JWTIss        string
	JWTAud        string
	JWTJWKSURL    string
	PublicBaseURL string
	MutateRPM     int
	ReadRPM       int

	// Phase B migrate dry_run. The token is read from the environment and is
	// never logged. An empty source URL keeps the in-process fixture path.
	MigrateDisabled     bool
	MigrateModeMax      string
	PteroSourceAPIURL   string
	PteroSourceAPIToken string

	// CreateNodeAllowlist is the non–managed-inventory TEST node ids server.create
	// may target. Empty means node 5. GLASSPANEL_CREATE_NODE_ID is the Portal
	// alias and must be a member when both are set.
	CreateNodeAllowlist []string
	// AllocPool is the named allocation pool SoT. Empty means tor-n5-ula-test.
	// GLASSPANEL_ALLOC_POOL is the Portal alias and must match when both are set.
	AllocPool string
	// WingsExecutor is noop unless PANEL_WINGS_EXECUTOR=real. Unset stays noop.
	// real dials only when WingsAllowlist names the target and the daemon
	// origin and token are both set. Both empty still boots; the allowlisted
	// call fails closed and does not report success.
	WingsExecutor string
	// WingsAllowlist is PANEL_WINGS_ALLOWLIST. Empty means zero real dials.
	WingsAllowlist WingsAllowlist
	// WingsBaseURL is PANEL_WINGS_BASE_URL, the daemon origin. Empty with an
	// empty token does not dial. The token is never logged.
	WingsBaseURL string
	// WingsToken is PANEL_WINGS_TOKEN, the daemon bearer. Never log it.
	WingsToken string
}

// WingsAllowlist is an explicit set of Glass UUIDs and Wings node ids.
// Dial matches UUIDs only. A node id is stored and does not authorize a dial.
// An empty set is fail-closed: executor=real still performs no real dial.
type WingsAllowlist struct {
	UUIDs map[string]struct{}
	Nodes map[string]struct{}
}

// Empty reports that no UUID and no node id is listed.
func (a WingsAllowlist) Empty() bool {
	return len(a.UUIDs) == 0 && len(a.Nodes) == 0
}

// Len is the number of UUID and node entries. It is safe to log.
func (a WingsAllowlist) Len() int {
	return len(a.UUIDs) + len(a.Nodes)
}

// HasUUID reports whether id is an allowlisted Glass UUID.
func (a WingsAllowlist) HasUUID(id string) bool {
	_, ok := a.UUIDs[strings.ToLower(strings.TrimSpace(id))]
	return ok
}

// HasNode reports whether id is an allowlisted Wings node id.
func (a WingsAllowlist) HasNode(id string) bool {
	_, ok := a.Nodes[strings.TrimSpace(id)]
	return ok
}

// Load reads environment variables. LISTEN_ADDR defaults to loopback.
// 0.0.0.0:8080 is accepted only when set explicitly for the CT316 underlay.
func Load() (Config, error) {
	c := Config{
		Env:                 getenv("PANEL_ENV", "test"),
		ListenAddr:          getenv("LISTEN_ADDR", DefaultListenAddr),
		JWTSecret:           []byte(os.Getenv("PANEL_JWT_HMAC_SECRET")),
		JWTIss:              getenv("PANEL_JWT_ISS", DefaultJWTIss),
		JWTAud:              getenv("PANEL_JWT_AUD", DefaultJWTAud),
		JWTJWKSURL:          getenv("PANEL_JWT_JWKS_URL", DefaultJWTJWKSURL),
		PublicBaseURL:       getenv("PANEL_PUBLIC_BASE_URL", DefaultPublicBase),
		MutateRPM:           MaxMutateRPM,
		ReadRPM:             MaxReadRPM,
		MigrateDisabled:     migrateDisabled(),
		MigrateModeMax:      strings.ToLower(strings.TrimSpace(getenv("GLASSPANEL_MIGRATE_MODE_MAX", MigrateModeInventoryOnly))),
		PteroSourceAPIURL:   strings.TrimSpace(os.Getenv("PTERO_SOURCE_API_URL")),
		PteroSourceAPIToken: strings.TrimSpace(os.Getenv("PTERO_SOURCE_API_TOKEN")),
		WingsExecutor:       strings.ToLower(strings.TrimSpace(getenv("PANEL_WINGS_EXECUTOR", WingsExecutorNoop))),
		WingsBaseURL:        strings.TrimSpace(os.Getenv("PANEL_WINGS_BASE_URL")),
		WingsToken:          strings.TrimSpace(os.Getenv("PANEL_WINGS_TOKEN")),
	}
	allow, err := ParseWingsAllowlist(os.Getenv("PANEL_WINGS_ALLOWLIST"))
	if err != nil {
		return Config{}, err
	}
	c.WingsAllowlist = allow
	nodes, err := loadCreateNodes()
	if err != nil {
		return Config{}, err
	}
	pool, err := loadAllocPool()
	if err != nil {
		return Config{}, err
	}
	c.CreateNodeAllowlist = nodes
	c.AllocPool = pool
	c = c.WithCreateDefaults()
	if v := os.Getenv("PANEL_MUTATE_RPM"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("PANEL_MUTATE_RPM: %w", err)
		}
		c.MutateRPM = n
	}
	if v := os.Getenv("PANEL_READ_RPM"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("PANEL_READ_RPM: %w", err)
		}
		c.ReadRPM = n
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate rejects prod settings, public binds, and rate limits above 60/300.
func (c Config) Validate() error {
	if c.Env != "test" {
		return fmt.Errorf("PANEL_ENV must be test (got %q); this binary is TEST-only", c.Env)
	}
	if err := ValidateListen(c.ListenAddr); err != nil {
		return err
	}
	if len(c.JWTSecret) < 16 {
		return fmt.Errorf("PANEL_JWT_HMAC_SECRET must be at least 16 bytes")
	}
	if string(c.JWTSecret) == "replace-with-test-hmac-secret" {
		return fmt.Errorf("PANEL_JWT_HMAC_SECRET is still the example placeholder")
	}
	if err := ValidateJWKSURL(c.JWTJWKSURL); err != nil {
		return err
	}
	if c.JWTIss == "" || isProdIssuer(c.JWTIss) {
		return fmt.Errorf("PANEL_JWT_ISS must be the TEST issuer")
	}
	if c.JWTIss != DefaultJWTIss {
		return fmt.Errorf("PANEL_JWT_ISS must be %s", DefaultJWTIss)
	}
	if c.JWTAud != DefaultJWTAud {
		return fmt.Errorf("PANEL_JWT_AUD must be %s", DefaultJWTAud)
	}
	if isProdAudience(c.JWTAud) {
		return fmt.Errorf("PANEL_JWT_AUD must not be the prod audience")
	}
	u, err := url.Parse(c.PublicBaseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return fmt.Errorf("PANEL_PUBLIC_BASE_URL must be an http(s) URL")
	}
	if !strings.EqualFold(u.Hostname(), TestHost) {
		return fmt.Errorf("PANEL_PUBLIC_BASE_URL host must be %s", TestHost)
	}
	if strings.Contains(strings.ToLower(c.PublicBaseURL), ProdHost) {
		return fmt.Errorf("PANEL_PUBLIC_BASE_URL must not be the prod host")
	}
	if c.MutateRPM < 1 || c.MutateRPM > MaxMutateRPM {
		return fmt.Errorf("mutate rpm must be 1..%d", MaxMutateRPM)
	}
	if c.ReadRPM < 1 || c.ReadRPM > MaxReadRPM {
		return fmt.Errorf("read rpm must be 1..%d", MaxReadRPM)
	}
	switch c.MigrateModeMax {
	case "", MigrateModeInventoryOnly, MigrateModeDryRun:
	default:
		return fmt.Errorf("GLASSPANEL_MIGRATE_MODE_MAX hard ceiling is inventory_only or dry_run")
	}
	c = c.WithCreateDefaults()
	if err := validateCreatePolicy(c); err != nil {
		return err
	}
	if err := validateWingsAllowlist(c.WingsAllowlist); err != nil {
		return err
	}
	if err := validatePteroSource(c.PteroSourceAPIURL, c.PteroSourceAPIToken); err != nil {
		return err
	}
	if err := validateWingsDial(c.WingsBaseURL, c.WingsToken); err != nil {
		return err
	}
	return nil
}

// validateWingsDial accepts both empty, or an http(s) origin plus a token.
// executor=real with both empty still boots. The allowlisted call then fails
// closed. Errors name the env vars and never include the token or userinfo.
func validateWingsDial(rawURL, token string) error {
	urlSet := strings.TrimSpace(rawURL) != ""
	tokenSet := token != ""
	if urlSet != tokenSet {
		return fmt.Errorf("PANEL_WINGS_BASE_URL and PANEL_WINGS_TOKEN must both be set or both be empty")
	}
	if !urlSet {
		return nil
	}
	if len(token) < 8 || len(token) > 4096 {
		return fmt.Errorf("PANEL_WINGS_TOKEN length is rejected")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("PANEL_WINGS_BASE_URL must be an absolute http(s) URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("PANEL_WINGS_BASE_URL scheme must be http or https")
	}
	if u.User != nil {
		return fmt.Errorf("PANEL_WINGS_BASE_URL must not include userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("PANEL_WINGS_BASE_URL must not include a query or fragment")
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("PANEL_WINGS_BASE_URL must be an origin without a path")
	}
	return nil
}

// validatePteroSource accepts both empty, or an http(s) origin plus a token.
// Errors name the env vars and never include the token or the URL userinfo.
func validatePteroSource(rawURL, token string) error {
	urlSet := strings.TrimSpace(rawURL) != ""
	tokenSet := token != ""
	if urlSet != tokenSet {
		return fmt.Errorf("PTERO_SOURCE_API_URL and PTERO_SOURCE_API_TOKEN must both be set or both be empty")
	}
	if !urlSet {
		return nil
	}
	if len(token) < 8 || len(token) > 4096 {
		return fmt.Errorf("PTERO_SOURCE_API_TOKEN length is rejected")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("PTERO_SOURCE_API_URL must be an absolute http(s) URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("PTERO_SOURCE_API_URL scheme must be http or https")
	}
	if u.User != nil {
		return fmt.Errorf("PTERO_SOURCE_API_URL must not include userinfo")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("PTERO_SOURCE_API_URL must not include a query or fragment")
	}
	return nil
}

// WithCreateDefaults fills the Phase A create SoT when env left it empty.
func (c Config) WithCreateDefaults() Config {
	if strings.TrimSpace(c.AllocPool) == "" {
		c.AllocPool = alloc.PoolTorN5ULA
	}
	if len(c.CreateNodeAllowlist) == 0 {
		c.CreateNodeAllowlist = []string{alloc.NodeTorN5}
	}
	if strings.TrimSpace(c.WingsExecutor) == "" {
		c.WingsExecutor = WingsExecutorNoop
	} else {
		c.WingsExecutor = strings.ToLower(strings.TrimSpace(c.WingsExecutor))
	}
	if strings.TrimSpace(c.MigrateModeMax) == "" {
		c.MigrateModeMax = MigrateModeInventoryOnly
	}
	return c
}

func validateCreatePolicy(c Config) error {
	switch c.WingsExecutor {
	case WingsExecutorNoop, WingsExecutorReal:
	default:
		return fmt.Errorf("PANEL_WINGS_EXECUTOR must be noop or real (got %q)", c.WingsExecutor)
	}
	if c.AllocPool != alloc.PoolTorN5ULA {
		return fmt.Errorf("PANEL_ALLOC_POOL must be %s (ULA %s, non-routable, not a public AAAA)", alloc.PoolTorN5ULA, alloc.PrefixTorN5ULA)
	}
	if len(c.CreateNodeAllowlist) == 0 {
		return fmt.Errorf("PANEL_CREATE_NODE_ALLOWLIST is empty")
	}
	seen := map[string]struct{}{}
	hasPoolNode := false
	for _, raw := range c.CreateNodeAllowlist {
		id, ok := CanonNodeID(raw)
		if !ok || id != raw {
			return fmt.Errorf("PANEL_CREATE_NODE_ALLOWLIST entry %q is not a canonical node id", raw)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("PANEL_CREATE_NODE_ALLOWLIST duplicate node %s", id)
		}
		seen[id] = struct{}{}
		if id == ManagedInventoryCHINodeID {
			return fmt.Errorf("PANEL_CREATE_NODE_ALLOWLIST must not include managed-inventory node %s", ManagedInventoryCHINodeID)
		}
		if id == alloc.NodeTorN5 {
			hasPoolNode = true
		}
	}
	if !hasPoolNode {
		return fmt.Errorf("PANEL_CREATE_NODE_ALLOWLIST must include node %s for pool %s", alloc.NodeTorN5, alloc.PoolTorN5ULA)
	}
	return nil
}

// migrateDisabled is true only when GLASSPANEL_MIGRATE_ENABLED is explicitly off.
// Unset stays enabled so the TEST inventory_only path keeps working.
func migrateDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GLASSPANEL_MIGRATE_ENABLED"))) {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}

// AllowsCreateNode reports whether nodeID is on the create allowlist.
func (c Config) AllowsCreateNode(nodeID string) bool {
	for _, id := range c.CreateNodeAllowlist {
		if id == nodeID {
			return true
		}
	}
	return false
}

// ParseWingsAllowlist splits PANEL_WINGS_ALLOWLIST into UUIDs and node ids.
// Empty or whitespace is an empty set (zero real dispatch). A wildcard is
// rejected so the list cannot mean "every non-deny server".
func ParseWingsAllowlist(raw string) (WingsAllowlist, error) {
	a := WingsAllowlist{
		UUIDs: map[string]struct{}{},
		Nodes: map[string]struct{}{},
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return a, nil
	}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		low := strings.ToLower(part)
		switch low {
		case "*", "all", "any":
			return WingsAllowlist{}, fmt.Errorf("PANEL_WINGS_ALLOWLIST rejects %q; an empty list means no real dispatch", part)
		}
		if strings.Contains(low, "glassmc-dev") {
			return WingsAllowlist{}, fmt.Errorf("PANEL_WINGS_ALLOWLIST rejects %q; glassmc-dev docker is not a Wings target", part)
		}
		if u, ok := canonUUID(low); ok {
			a.UUIDs[u] = struct{}{}
			continue
		}
		id, ok := CanonNodeID(part)
		if !ok {
			return WingsAllowlist{}, fmt.Errorf("PANEL_WINGS_ALLOWLIST entry %q is not a uuid or node id", part)
		}
		if id == ManagedInventoryCHINodeID {
			return WingsAllowlist{}, fmt.Errorf("PANEL_WINGS_ALLOWLIST must not include managed-inventory node %s", ManagedInventoryCHINodeID)
		}
		a.Nodes[id] = struct{}{}
	}
	return a, nil
}

func validateWingsAllowlist(a WingsAllowlist) error {
	for id := range a.UUIDs {
		if _, ok := canonUUID(id); !ok {
			return fmt.Errorf("PANEL_WINGS_ALLOWLIST uuid %q is not canonical", id)
		}
	}
	for id := range a.Nodes {
		canon, ok := CanonNodeID(id)
		if !ok || canon != id {
			return fmt.Errorf("PANEL_WINGS_ALLOWLIST node %q is not canonical", id)
		}
		if id == ManagedInventoryCHINodeID {
			return fmt.Errorf("PANEL_WINGS_ALLOWLIST must not include managed-inventory node %s", ManagedInventoryCHINodeID)
		}
		if strings.Contains(strings.ToLower(id), "glassmc-dev") {
			return fmt.Errorf("PANEL_WINGS_ALLOWLIST rejects node %q", id)
		}
	}
	return nil
}

func canonUUID(s string) (string, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 36 {
		return "", false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "", false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return "", false
			}
		}
	}
	return s, true
}

// CanonNodeID accepts a positive decimal node id without leading zeros.
func CanonNodeID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s[0] == '+' || s[0] == '-' {
		return "", false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 || n > 1_000_000 {
		return "", false
	}
	canon := strconv.Itoa(n)
	if canon != s {
		return "", false
	}
	return canon, true
}

func loadCreateNodes() ([]string, error) {
	raw := strings.TrimSpace(os.Getenv("PANEL_CREATE_NODE_ALLOWLIST"))
	single := strings.TrimSpace(os.Getenv("GLASSPANEL_CREATE_NODE_ID"))
	if raw == "" && single == "" {
		return []string{alloc.NodeTorN5}, nil
	}
	var nodes []string
	if raw != "" {
		for _, part := range strings.Split(raw, ",") {
			id, ok := CanonNodeID(part)
			if !ok {
				return nil, fmt.Errorf("PANEL_CREATE_NODE_ALLOWLIST entry %q is not a node id", strings.TrimSpace(part))
			}
			nodes = append(nodes, id)
		}
	}
	if single != "" {
		id, ok := CanonNodeID(single)
		if !ok {
			return nil, fmt.Errorf("GLASSPANEL_CREATE_NODE_ID %q is not a node id", single)
		}
		if len(nodes) == 0 {
			nodes = []string{id}
		} else if !nodeListed(nodes, id) {
			return nil, fmt.Errorf("GLASSPANEL_CREATE_NODE_ID %s is not in PANEL_CREATE_NODE_ALLOWLIST", id)
		}
	}
	return nodes, nil
}

func loadAllocPool() (string, error) {
	panel := strings.TrimSpace(os.Getenv("PANEL_ALLOC_POOL"))
	glass := strings.TrimSpace(os.Getenv("GLASSPANEL_ALLOC_POOL"))
	switch {
	case panel == "" && glass == "":
		return alloc.PoolTorN5ULA, nil
	case panel == "":
		return glass, nil
	case glass == "":
		return panel, nil
	case panel != glass:
		return "", fmt.Errorf("PANEL_ALLOC_POOL %q and GLASSPANEL_ALLOC_POOL %q disagree", panel, glass)
	default:
		return panel, nil
	}
}

func nodeListed(nodes []string, id string) bool {
	for _, n := range nodes {
		if n == id {
			return true
		}
	}
	return false
}

// ValidateListen allows loopback:8080 and explicit 0.0.0.0:8080 only.
func ValidateListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("LISTEN_ADDR %q: %w", addr, err)
	}
	if port != "8080" {
		return fmt.Errorf("LISTEN_ADDR port must be 8080 (got %s)", port)
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "0.0.0.0", "::1":
		return nil
	default:
		return fmt.Errorf("LISTEN_ADDR host %q is not allowed; use 127.0.0.1:8080 or 0.0.0.0:8080 for the CT underlay", host)
	}
}

// AuthMode labels the verifier.
// Staff JWTs verify as Portal OIDC RS256 when PANEL_JWT_JWKS_URL is set.
// PANEL_JWT_HMAC_SECRET signs and verifies panel-minted agent JWTs only.
// It is not a staff accept path.
func (c Config) AuthMode() string {
	if strings.TrimSpace(c.JWTJWKSURL) != "" {
		return "portal-oidc-rs256-staff+agent-hs256"
	}
	return "agent-hs256-only"
}

// ValidateJWKSURL accepts an empty URL or an absolute http(s) JWKS URL.
// An empty URL means staff RS256 cannot be verified. Agent HS256 mint still
// works. Staff HS256 is never accepted. Prod Portal and prod panel hosts are rejected.
func ValidateJWKSURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("PANEL_JWT_JWKS_URL must be an absolute http(s) URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("PANEL_JWT_JWKS_URL scheme must be http or https")
	}
	if u.User != nil {
		return fmt.Errorf("PANEL_JWT_JWKS_URL must not include userinfo")
	}
	if u.Path == "" || u.Path == "/" {
		return fmt.Errorf("PANEL_JWT_JWKS_URL must include a JWKS path")
	}
	if strings.Contains(strings.ToLower(u.Path), "/.well-known") {
		return fmt.Errorf("PANEL_JWT_JWKS_URL must not use /.well-known/ (portal-test nginx returns 403); use %s", DefaultJWTJWKSURL)
	}
	host := strings.ToLower(u.Hostname())
	if isProdIssuer("https://"+host) || isProdAudience("https://"+host) {
		return fmt.Errorf("PANEL_JWT_JWKS_URL must be the TEST Portal JWKS, not a prod host")
	}
	return nil
}

// JWKSHost is the host of PANEL_JWT_JWKS_URL, or empty when unset.
func (c Config) JWKSHost() string {
	u, err := url.Parse(strings.TrimSpace(c.JWTJWKSURL))
	if err != nil {
		return ""
	}
	return u.Host
}

// UnderlayBind reports whether the process is bound on all interfaces.
func UnderlayBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && host == "0.0.0.0"
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func isProdAudience(aud string) bool {
	a := strings.ToLower(strings.TrimSpace(aud))
	switch a {
	case "https://panel-api.glasshosting.com",
		"https://panel-api.glasshosting.com/v1",
		"glass-game-panel",
		"glass-game-panel-prod":
		return true
	default:
		return strings.Contains(a, ProdHost)
	}
}

func isProdIssuer(iss string) bool {
	s := strings.ToLower(strings.TrimSpace(iss))
	switch s {
	case "https://portal.glasshosting.com",
		"https://panel-api.glasshosting.com",
		"https://auth.glasshosting.com":
		return true
	default:
		return strings.Contains(s, ProdHost) || strings.Contains(s, "portal.glasshosting.com")
	}
}
