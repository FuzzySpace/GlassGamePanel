package config

import (
	"strings"
	"testing"
)

func TestListenAndCaps(t *testing.T) {
	if DefaultListenAddr != "127.0.0.1:8080" {
		t.Fatalf("default listen %s", DefaultListenAddr)
	}
	for _, ok := range []string{"127.0.0.1:8080", "0.0.0.0:8080", "[::1]:8080"} {
		if err := ValidateListen(ok); err != nil {
			t.Fatalf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{":8080", "1.2.3.4:8080", "10.10.1.43:8080", "127.0.0.1:9090", "0.0.0.0:80"} {
		if err := ValidateListen(bad); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if !UnderlayBind("0.0.0.0:8080") {
		t.Fatal("expected underlay bind")
	}
	if UnderlayBind("127.0.0.1:8080") {
		t.Fatal("loopback is not the underlay bind")
	}

	t.Setenv("PANEL_ENV", "test")
	t.Setenv("GLASSPANEL_MIGRATE_ENABLED", "")
	t.Setenv("GLASSPANEL_MIGRATE_MODE_MAX", "")
	t.Setenv("PTERO_SOURCE_API_URL", "")
	t.Setenv("PTERO_SOURCE_API_TOKEN", "")
	t.Setenv("PANEL_WINGS_EXECUTOR", "")
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "secnoa-test-hmac-secret-not-for-prod")
	t.Setenv("PANEL_JWT_ISS", "")
	t.Setenv("PANEL_JWT_AUD", "")
	t.Setenv("PANEL_JWT_JWKS_URL", "")
	t.Setenv("PANEL_PUBLIC_BASE_URL", "")
	t.Setenv("PANEL_MUTATE_RPM", "")
	t.Setenv("PANEL_READ_RPM", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != DefaultListenAddr || cfg.MutateRPM != 60 || cfg.ReadRPM != 300 {
		t.Fatalf("%+v", cfg)
	}
	if cfg.JWTJWKSURL != DefaultJWTJWKSURL || cfg.JWTIss != DefaultJWTIss || cfg.JWTAud != DefaultJWTAud {
		t.Fatalf("jwt defaults %+v", cfg)
	}
	if cfg.AuthMode() != "portal-oidc-rs256-staff+agent-hs256" {
		t.Fatalf("auth mode %+v", cfg)
	}

	t.Setenv("PANEL_ENV", "prod")
	if _, err := Load(); err == nil {
		t.Fatal("prod env accepted")
	}
	t.Setenv("PANEL_ENV", "test")
	t.Setenv("PANEL_MUTATE_RPM", "61")
	if _, err := Load(); err == nil {
		t.Fatal("mutate rpm above 60 accepted")
	}
	t.Setenv("PANEL_MUTATE_RPM", "60")
	t.Setenv("PANEL_READ_RPM", "301")
	if _, err := Load(); err == nil {
		t.Fatal("read rpm above 300 accepted")
	}
	t.Setenv("PANEL_READ_RPM", "")
	t.Setenv("PANEL_JWT_AUD", "https://panel-api.glasshosting.com")
	if _, err := Load(); err == nil {
		t.Fatal("prod aud accepted as runtime aud")
	}
}

func TestJWKSURL(t *testing.T) {
	base := Config{
		Env:           "test",
		ListenAddr:    DefaultListenAddr,
		JWTSecret:     []byte("secnoa-test-hmac-secret-not-for-prod"),
		JWTIss:        DefaultJWTIss,
		JWTAud:        DefaultJWTAud,
		PublicBaseURL: DefaultPublicBase,
		MutateRPM:     60,
		ReadRPM:       300,
	}
	okURL := DefaultJWTJWKSURL
	base.JWTJWKSURL = okURL
	if err := base.Validate(); err != nil {
		t.Fatal(err)
	}
	if base.AuthMode() != "portal-oidc-rs256-staff+agent-hs256" || base.JWKSHost() != "portal-test.glasshosting.internal" {
		t.Fatalf("mode %s host %s", base.AuthMode(), base.JWKSHost())
	}
	empty := base
	empty.JWTJWKSURL = ""
	if err := empty.Validate(); err != nil {
		t.Fatal(err)
	}
	if empty.AuthMode() != "agent-hs256-only" {
		t.Fatalf("empty jwks mode %s", empty.AuthMode())
	}
	for _, bad := range []string{
		"https://portal.glasshosting.com/oidc/jwks.json",
		"https://portal-test.glasshosting.internal/.well-known/jwks.json",
		"https://portal-test.glasshosting.internal/.well-known/openid-configuration",
		"https://panel-api.glasshosting.com/jwks",
		"https://auth.glasshosting.com/jwks",
		"https://user:pass@portal-test.glasshosting.internal/jwks",
		"file:///tmp/jwks.json",
		"https://portal-test.glasshosting.internal",
		"not a url",
	} {
		c := base
		c.JWTJWKSURL = bad
		if err := c.Validate(); err == nil {
			t.Fatalf("accepted jwks url %s", bad)
		}
	}
	local := base
	local.JWTJWKSURL = "http://127.0.0.1:9/oidc/jwks.json"
	if err := local.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateModeCeiling(t *testing.T) {
	t.Setenv("PANEL_ENV", "test")
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "secnoa-test-hmac-secret-not-for-prod")
	t.Setenv("PANEL_JWT_ISS", "")
	t.Setenv("PANEL_JWT_AUD", "")
	t.Setenv("PANEL_JWT_JWKS_URL", "")
	t.Setenv("PANEL_PUBLIC_BASE_URL", "")
	t.Setenv("PANEL_MUTATE_RPM", "")
	t.Setenv("PANEL_READ_RPM", "")
	t.Setenv("GLASSPANEL_MIGRATE_ENABLED", "")
	t.Setenv("PTERO_SOURCE_API_URL", "")
	t.Setenv("PTERO_SOURCE_API_TOKEN", "")
	t.Setenv("PANEL_WINGS_EXECUTOR", "")
	t.Setenv("PANEL_WINGS_BASE_URL", "")
	t.Setenv("PANEL_WINGS_TOKEN", "")
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "")
	t.Setenv("PANEL_ALLOC_POOL", "")
	t.Setenv("GLASSPANEL_CREATE_NODE_ID", "")
	t.Setenv("GLASSPANEL_ALLOC_POOL", "")

	t.Setenv("GLASSPANEL_MIGRATE_MODE_MAX", "import")
	if _, err := Load(); err == nil {
		t.Fatal("import accepted as mode max")
	}
	t.Setenv("GLASSPANEL_MIGRATE_MODE_MAX", "import_and_cutover")
	if _, err := Load(); err == nil {
		t.Fatal("import_and_cutover accepted as mode max")
	}
	t.Setenv("GLASSPANEL_MIGRATE_MODE_MAX", "dry_run")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MigrateModeMax != MigrateModeDryRun || cfg.MigrateDisabled || cfg.WingsExecutor != WingsExecutorNoop {
		t.Fatalf("%+v", cfg)
	}
	t.Setenv("GLASSPANEL_MIGRATE_MODE_MAX", "inventory_only")
	t.Setenv("GLASSPANEL_MIGRATE_ENABLED", "false")
	cfg, err = Load()
	if err != nil || !cfg.MigrateDisabled || cfg.MigrateModeMax != MigrateModeInventoryOnly {
		t.Fatalf("disabled %+v err %v", cfg, err)
	}
	t.Setenv("GLASSPANEL_MIGRATE_ENABLED", "true")
	t.Setenv("PANEL_WINGS_ALLOWLIST", "")
	t.Setenv("PANEL_WINGS_EXECUTOR", "real")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WingsExecutor != WingsExecutorReal || !cfg.WingsAllowlist.Empty() {
		t.Fatalf("real with empty allowlist %+v", cfg.WingsAllowlist)
	}
	t.Setenv("PANEL_WINGS_EXECUTOR", "wings")
	if _, err := Load(); err == nil {
		t.Fatal("executor wings accepted")
	}
	t.Setenv("PANEL_WINGS_EXECUTOR", "noop")
	t.Setenv("PTERO_SOURCE_API_URL", "https://user:secret@ptero.example")
	t.Setenv("PTERO_SOURCE_API_TOKEN", "test-ro-application-token")
	if _, err := Load(); err == nil {
		t.Fatal("userinfo source url accepted")
	}
	t.Setenv("PTERO_SOURCE_API_URL", "https://ptero.example")
	t.Setenv("PTERO_SOURCE_API_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("url without token accepted")
	}
	t.Setenv("PTERO_SOURCE_API_TOKEN", "test-ro-application-token")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PteroSourceAPIURL != "https://ptero.example" || cfg.PteroSourceAPIToken != "test-ro-application-token" {
		t.Fatal("source config not loaded")
	}
}

func TestCreatePolicy(t *testing.T) {
	t.Setenv("PANEL_ENV", "test")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "secnoa-test-hmac-secret-not-for-prod")
	t.Setenv("PANEL_JWT_ISS", "")
	t.Setenv("PANEL_JWT_AUD", "")
	t.Setenv("PANEL_JWT_JWKS_URL", "")
	t.Setenv("PANEL_PUBLIC_BASE_URL", "")
	t.Setenv("PANEL_MUTATE_RPM", "")
	t.Setenv("PANEL_READ_RPM", "")
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("GLASSPANEL_MIGRATE_ENABLED", "")
	t.Setenv("GLASSPANEL_MIGRATE_MODE_MAX", "")
	t.Setenv("PTERO_SOURCE_API_URL", "")
	t.Setenv("PTERO_SOURCE_API_TOKEN", "")
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "")
	t.Setenv("PANEL_ALLOC_POOL", "")
	t.Setenv("GLASSPANEL_CREATE_NODE_ID", "")
	t.Setenv("GLASSPANEL_ALLOC_POOL", "")
	t.Setenv("PANEL_WINGS_EXECUTOR", "")
	t.Setenv("PANEL_WINGS_BASE_URL", "")
	t.Setenv("PANEL_WINGS_TOKEN", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AllocPool != "tor-n5-ula-test" || len(cfg.CreateNodeAllowlist) != 1 || cfg.CreateNodeAllowlist[0] != "5" || cfg.WingsExecutor != "noop" {
		t.Fatalf("%+v", cfg)
	}

	t.Setenv("GLASSPANEL_CREATE_NODE_ID", "5")
	t.Setenv("GLASSPANEL_ALLOC_POOL", "tor-n5-ula-test")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "5")
	t.Setenv("PANEL_ALLOC_POOL", "tor-n5-ula-test")
	if _, err := Load(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GLASSPANEL_ALLOC_POOL", "chi-managed-inventory")
	if _, err := Load(); err == nil {
		t.Fatal("disagreeing pool names accepted")
	}
	t.Setenv("GLASSPANEL_ALLOC_POOL", "")
	t.Setenv("GLASSPANEL_CREATE_NODE_ID", "")
	t.Setenv("PANEL_ALLOC_POOL", "chi-managed-inventory")
	if _, err := Load(); err == nil {
		t.Fatal("unknown pool accepted")
	}
	t.Setenv("PANEL_ALLOC_POOL", "")
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "1")
	if _, err := Load(); err == nil {
		t.Fatal("CHI node 1 accepted")
	}
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "6")
	if _, err := Load(); err == nil {
		t.Fatal("allowlist without node 5 accepted")
	}
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "5,43")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowsCreateNode("5") || !cfg.AllowsCreateNode("43") {
		t.Fatalf("allowlist %+v", cfg.CreateNodeAllowlist)
	}
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "")
	t.Setenv("PANEL_WINGS_EXECUTOR", "")
	t.Setenv("PANEL_WINGS_ALLOWLIST", "")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WingsExecutor != WingsExecutorNoop || !cfg.WingsAllowlist.Empty() {
		t.Fatalf("default executor %+v allowlist %d", cfg.WingsExecutor, cfg.WingsAllowlist.Len())
	}
	t.Setenv("PANEL_WINGS_EXECUTOR", "real")
	t.Setenv("PANEL_WINGS_ALLOWLIST", "AbAbAbAb-AbAb-4aBa-8aBa-AbAbAbAbAbAb, 5")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WingsExecutor != WingsExecutorReal || cfg.WingsAllowlist.Len() != 2 || !cfg.WingsAllowlist.HasUUID("abababab-abab-4aba-8aba-abababababab") || !cfg.WingsAllowlist.HasNode("5") {
		t.Fatalf("allowlist len=%d", cfg.WingsAllowlist.Len())
	}
	for _, bad := range []string{"*", "all", "1", "glassmc-dev-smp", "glassmc-dev-velocity", "not-a-node", "05"} {
		t.Setenv("PANEL_WINGS_ALLOWLIST", bad)
		if _, err := Load(); err == nil {
			t.Fatalf("allowlist %q accepted", bad)
		}
	}
	t.Setenv("PANEL_WINGS_ALLOWLIST", "cfe08e83-08f9-4515-a5d3-f84737b6723a")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WingsAllowlist.HasUUID("cfe08e83-08f9-4515-a5d3-f84737b6723a") {
		t.Fatal("deny uuid must parse so runtime can still refuse it")
	}
	t.Setenv("PANEL_WINGS_BASE_URL", "")
	t.Setenv("PANEL_WINGS_TOKEN", "")
	t.Setenv("PANEL_WINGS_EXECUTOR", "real")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WingsExecutor != WingsExecutorReal || cfg.WingsBaseURL != "" || cfg.WingsToken != "" {
		t.Fatal("real must boot with an empty wings origin and token")
	}
	t.Setenv("PANEL_WINGS_BASE_URL", "https://wings.example:8080")
	t.Setenv("PANEL_WINGS_TOKEN", "")
	if _, err := Load(); err == nil {
		t.Fatal("wings url without token accepted")
	}
	t.Setenv("PANEL_WINGS_TOKEN", "daemon-token-value")
	t.Setenv("PANEL_WINGS_BASE_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("wings token without url accepted")
	}
	t.Setenv("PANEL_WINGS_BASE_URL", "https://user:daemon-token-value@wings.example:8080")
	_, err = Load()
	if err == nil || strings.Contains(err.Error(), "daemon-token-value") {
		t.Fatalf("userinfo wings url err %v", err)
	}
	t.Setenv("PANEL_WINGS_BASE_URL", "https://wings.example:8080/api")
	if _, err := Load(); err == nil {
		t.Fatal("wings url path accepted")
	}
	t.Setenv("PANEL_WINGS_BASE_URL", "https://wings.example:8080")
	cfg, err = Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.WingsBaseURL != "https://wings.example:8080" || cfg.WingsToken != "daemon-token-value" {
		t.Fatal("wings dial config not loaded")
	}
}

func TestExampleSecretRejected(t *testing.T) {
	c := Config{
		Env:           "test",
		ListenAddr:    DefaultListenAddr,
		JWTSecret:     []byte("replace-with-test-hmac-secret"),
		JWTIss:        DefaultJWTIss,
		JWTAud:        DefaultJWTAud,
		PublicBaseURL: DefaultPublicBase,
		MutateRPM:     60,
		ReadRPM:       300,
	}
	if err := c.Validate(); err == nil {
		t.Fatal("placeholder secret accepted")
	}
}
