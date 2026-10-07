package config

import (
	"strings"
	"testing"
)

func TestValidateProdDay1AcceptsPins(t *testing.T) {
	clearPlaneEnv(t)
	t.Setenv("PANEL_ENV", "prod")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "day1-prod-hmac-secret-value")
	t.Setenv("PANEL_JWT_ISS", ProdJWTIss)
	t.Setenv("PANEL_JWT_AUD", ProdJWTAud)
	t.Setenv("PANEL_JWT_JWKS_URL", ProdJWTJWKSURL)
	t.Setenv("PANEL_JWT_KID", ProdJWTKID)
	t.Setenv("PANEL_PUBLIC_BASE_URL", ProdPublicBase)
	t.Setenv("PANEL_MUTATE_RPM", "60")
	t.Setenv("PANEL_READ_RPM", "300")
	t.Setenv("PANEL_WINGS_EXECUTOR", "noop")

	cfg, err := LoadProd()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Env != "prod" || cfg.JWTIss != ProdJWTIss || cfg.JWTAud != ProdJWTAud || cfg.PublicBaseURL != ProdPublicBase {
		t.Fatalf("pins %+v", cfg)
	}
	if cfg.JWTKID != ProdJWTKID || cfg.JWTJWKSURL != ProdJWTJWKSURL {
		t.Fatalf("kid %s jwks %s", cfg.JWTKID, cfg.JWTJWKSURL)
	}
	if cfg.WingsExecutor != WingsExecutorNoop || cfg.WingsBaseURL != "" || cfg.WingsToken != "" {
		t.Fatalf("executor %+v dial %q", cfg.WingsExecutor, cfg.WingsBaseURL)
	}
	if cfg.MutateRPM != MaxMutateRPM || cfg.ReadRPM != MaxReadRPM {
		t.Fatalf("rpm %d %d", cfg.MutateRPM, cfg.ReadRPM)
	}
	if cfg.RuntimeName() != "panel-api" || cfg.AuthMode() != "portal-oidc-rs256-staff+agent-hs256" {
		t.Fatalf("runtime %s auth %s", cfg.RuntimeName(), cfg.AuthMode())
	}
	if err := cfg.ValidateProd(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted a prod config; the TEST contract must stay TEST-only")
	}
	if err := cfg.ValidateTest(); err == nil {
		t.Fatal("ValidateTest accepted a prod config")
	}
}

func TestLoadProdDefaultsDay1Pins(t *testing.T) {
	clearPlaneEnv(t)
	t.Setenv("PANEL_ENV", "prod")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "day1-prod-hmac-secret-value")
	cfg, err := LoadProd()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.JWTIss != ProdJWTIss || cfg.JWTAud != ProdJWTAud || cfg.PublicBaseURL != ProdPublicBase || cfg.JWTKID != ProdJWTKID || cfg.JWTJWKSURL != ProdJWTJWKSURL {
		t.Fatalf("defaults iss=%s aud=%s base=%s kid=%s jwks=%s", cfg.JWTIss, cfg.JWTAud, cfg.PublicBaseURL, cfg.JWTKID, cfg.JWTJWKSURL)
	}
	if cfg.WingsExecutor != WingsExecutorNoop || !cfg.WingsAllowlist.Empty() {
		t.Fatalf("executor %s allowlist %d", cfg.WingsExecutor, cfg.WingsAllowlist.Len())
	}
}

func TestLoadStaysTestOnlyWhenProdPinsAreSet(t *testing.T) {
	clearPlaneEnv(t)
	t.Setenv("PANEL_ENV", "prod")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "day1-prod-hmac-secret-value")
	t.Setenv("PANEL_JWT_ISS", ProdJWTIss)
	t.Setenv("PANEL_JWT_AUD", ProdJWTAud)
	t.Setenv("PANEL_JWT_JWKS_URL", ProdJWTJWKSURL)
	t.Setenv("PANEL_JWT_KID", ProdJWTKID)
	t.Setenv("PANEL_PUBLIC_BASE_URL", ProdPublicBase)
	t.Setenv("PANEL_WINGS_EXECUTOR", "noop")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "TEST-only") {
		t.Fatalf("test Load accepted prod: %v", err)
	}
}

func TestLoadProdRefusesTestEnvAndEmptyEnv(t *testing.T) {
	clearPlaneEnv(t)
	t.Setenv("PANEL_JWT_HMAC_SECRET", "day1-prod-hmac-secret-value")
	t.Setenv("PANEL_ENV", "")
	if _, err := LoadProd(); err == nil || !strings.Contains(err.Error(), "prod") {
		t.Fatalf("empty PANEL_ENV: %v", err)
	}
	t.Setenv("PANEL_ENV", "test")
	if _, err := LoadProd(); err == nil || !strings.Contains(err.Error(), "prod") {
		t.Fatalf("PANEL_ENV=test on prod: %v", err)
	}
}

func TestValidateProdRefusesTestAndPublicPins(t *testing.T) {
	base := prodDay1()
	cases := []struct {
		name string
		edit func(*Config)
		want string
	}{
		{"test iss", func(c *Config) { c.JWTIss = DefaultJWTIss }, "TEST issuer"},
		{"test aud", func(c *Config) { c.JWTAud = DefaultJWTAud }, "TEST audience"},
		{"test kid", func(c *Config) { c.JWTKID = TestJWTKID }, TestJWTKID},
		{"other kid", func(c *Config) { c.JWTKID = "ggp-other" }, ProdJWTKID},
		{"public aud", func(c *Config) { c.JWTAud = "https://panel-api.glasshosting.com" }, "public panel audience"},
		{"public aud v1", func(c *Config) { c.JWTAud = "https://panel-api.glasshosting.com/v1" }, "public panel audience"},
		{"public base", func(c *Config) { c.PublicBaseURL = "https://panel-api.glasshosting.com" }, "public panel host"},
		{"public base v1", func(c *Config) { c.PublicBaseURL = "https://panel-api.glasshosting.com/v1" }, "public panel host"},
		{"test base", func(c *Config) { c.PublicBaseURL = DefaultPublicBase }, "TEST host"},
		{"test jwks", func(c *Config) { c.JWTJWKSURL = DefaultJWTJWKSURL }, "TEST Portal JWKS"},
		{"public jwks", func(c *Config) { c.JWTJWKSURL = "https://panel-api.glasshosting.com/jwks" }, "public panel host"},
		{"well known jwks", func(c *Config) { c.JWTJWKSURL = "https://portal.glasshosting.com/.well-known/jwks.json" }, ".well-known"},
		{"http portal jwks", func(c *Config) { c.JWTJWKSURL = "http://portal.glasshosting.com/oidc/jwks.json" }, "https"},
		{"mutate rpm", func(c *Config) { c.MutateRPM = 61 }, "mutate rpm"},
		{"read rpm", func(c *Config) { c.ReadRPM = 301 }, "read rpm"},
		{"executor real", func(c *Config) { c.WingsExecutor = WingsExecutorReal }, "noop"},
		{"dial set", func(c *Config) {
			c.WingsBaseURL = "https://wings.example:8080"
			c.WingsToken = "daemon-token-value"
		}, "must both be empty"},
		{"placeholder secret", func(c *Config) { c.JWTSecret = []byte("replace-with-prod-hmac-secret") }, "placeholder"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			tc.edit(&c)
			err := c.ValidateProd()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
			if strings.Contains(err.Error(), "daemon-token-value") {
				t.Fatal("token leaked in error")
			}
		})
	}
}

func TestValidateProdAcceptsDay1LocalJWKS(t *testing.T) {
	for _, raw := range []string{
		ProdJWTJWKSURL,
		"http://127.0.0.1:9/oidc/jwks.json",
		"http://[::1]:9/oidc/jwks.json",
		"http://10.10.1.46/oidc/jwks.json",
		"https://10.99.0.41/jwks.json",
	} {
		c := prodDay1()
		c.JWTJWKSURL = raw
		if err := c.ValidateProd(); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func TestValidateProdRefusesManagedInventoryAllowlist(t *testing.T) {
	clearPlaneEnv(t)
	t.Setenv("PANEL_ENV", "prod")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "day1-prod-hmac-secret-value")
	t.Setenv("PANEL_WINGS_EXECUTOR", "noop")

	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "1")
	if _, err := LoadProd(); err == nil || !strings.Contains(err.Error(), "node 1") {
		t.Fatalf("node 1 create: %v", err)
	}
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "5,43")
	if _, err := LoadProd(); err == nil || !strings.Contains(err.Error(), "43") {
		t.Fatalf("sid 43 create: %v", err)
	}
	t.Setenv("PANEL_CREATE_NODE_ALLOWLIST", "")
	t.Setenv("PANEL_WINGS_ALLOWLIST", "1")
	if _, err := LoadProd(); err == nil || !strings.Contains(err.Error(), "node 1") {
		t.Fatalf("node 1 wings: %v", err)
	}
	const denyUUID = "cfe08e83-08f9-4515-a5d3-f84737b6723a"
	t.Setenv("PANEL_WINGS_ALLOWLIST", denyUUID)
	if _, err := LoadProd(); err == nil || !strings.Contains(err.Error(), "managed-inventory") {
		t.Fatalf("deny uuid wings: %v", err)
	}

	// The TEST contract still parses a deny UUID so the request path can refuse it.
	t.Setenv("PANEL_ENV", "test")
	t.Setenv("PANEL_JWT_HMAC_SECRET", "secnoa-test-hmac-secret-not-for-prod")
	t.Setenv("PANEL_JWT_ISS", "")
	t.Setenv("PANEL_JWT_AUD", "")
	t.Setenv("PANEL_JWT_JWKS_URL", "")
	t.Setenv("PANEL_PUBLIC_BASE_URL", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WingsAllowlist.HasUUID(denyUUID) {
		t.Fatal("TEST Load must still accept a deny uuid on the allowlist")
	}
}

func prodDay1() Config {
	return Config{
		Env:           "prod",
		ListenAddr:    DefaultListenAddr,
		JWTSecret:     []byte("day1-prod-hmac-secret-value"),
		JWTIss:        ProdJWTIss,
		JWTAud:        ProdJWTAud,
		JWTJWKSURL:    ProdJWTJWKSURL,
		JWTKID:        ProdJWTKID,
		PublicBaseURL: ProdPublicBase,
		MutateRPM:     MaxMutateRPM,
		ReadRPM:       MaxReadRPM,
		WingsExecutor: WingsExecutorNoop,
	}
}

func clearPlaneEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PANEL_ENV",
		"LISTEN_ADDR",
		"PANEL_JWT_HMAC_SECRET",
		"PANEL_JWT_ISS",
		"PANEL_JWT_AUD",
		"PANEL_JWT_JWKS_URL",
		"PANEL_JWT_KID",
		"PANEL_PUBLIC_BASE_URL",
		"PANEL_MUTATE_RPM",
		"PANEL_READ_RPM",
		"PANEL_WINGS_EXECUTOR",
		"PANEL_WINGS_BASE_URL",
		"PANEL_WINGS_TOKEN",
		"PANEL_WINGS_ALLOWLIST",
		"PANEL_CREATE_NODE_ALLOWLIST",
		"PANEL_ALLOC_POOL",
		"GLASSPANEL_CREATE_NODE_ID",
		"GLASSPANEL_ALLOC_POOL",
		"GLASSPANEL_MIGRATE_ENABLED",
		"GLASSPANEL_MIGRATE_MODE_MAX",
		"PTERO_SOURCE_API_URL",
		"PTERO_SOURCE_API_TOKEN",
	} {
		t.Setenv(k, "")
	}
}
