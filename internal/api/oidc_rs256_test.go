package api

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/fixture"
	"github.com/golang-jwt/jwt/v5"
)

func TestPortalOIDCRS256Servers(t *testing.T) {
	key := genPortalKey(t)
	wrong := genPortalKey(t)
	rotated := genPortalKey(t)
	set := &portalJWKS{}
	set.publish("portal-test-1", &key.PublicKey)
	jwks := httptest.NewServer(set.handler())
	t.Cleanup(jwks.Close)

	cfg := testConfig()
	cfg.JWTJWKSURL = jwks.URL + "/oidc/jwks.json"
	if cfg.AuthMode() != "portal-oidc-rs256-staff+agent-hs256" {
		t.Fatalf("auth mode %s", cfg.AuthMode())
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	c := &cli{t: t, srv: srv, base: ts.URL, http: &http.Client{Timeout: 5 * time.Second}}
	d, err := deny.Load()
	if err != nil {
		t.Fatal(err)
	}
	denyUUID := d.UUIDs()[0]
	now := time.Now().UTC()

	staff := portalClaims("staff-oidc", auth.TokenUseStaff, "jti-staff-oidc", "servers:read", nil, config.DefaultJWTIss, config.DefaultJWTAud, now)
	staffTok := signPortalRS256(t, key, "portal-test-1", staff)
	st, body, hdr := c.do(http.MethodGet, "/v1/servers", staffTok, "", nil)
	if st != http.StatusOK {
		t.Fatalf("staff list: %d %s", st, body)
	}
	if hdr.Get("X-Glass-Wings-Dispatch") != "0" || hdr.Get("X-Glass-Executor") != "noop" {
		t.Fatalf("headers %#v", hdr)
	}
	if !bytes.Contains(body, []byte(fixture.NonDenyServerID)) {
		t.Fatalf("list body %s", body)
	}

	agent := portalClaims("agent:oidc", auth.TokenUseAgent, "jti-agent-oidc", "servers:read", []string{fixture.NonDenyServerID}, config.DefaultJWTIss, config.DefaultJWTAud, now)
	agentTok := signPortalRS256(t, key, "portal-test-1", agent)
	st, body, hdr = c.do(http.MethodGet, "/v1/servers", agentTok, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(fixture.NonDenyServerID)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("agent list: %d %s", st, body)
	}

	st, body, hdr = c.do(http.MethodGet, "/v1/servers/"+denyUUID, staffTok, "", nil)
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("deny uuid: %d %s", st, body)
	}

	badTok := signPortalRS256(t, wrong, "portal-test-1", staff)
	st, body, _ = c.do(http.MethodGet, "/v1/servers", badTok, "", nil)
	if st != http.StatusUnauthorized || errorCode(body) != "unauthorized" {
		t.Fatalf("wrong key: %d %s", st, body)
	}

	wrongAud := portalClaims("staff-oidc", auth.TokenUseStaff, "jti-wrong-aud", "servers:read", nil, config.DefaultJWTIss, "https://panel-api-other.example", now)
	st, body, _ = c.do(http.MethodGet, "/v1/servers", signPortalRS256(t, key, "portal-test-1", wrongAud), "", nil)
	if st != http.StatusUnauthorized || errorCode(body) != "unauthorized" {
		t.Fatalf("wrong aud: %d %s", st, body)
	}
	prodAud := portalClaims("staff-oidc", auth.TokenUseStaff, "jti-prod-aud", "servers:read", nil, config.DefaultJWTIss, "https://panel-api.glasshosting.com", now)
	st, body, _ = c.do(http.MethodGet, "/v1/servers", signPortalRS256(t, key, "portal-test-1", prodAud), "", nil)
	if st != http.StatusUnauthorized || errorCode(body) != "unauthorized" || !bytes.Contains(body, []byte("prod_aud_or_iss_rejected")) {
		t.Fatalf("prod aud: %d %s", st, body)
	}
	wrongIss := portalClaims("staff-oidc", auth.TokenUseStaff, "jti-wrong-iss", "servers:read", nil, "https://issuer.example", config.DefaultJWTAud, now)
	st, body, _ = c.do(http.MethodGet, "/v1/servers", signPortalRS256(t, key, "portal-test-1", wrongIss), "", nil)
	if st != http.StatusUnauthorized || errorCode(body) != "unauthorized" {
		t.Fatalf("wrong iss: %d %s", st, body)
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es := jwt.NewWithClaims(jwt.SigningMethodES256, staff)
	es.Header["kid"] = "portal-test-1"
	esTok, err := es.SignedString(ec)
	if err != nil {
		t.Fatal(err)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers", esTok, "", nil)
	if st != http.StatusUnauthorized || errorCode(body) != "unauthorized" {
		t.Fatalf("wrong alg: %d %s", st, body)
	}

	set.publish("portal-test-2", &rotated.PublicKey)
	rotatedClaims := portalClaims("staff-oidc", auth.TokenUseStaff, "jti-rotated", "servers:read", nil, config.DefaultJWTIss, config.DefaultJWTAud, now)
	st, body, _ = c.do(http.MethodGet, "/v1/servers", signPortalRS256(t, rotated, "portal-test-2", rotatedClaims), "", nil)
	if st != http.StatusOK {
		t.Fatalf("rotated kid: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers", staffTok, "", nil)
	if st != http.StatusOK {
		t.Fatalf("overlap kid: %d %s", st, body)
	}

	staffHS := c.hmacToken("ops-hs256-staff", auth.TokenUseStaff, "jti-ops-hs256-staff", []string{"servers:read"}, nil)
	st, body, _ = c.do(http.MethodGet, "/v1/servers", staffHS, "", nil)
	if st != http.StatusUnauthorized || errorCode(body) != "unauthorized" {
		t.Fatalf("staff hs256: %d %s", st, body)
	}

	mintStaff := portalClaims("staff-mint", auth.TokenUseStaff, "jti-mint-staff", "agents:manage", nil, config.DefaultJWTIss, config.DefaultJWTAud, now)
	mintTok := signPortalRS256(t, key, "portal-test-1", mintStaff)
	st, body, _ = c.do(http.MethodPost, "/v1/agent-tokens", mintTok, c.idem(), map[string]any{
		"name":        "gate2b-agent",
		"scopes":      []string{"servers:read"},
		"ttl_seconds": 300,
		"server_ids":  []string{fixture.NonDenyServerID},
	})
	if st != http.StatusCreated {
		t.Fatalf("mint agent: %d %s", st, body)
	}
	var minted struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		t.Fatal(err)
	}
	issued, err := auth.Parse(cfg.JWTSecret, config.DefaultJWTIss, config.DefaultJWTAud, minted.Token, now)
	if err != nil || !issued.IsAgent() || issued.AuthPath != auth.PathAgentHMAC {
		t.Fatalf("minted principal err=%v %+v", err, issued)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers", minted.Token, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(fixture.NonDenyServerID)) {
		t.Fatalf("minted agent list: %d %s", st, body)
	}
	if srv.WingsAttempts() != 0 {
		t.Fatalf("wings dispatch %d", srv.WingsAttempts())
	}

	dir := filepath.Join(moduleRoot(t), "artifacts", "api-evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"gate":         "Portal OIDC RS256",
		"gate_2b":      "option-a",
		"proves":       "Staff JWTs verify as RS256 against a local JWKS. GET /v1/servers is 200. Staff HS256 is 401 even when the HMAC secret is configured. A panel-minted agent HS256 token is 200 on GET /v1/servers. Portal-minted agent RS256 is also 200. A managed-inventory deny UUID is 403 managed_inventory_denied. A token signed by a key that is not in the JWKS is 401. Wrong aud, iss, and alg are 401. Kid rotation is accepted while the previous kid remains published. Wings dispatch stays 0. This repo does not mint Portal tokens. HMAC signs agent tokens only and is not a staff accept path.",
		"staff_accept": "portal-oidc-rs256",
		"agent_mint":   auth.PathAgentHMAC,
		"iss":          config.DefaultJWTIss,
		"aud":          config.DefaultJWTAud,
		"cases": []map[string]any{
			{"name": "staff_rs256_list", "status": http.StatusOK},
			{"name": "agent_rs256_list", "status": http.StatusOK},
			{"name": "managed_inventory_deny_uuid", "status": http.StatusForbidden, "code": "managed_inventory_denied"},
			{"name": "wrong_key", "status": http.StatusUnauthorized, "code": "unauthorized"},
			{"name": "wrong_aud", "status": http.StatusUnauthorized, "code": "unauthorized"},
			{"name": "prod_aud", "status": http.StatusUnauthorized, "code": "unauthorized"},
			{"name": "wrong_iss", "status": http.StatusUnauthorized, "code": "unauthorized"},
			{"name": "wrong_alg", "status": http.StatusUnauthorized, "code": "unauthorized"},
			{"name": "kid_rotation", "status": http.StatusOK},
			{"name": "staff_hs256", "status": http.StatusUnauthorized, "code": "unauthorized"},
			{"name": "minted_agent_hs256_list", "status": http.StatusOK},
		},
		"wings_dispatch": srv.WingsAttempts(),
		"pass":           true,
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "portal-oidc-rs256.json"), append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	gate := map[string]any{
		"gate":   "Gate 2b Option A",
		"apply":  "gated apply — not auto-published",
		"proves": "Staff HS256 is 401. Portal-like staff RS256 is 200 on GET /v1/servers. Panel-minted agent HS256 is 200 on GET /v1/servers. A managed-inventory deny UUID is 403 managed_inventory_denied. Wings dispatch stays 0.",
		"iss":    config.DefaultJWTIss,
		"aud":    config.DefaultJWTAud,
		"cases": []map[string]any{
			{"name": "staff_hs256", "method": http.MethodGet, "path": "/v1/servers", "status": http.StatusUnauthorized, "code": "unauthorized"},
			{"name": "staff_rs256_list", "method": http.MethodGet, "path": "/v1/servers", "status": http.StatusOK},
			{"name": "minted_agent_hs256_list", "method": http.MethodGet, "path": "/v1/servers", "status": http.StatusOK},
			{"name": "managed_inventory_deny_uuid", "method": http.MethodGet, "path": "/v1/servers/{denyUUID}", "status": http.StatusForbidden, "code": "managed_inventory_denied"},
		},
		"wings_dispatch": srv.WingsAttempts(),
		"pass":           true,
	}
	gb, err := json.MarshalIndent(gate, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "gate-2b-option-a.json"), append(gb, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

type portalJWKS struct {
	mu   sync.Mutex
	keys []map[string]string
}

func (s *portalJWKS) publish(kid string, pub *rsa.PublicKey) {
	entry := map[string]string{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.keys {
		if s.keys[i]["kid"] == kid {
			s.keys[i] = entry
			return
		}
	}
	s.keys = append(s.keys, entry)
}

func (s *portalJWKS) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oidc/jwks.json" {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		keys := append([]map[string]string(nil), s.keys...)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
}

func portalClaims(sub, use, jti, scope string, servers []string, iss, aud string, now time.Time) auth.Claims {
	return auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:     scope,
		TokenUse:  use,
		ServerIDs: servers,
	}
}

func signPortalRS256(t *testing.T, key *rsa.PrivateKey, kid string, c auth.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	tok.Header["kid"] = kid
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func genPortalKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
