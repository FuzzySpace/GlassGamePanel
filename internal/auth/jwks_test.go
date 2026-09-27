package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func TestPortalOIDCRS256StaffAndAgent(t *testing.T) {
	key := genRSA(t)
	set := &jwksSet{}
	set.publish("kid-1", &key.PublicKey)
	srv := httptest.NewServer(set.handler())
	t.Cleanup(srv.Close)
	secret := []byte("secnoa-test-hmac-secret-not-for-prod")
	v, err := NewValidator(secret, config.DefaultJWTIss, config.DefaultJWTAud, srv.URL+"/oidc/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	staff := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	staff.Scope = "servers:read"
	raw := signRS256(t, key, "kid-1", staff)
	p, err := v.Parse(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.AuthPath != PathPortalOIDC || p.TokenUse != TokenUseStaff || !p.HasScope("servers:read") {
		t.Fatalf("%+v", p)
	}

	agent := staff
	agent.Subject = "agent:rs256"
	agent.ID = "jti-agent-rs256"
	agent.TokenUse = TokenUseAgent
	agent.ServerIDs = []string{"11111111-1111-4111-8111-111111111111"}
	raw = signRS256(t, key, "kid-1", agent)
	p, err = v.Parse(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.AuthPath != PathPortalOIDC || p.TokenUse != TokenUseAgent || len(p.ServerIDs) != 1 {
		t.Fatalf("%+v", p)
	}

	bridge := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	bridge.ID = "jti-agent-hmac"
	bridge.Subject = "agent:hmac"
	bridge.TokenUse = TokenUseAgent
	bridge.ServerIDs = []string{"11111111-1111-4111-8111-111111111111"}
	raw, err = Sign(secret, bridge)
	if err != nil {
		t.Fatal(err)
	}
	p, err = v.Parse(raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.AuthPath != PathAgentHMAC || p.TokenUse != TokenUseAgent {
		t.Fatalf("agent hmac path %+v", p)
	}

	staffHMAC := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	staffHMAC.ID = "jti-staff-hmac"
	raw, err = Sign(secret, staffHMAC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("staff hs256: %v", err)
	}
}

func TestPortalOIDCRejectsWrongIssAudAlgAndKey(t *testing.T) {
	key := genRSA(t)
	other := genRSA(t)
	set := &jwksSet{}
	set.publish("kid-1", &key.PublicKey)
	srv := httptest.NewServer(set.handler())
	t.Cleanup(srv.Close)
	v := mustValidator(t, srv.URL+"/oidc/jwks.json")
	now := time.Now().UTC()
	good := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)

	raw := signRS256(t, other, "kid-1", good)
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong key: %v", err)
	}
	raw = signRS256(t, key, "kid-missing", good)
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown kid: %v", err)
	}

	wrongAud := claims(config.DefaultJWTIss, "https://panel-api-other.example", now)
	raw = signRS256(t, key, "kid-1", wrongAud)
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong aud: %v", err)
	}
	prodAud := claims(config.DefaultJWTIss, "https://panel-api.glasshosting.com", now)
	raw = signRS256(t, key, "kid-1", prodAud)
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrProdRejected) {
		t.Fatalf("prod aud: %v", err)
	}
	wrongIss := claims("https://issuer.example", config.DefaultJWTAud, now)
	raw = signRS256(t, key, "kid-1", wrongIss)
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong iss: %v", err)
	}
	prodIss := claims("https://portal.glasshosting.com", config.DefaultJWTAud, now)
	raw = signRS256(t, key, "kid-1", prodIss)
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrProdRejected) {
		t.Fatalf("prod iss: %v", err)
	}

	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es := jwt.NewWithClaims(jwt.SigningMethodES256, good)
	es.Header["kid"] = "kid-1"
	raw, err = es.SignedString(ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ES256: %v", err)
	}

	rs384 := jwt.NewWithClaims(jwt.SigningMethodRS384, good)
	rs384.Header["kid"] = "kid-1"
	raw, err = rs384.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("RS384: %v", err)
	}

	confused := jwt.NewWithClaims(jwt.SigningMethodHS256, good)
	confused.Header["kid"] = "kid-1"
	raw, err = confused.SignedString(key.PublicKey.N.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("alg confusion: %v", err)
	}

	if _, err := v.Parse(noneToken(t, good), now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("alg none: %v", err)
	}

	noJWKS, err := NewValidator([]byte("secnoa-test-hmac-secret-not-for-prod"), config.DefaultJWTIss, config.DefaultJWTAud, "")
	if err != nil {
		t.Fatal(err)
	}
	raw = signRS256(t, key, "kid-1", good)
	if _, err := noJWKS.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("rs256 without jwks: %v", err)
	}
}

func TestJWKSKidRotation(t *testing.T) {
	first := genRSA(t)
	second := genRSA(t)
	set := &jwksSet{}
	set.publish("kid-1", &first.PublicKey)
	srv := httptest.NewServer(set.handler())
	t.Cleanup(srv.Close)
	v := mustValidator(t, srv.URL+"/oidc/jwks.json")
	now := time.Now().UTC()
	c1 := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	c1.ID = "jti-kid-1"
	raw1 := signRS256(t, first, "kid-1", c1)
	if _, err := v.Parse(raw1, now); err != nil {
		t.Fatal(err)
	}

	set.publish("kid-2", &second.PublicKey)
	c2 := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	c2.ID = "jti-kid-2"
	c2.TokenUse = TokenUseAgent
	c2.Subject = "agent:rotate"
	c2.ServerIDs = []string{"11111111-1111-4111-8111-111111111111"}
	raw2 := signRS256(t, second, "kid-2", c2)
	p, err := v.Parse(raw2, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenUse != TokenUseAgent || p.AuthPath != PathPortalOIDC {
		t.Fatalf("%+v", p)
	}
	if _, err := v.Parse(raw1, now); err != nil {
		t.Fatalf("overlap kid-1: %v", err)
	}

	set.drop("kid-1")
	v.jwks.ttl = 0
	if _, err := v.Parse(raw1, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("retired kid: %v", err)
	}
	if _, err := v.Parse(raw2, now); err != nil {
		t.Fatalf("kid-2 after retire: %v", err)
	}
}

func TestMissingKidUsesSoleKey(t *testing.T) {
	key := genRSA(t)
	set := &jwksSet{}
	set.publish("only", &key.PublicKey)
	srv := httptest.NewServer(set.handler())
	t.Cleanup(srv.Close)
	v := mustValidator(t, srv.URL+"/oidc/jwks.json")
	now := time.Now().UTC()
	raw := signRS256(t, key, "", claims(config.DefaultJWTIss, config.DefaultJWTAud, now))
	if _, err := v.Parse(raw, now); err != nil {
		t.Fatal(err)
	}

	other := genRSA(t)
	set.publish("two", &other.PublicKey)
	v.jwks.ttl = 0
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("missing kid with two keys: %v", err)
	}
}

func TestJWKSRedirectRejected(t *testing.T) {
	key := genRSA(t)
	set := &jwksSet{}
	set.publish("kid-1", &key.PublicKey)
	good := httptest.NewServer(set.handler())
	t.Cleanup(good.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, good.URL+"/oidc/jwks.json", http.StatusFound)
	}))
	t.Cleanup(redir.Close)
	v := mustValidator(t, redir.URL+"/oidc/jwks.json")
	now := time.Now().UTC()
	raw := signRS256(t, key, "kid-1", claims(config.DefaultJWTIss, config.DefaultJWTAud, now))
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("redirect: %v", err)
	}
}

func TestJWKSStaleKeyExpiresWhenEndpointDown(t *testing.T) {
	key := genRSA(t)
	set := &jwksSet{}
	set.publish("kid-1", &key.PublicKey)
	srv := httptest.NewServer(set.handler())
	v := mustValidator(t, srv.URL+"/oidc/jwks.json")
	now := time.Now().UTC()
	raw := signRS256(t, key, "kid-1", claims(config.DefaultJWTIss, config.DefaultJWTAud, now))
	if _, err := v.Parse(raw, now); err != nil {
		t.Fatal(err)
	}
	srv.Close()
	v.jwks.ttl = 0
	if _, err := v.Parse(raw, now); err != nil {
		t.Fatalf("recent cache during jwks outage: %v", err)
	}
	v.jwks.fetched = time.Now().Add(-(jwksTTL + jwksStaleGrace + time.Minute))
	if _, err := v.Parse(raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired cache during jwks outage: %v", err)
	}
}

func TestParseJWKSRejectsWeakAndDuplicate(t *testing.T) {
	n := base64.RawURLEncoding.EncodeToString(bytesRepeat(128))
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	body := []byte(`{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"short","n":"` + n + `","e":"` + e + `"}]}`)
	if _, err := parseJWKS(body); err == nil {
		t.Fatal("short modulus accepted")
	}
	key := genRSA(t)
	one := jwkMap("kid-1", &key.PublicKey)
	doc := map[string]any{"keys": []any{one, one}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseJWKS(b); err == nil {
		t.Fatal("duplicate kid accepted")
	}
}

type jwksSet struct {
	mu   sync.Mutex
	keys []jwk
}

func (s *jwksSet) publish(kid string, pub *rsa.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := jwkFromPublic(kid, pub)
	for i := range s.keys {
		if s.keys[i].Kid == kid {
			s.keys[i] = next
			return
		}
	}
	s.keys = append(s.keys, next)
}

func (s *jwksSet) drop(kid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.keys[:0]
	for _, k := range s.keys {
		if k.Kid != kid {
			out = append(out, k)
		}
	}
	s.keys = out
}

func (s *jwksSet) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oidc/jwks.json" {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwksDoc{Keys: append([]jwk(nil), s.keys...)})
	})
}

func mustValidator(t *testing.T, jwksURL string) *Validator {
	t.Helper()
	v, err := NewValidator([]byte("secnoa-test-hmac-secret-not-for-prod"), config.DefaultJWTIss, config.DefaultJWTAud, jwksURL)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signRS256(t *testing.T, key *rsa.PrivateKey, kid string, c Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func noneToken(t *testing.T, c Claims) string {
	t.Helper()
	hb, err := json.Marshal(map[string]string{"alg": "none", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	pb, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb) + "."
}

func jwkFromPublic(kid string, pub *rsa.PublicKey) jwk {
	return jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: kid,
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func jwkMap(kid string, pub *rsa.PublicKey) map[string]string {
	k := jwkFromPublic(kid, pub)
	return map[string]string{"kty": k.Kty, "use": k.Use, "kid": k.Kid, "alg": k.Alg, "n": k.N, "e": k.E}
}

func bytesRepeat(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}
