package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/golang-jwt/jwt/v5"
)

func TestParseRejectsProd(t *testing.T) {
	secret := []byte("secnoa-test-hmac-secret-not-for-prod")
	now := time.Now().UTC()
	good := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	good.TokenUse = TokenUseAgent
	good.Subject = "agent:parse"
	good.ID = "jti-agent-parse"
	good.ServerIDs = []string{"11111111-1111-4111-8111-111111111111"}
	raw, err := Sign(secret, good)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(secret, config.DefaultJWTIss, config.DefaultJWTAud, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenUse != TokenUseAgent || !p.HasScope("power") || p.AuthPath != PathAgentHMAC {
		t.Fatalf("%+v", p)
	}

	staff := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	raw, err = Sign(secret, staff)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(secret, config.DefaultJWTIss, config.DefaultJWTAud, raw, now)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("staff hs256: %v", err)
	}

	prodAud := claims(config.DefaultJWTIss, "https://panel-api.glasshosting.com", now)
	prodAud.TokenUse = TokenUseAgent
	prodAud.Subject = "agent:prod-aud"
	raw, err = Sign(secret, prodAud)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(secret, config.DefaultJWTIss, config.DefaultJWTAud, raw, now)
	if !errors.Is(err, ErrProdRejected) {
		t.Fatalf("prod aud: %v", err)
	}

	both := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	both.TokenUse = TokenUseAgent
	both.Subject = "agent:mixed-aud"
	both.Audience = jwt.ClaimStrings{config.DefaultJWTAud, "https://panel-api.glasshosting.com/v1"}
	raw, err = Sign(secret, both)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(secret, config.DefaultJWTIss, config.DefaultJWTAud, raw, now)
	if !errors.Is(err, ErrProdRejected) {
		t.Fatalf("mixed aud: %v", err)
	}

	prodIss := claims("https://portal.glasshosting.com", config.DefaultJWTAud, now)
	prodIss.TokenUse = TokenUseAgent
	prodIss.Subject = "agent:prod-iss"
	raw, err = Sign(secret, prodIss)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(secret, config.DefaultJWTIss, config.DefaultJWTAud, raw, now)
	if !errors.Is(err, ErrProdRejected) {
		t.Fatalf("prod iss: %v", err)
	}

	expired := claims(config.DefaultJWTIss, config.DefaultJWTAud, now)
	expired.TokenUse = TokenUseAgent
	expired.Subject = "agent:expired"
	expired.ExpiresAt = jwt.NewNumericDate(now.Add(-time.Hour))
	raw, err = Sign(secret, expired)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Parse(secret, config.DefaultJWTIss, config.DefaultJWTAud, raw, now)
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired: %v", err)
	}
}

func TestProdPlaneKeepsGate2b(t *testing.T) {
	secret := []byte("day1-prod-hmac-secret-value")
	now := time.Now().UTC()

	agent := claims(config.ProdJWTIss, config.ProdJWTAud, now)
	agent.TokenUse = TokenUseAgent
	agent.Subject = "agent:prod"
	agent.ID = "jti-prod-agent"
	agent.ServerIDs = []string{"11111111-1111-4111-8111-111111111111"}
	raw, err := Sign(secret, agent)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(secret, config.ProdJWTIss, config.ProdJWTAud, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	if p.TokenUse != TokenUseAgent || p.AuthPath != PathAgentHMAC || p.Issuer != config.ProdJWTIss {
		t.Fatalf("%+v", p)
	}

	staff := claims(config.ProdJWTIss, config.ProdJWTAud, now)
	raw, err = Sign(secret, staff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(secret, config.ProdJWTIss, config.ProdJWTAud, raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("staff hs256 on prod: %v", err)
	}

	testIss := claims(config.DefaultJWTIss, config.ProdJWTAud, now)
	testIss.TokenUse = TokenUseAgent
	testIss.Subject = "agent:test-iss"
	testIss.ID = "jti-test-iss-on-prod"
	raw, err = Sign(secret, testIss)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(secret, config.ProdJWTIss, config.ProdJWTAud, raw, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("test iss on prod: %v", err)
	}

	publicAud := claims(config.ProdJWTIss, "https://panel-api.glasshosting.com", now)
	publicAud.TokenUse = TokenUseAgent
	publicAud.Subject = "agent:public-aud"
	publicAud.ID = "jti-public-aud"
	raw, err = Sign(secret, publicAud)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Parse(secret, config.ProdJWTIss, config.ProdJWTAud, raw, now); !errors.Is(err, ErrProdRejected) {
		t.Fatalf("public aud on prod: %v", err)
	}
}

func claims(iss, aud string, now time.Time) Claims {
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   "staff-test",
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        "jti-test",
		},
		Scope:    "power console",
		TokenUse: TokenUseStaff,
	}
}
