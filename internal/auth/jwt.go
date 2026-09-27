package auth

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenUseStaff = "staff"
	TokenUseAgent = "agent"

	// PathPortalOIDC is a JWT verified as Portal OIDC RS256 against JWKS.
	// Staff tokens use only this path. Portal-minted agent tokens may use it too.
	PathPortalOIDC = "portal-oidc-rs256"
	// PathAgentHMAC is HS256 verification of panel-minted agent tokens.
	// Staff tokens are rejected on this path even when the HMAC secret checks out.
	PathAgentHMAC = "agent-hmac-mint"
	// PathHMACBridge is the historical name of PathAgentHMAC.
	// Gate 2b Option A: it is not a staff accept path.
	PathHMACBridge = PathAgentHMAC
)

// ErrUnauthorized is any rejected bearer token.
var ErrUnauthorized = errors.New("unauthorized")

// ErrProdRejected is a token whose aud or iss is the prod Portal/panel.
var ErrProdRejected = errors.New("prod token rejected on TEST")

// Claims is the TEST JWT. token_use is staff or agent. scope is space-delimited.
type Claims struct {
	jwt.RegisteredClaims
	Scope     string   `json:"scope,omitempty"`
	Scopes    []string `json:"scopes,omitempty"`
	TokenUse  string   `json:"token_use"`
	ServerIDs []string `json:"server_ids,omitempty"`
	MintedBy  string   `json:"minted_by,omitempty"`
}

// Principal is an authenticated caller.
type Principal struct {
	Subject   string
	JTI       string
	TokenUse  string
	Scopes    map[string]struct{}
	ServerIDs []string
	Issuer    string
	Audience  []string
	MintedBy  string
	// AuthPath is PathPortalOIDC or PathAgentHMAC. It is not returned on the API.
	AuthPath string
}

// HasScope reports whether the token carries scope.
func (p Principal) HasScope(scope string) bool {
	_, ok := p.Scopes[scope]
	return ok
}

// IsAgent reports agent tokens (cannot mint children or call migrations).
func (p Principal) IsAgent() bool {
	return p.TokenUse == TokenUseAgent
}

// Sign HS256-signs a panel-minted agent token.
// Portal OIDC tokens are RS256 and are not minted in this repo.
// The HMAC secret is not a staff accept path: a staff token signed here
// fails Validator.Parse. Callers must set the TEST issuer and audience.
func Sign(secret []byte, c Claims) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return t.SignedString(secret)
}

// Parse validates an HS256 token. Agent tokens are accepted. Staff tokens are
// rejected. RS256 verification uses Validator with a JWKS URL.
func Parse(secret []byte, wantIss, wantAud, raw string, now time.Time) (Principal, error) {
	v, err := NewValidator(secret, wantIss, wantAud, "")
	if err != nil {
		return Principal{}, ErrUnauthorized
	}
	return v.Parse(raw, now)
}

func principalFromClaims(c Claims, wantIss, wantAud, path string) (Principal, error) {
	if IsProdIssuer(c.Issuer) || AudienceHasProd(c.Audience) {
		return Principal{}, ErrProdRejected
	}
	if c.Issuer != wantIss {
		return Principal{}, ErrUnauthorized
	}
	if !audienceContains(c.Audience, wantAud) {
		return Principal{}, ErrUnauthorized
	}
	if c.Subject == "" || c.ID == "" {
		return Principal{}, ErrUnauthorized
	}
	if c.TokenUse != TokenUseStaff && c.TokenUse != TokenUseAgent {
		return Principal{}, ErrUnauthorized
	}
	// Gate 2b Option A: HS256 is panel-minted agent tokens only.
	// A valid HMAC signature does not authenticate staff.
	if path == PathAgentHMAC && c.TokenUse != TokenUseAgent {
		return Principal{}, ErrUnauthorized
	}
	if path != PathPortalOIDC && path != PathAgentHMAC {
		return Principal{}, ErrUnauthorized
	}
	scopes := map[string]struct{}{}
	for _, s := range strings.Fields(c.Scope) {
		scopes[s] = struct{}{}
	}
	for _, s := range c.Scopes {
		s = strings.TrimSpace(s)
		if s != "" {
			scopes[s] = struct{}{}
		}
	}
	ids := make([]string, 0, len(c.ServerIDs))
	for _, id := range c.ServerIDs {
		ids = append(ids, strings.ToLower(strings.TrimSpace(id)))
	}
	aud := append([]string(nil), []string(c.Audience)...)
	return Principal{
		Subject:   c.Subject,
		JTI:       c.ID,
		TokenUse:  c.TokenUse,
		Scopes:    scopes,
		ServerIDs: ids,
		Issuer:    c.Issuer,
		Audience:  aud,
		MintedBy:  c.MintedBy,
		AuthPath:  path,
	}, nil
}

// IsProdIssuer reports Glass prod Portal/panel issuers.
func IsProdIssuer(iss string) bool {
	s := strings.ToLower(strings.TrimSpace(iss))
	switch s {
	case "https://portal.glasshosting.com",
		"https://panel-api.glasshosting.com",
		"https://auth.glasshosting.com":
		return true
	default:
		return strings.Contains(s, "panel-api.glasshosting.com") || strings.Contains(s, "portal.glasshosting.com")
	}
}

// IsProdAudience reports Glass prod panel audiences.
func IsProdAudience(aud string) bool {
	a := strings.ToLower(strings.TrimSpace(aud))
	switch a {
	case "https://panel-api.glasshosting.com",
		"https://panel-api.glasshosting.com/v1",
		"glass-game-panel",
		"glass-game-panel-prod":
		return true
	default:
		return strings.Contains(a, "panel-api.glasshosting.com")
	}
}

// AudienceHasProd reports whether any audience entry is prod.
func AudienceHasProd(aud jwt.ClaimStrings) bool {
	for _, a := range aud {
		if IsProdAudience(a) {
			return true
		}
	}
	return false
}

func audienceContains(aud jwt.ClaimStrings, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}
