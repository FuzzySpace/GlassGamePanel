package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwksTTL          = 5 * time.Minute
	jwksStaleGrace   = 15 * time.Minute
	jwksFailCooldown = 2 * time.Second
	jwksMaxBytes     = 256 << 10
	jwksMaxKeys      = 16
	jwksMinBits      = 2048
	jwksHTTPTimeout  = 5 * time.Second
)

// Validator verifies Portal OIDC RS256 tokens via JWKS, and HS256 agent tokens
// with the panel mint secret. Staff tokens are RS256/JWKS only. Both accepted
// paths require the configured TEST issuer and audience.
// This type does not mint Portal tokens.
type Validator struct {
	hmacSecret []byte
	iss        string
	aud        string
	jwks       *jwksCache
}

// NewValidator builds a verifier. An empty jwksURL leaves RS256 rejected.
// Staff tokens then cannot authenticate. The HMAC secret still verifies
// panel-minted agent tokens. A non-empty URL is fetched only when an RS256
// token is presented (and again on expiry or an unknown kid).
func NewValidator(hmacSecret []byte, iss, aud, jwksURL string) (*Validator, error) {
	if strings.TrimSpace(iss) == "" || strings.TrimSpace(aud) == "" {
		return nil, fmt.Errorf("jwt iss and aud are required")
	}
	v := &Validator{
		hmacSecret: append([]byte(nil), hmacSecret...),
		iss:        iss,
		aud:        aud,
	}
	jwksURL = strings.TrimSpace(jwksURL)
	if jwksURL == "" {
		return v, nil
	}
	cache, err := newJWKSCache(jwksURL)
	if err != nil {
		return nil, err
	}
	v.jwks = cache
	return v, nil
}

// Parse verifies one bearer JWT. RS256 uses JWKS and may be staff or agent.
// HS256 uses the panel mint secret and is accepted only when token_use=agent.
// Staff HS256 is rejected after the signature check, even when the HMAC secret
// is configured. Any other alg is rejected. Claims are trusted only after the
// signature check; token_use is not used to choose the key.
func (v *Validator) Parse(raw string, now time.Time) (Principal, error) {
	if v == nil || strings.TrimSpace(raw) == "" {
		return Principal{}, ErrUnauthorized
	}
	var c Claims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg(), jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	tok, err := parser.ParseWithClaims(raw, &c, v.keyfunc)
	if err != nil || tok == nil || !tok.Valid {
		return Principal{}, ErrUnauthorized
	}
	path := PathPortalOIDC
	if tok.Method != nil && tok.Method.Alg() == jwt.SigningMethodHS256.Alg() {
		path = PathAgentHMAC
	}
	return principalFromClaims(c, v.iss, v.aud, path)
}

func (v *Validator) keyfunc(t *jwt.Token) (any, error) {
	if t == nil || t.Method == nil {
		return nil, fmt.Errorf("missing signing method")
	}
	switch t.Method.Alg() {
	case jwt.SigningMethodRS256.Alg():
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("alg rejected")
		}
		if v.jwks == nil {
			return nil, fmt.Errorf("jwks not configured")
		}
		kid, err := headerKID(t.Header)
		if err != nil {
			return nil, err
		}
		return v.jwks.publicKey(kid)
	case jwt.SigningMethodHS256.Alg():
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("alg rejected")
		}
		if len(v.hmacSecret) == 0 {
			return nil, fmt.Errorf("agent mint hmac secret missing")
		}
		// The secret verifies the signature only. Staff HS256 is rejected
		// after verification in Parse. Do not branch the key on token_use.
		return v.hmacSecret, nil
	default:
		return nil, fmt.Errorf("alg rejected")
	}
}

func headerKID(h map[string]any) (string, error) {
	raw, ok := h["kid"]
	if !ok || raw == nil {
		return "", nil
	}
	kid, ok := raw.(string)
	if !ok || strings.TrimSpace(kid) == "" {
		return "", fmt.Errorf("kid must be a non-empty string")
	}
	return strings.TrimSpace(kid), nil
}

type jwksCache struct {
	url          string
	client       *http.Client
	ttl          time.Duration
	failCooldown time.Duration

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetched     time.Time
	lastAttempt time.Time
	lastErr     error
	fetching    bool
	done        chan struct{}
}

func newJWKSCache(rawURL string) (*jwksCache, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, fmt.Errorf("jwks url is empty")
	}
	return &jwksCache{
		url:          rawURL,
		ttl:          jwksTTL,
		failCooldown: jwksFailCooldown,
		client: &http.Client{
			Timeout: jwksHTTPTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errors.New("jwks redirect rejected")
			},
		},
	}, nil
}

func (c *jwksCache) publicKey(kid string) (*rsa.PublicKey, error) {
	if k, ok := c.lookup(kid, true); ok {
		return k, nil
	}
	if err := c.refresh(); err != nil {
		if k, ok := c.lookup(kid, false); ok {
			return k, nil
		}
		return nil, err
	}
	if k, ok := c.lookup(kid, false); ok {
		return k, nil
	}
	return nil, fmt.Errorf("jwks kid not found")
}

// lookup returns a cached key. freshOnly skips the cache when it is past TTL,
// which forces a refresh. A missing kid also misses so rotation can publish
// a new key without waiting for TTL.
func (c *jwksCache) lookup(kid string, freshOnly bool) (*rsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if freshOnly && !c.freshLocked() {
		return nil, false
	}
	// A failed refresh may reuse a key only inside the grace window. A successful
	// refresh replaces the map, so a retired kid does not stay trusted.
	if !freshOnly && (c.fetched.IsZero() || time.Since(c.fetched) >= c.ttl+jwksStaleGrace) {
		return nil, false
	}
	if len(c.keys) == 0 {
		return nil, false
	}
	if kid == "" {
		if len(c.keys) != 1 {
			return nil, false
		}
		for _, k := range c.keys {
			return k, true
		}
	}
	k, ok := c.keys[kid]
	return k, ok
}

func (c *jwksCache) freshLocked() bool {
	return !c.fetched.IsZero() && time.Since(c.fetched) < c.ttl
}

func (c *jwksCache) refresh() error {
	c.mu.Lock()
	if c.fetching {
		ch := c.done
		c.mu.Unlock()
		<-ch
		c.mu.Lock()
		err := c.lastErr
		c.mu.Unlock()
		return err
	}
	if c.lastErr != nil && !c.lastAttempt.IsZero() && time.Since(c.lastAttempt) < c.failCooldown {
		err := c.lastErr
		c.mu.Unlock()
		return err
	}
	c.fetching = true
	c.done = make(chan struct{})
	ch := c.done
	c.mu.Unlock()

	keys, err := c.download()

	c.mu.Lock()
	c.lastAttempt = time.Now()
	if err != nil {
		c.lastErr = err
	} else {
		c.keys = keys
		c.fetched = c.lastAttempt
		c.lastErr = nil
	}
	c.fetching = false
	close(ch)
	c.mu.Unlock()
	return err
}

func (c *jwksCache) download() (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequest(http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > jwksMaxBytes {
		return nil, fmt.Errorf("jwks body too large")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	return parseJWKS(body)
}

type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func parseJWKS(body []byte) (map[string]*rsa.PublicKey, error) {
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwks json: %w", err)
	}
	if len(doc.Keys) == 0 || len(doc.Keys) > jwksMaxKeys {
		return nil, fmt.Errorf("jwks key count rejected")
	}
	out := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		use := strings.TrimSpace(k.Use)
		if use != "" && use != "sig" {
			continue
		}
		alg := strings.TrimSpace(k.Alg)
		if alg != "" && alg != jwt.SigningMethodRS256.Alg() {
			continue
		}
		kid := strings.TrimSpace(k.Kid)
		if kid == "" {
			return nil, fmt.Errorf("jwks rsa key missing kid")
		}
		if _, exists := out[kid]; exists {
			return nil, fmt.Errorf("jwks duplicate kid")
		}
		pub, err := rsaPublicFromModExp(k.N, k.E)
		if err != nil {
			return nil, err
		}
		out[kid] = pub
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("jwks has no RS256 keys")
	}
	return out, nil
}

func rsaPublicFromModExp(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("jwks modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("jwks exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, fmt.Errorf("jwks modulus or exponent rejected")
	}
	n := new(big.Int).SetBytes(nBytes)
	if n.BitLen() < jwksMinBits {
		return nil, fmt.Errorf("jwks rsa key shorter than %d bits", jwksMinBits)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e < 3 {
		return nil, fmt.Errorf("jwks exponent rejected")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}
