package api

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/fixture"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

func testConfig() config.Config {
	return config.Config{
		Env:           "test",
		ListenAddr:    config.DefaultListenAddr,
		JWTSecret:     []byte("secnoa-test-hmac-secret-not-for-prod"),
		JWTIss:        config.DefaultJWTIss,
		JWTAud:        config.DefaultJWTAud,
		PublicBaseURL: config.DefaultPublicBase,
		MutateRPM:     config.MaxMutateRPM,
		ReadRPM:       config.MaxReadRPM,
	}
}

type caseResult struct {
	Name          string `json:"name"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	Status        int    `json:"status"`
	Code          string `json:"code,omitempty"`
	WingsDispatch int64  `json:"wings_dispatch"`
	Pass          bool   `json:"pass"`
}

type gateDoc struct {
	Gate   string       `json:"gate"`
	Proves string       `json:"proves"`
	Cases  []caseResult `json:"cases"`
	Notes  []string     `json:"notes,omitempty"`
	Pass   bool         `json:"pass"`
}

type cli struct {
	t         *testing.T
	srv       *Server
	base      string
	http      *http.Client
	n         int
	portalKey *rsa.PrivateKey
	portalKID string
}

// newHarness starts a local Portal JWKS and a panel API.
// Staff helpers sign RS256 against that JWKS. Agent helpers stay HS256.
func newHarness(t *testing.T) (*Server, *cli, *httptest.Server) {
	t.Helper()
	key := genPortalKey(t)
	set := &portalJWKS{}
	const kid = "portal-test-1"
	set.publish(kid, &key.PublicKey)
	jwks := httptest.NewServer(set.handler())
	t.Cleanup(jwks.Close)
	cfg := testConfig()
	cfg.JWTJWKSURL = jwks.URL + "/oidc/jwks.json"
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	c := &cli{
		t:         t,
		srv:       srv,
		base:      ts.URL,
		http:      &http.Client{Timeout: 5 * time.Second},
		portalKey: key,
		portalKID: kid,
	}
	return srv, c, ts
}

func (c *cli) staff() string {
	c.n++
	return c.token("staff-secnoa", auth.TokenUseStaff, fmt.Sprintf("staff-%d", c.n), []string{
		"servers:read", "servers:write", "power", "console", "files", "backups",
		"metrics", "agents:manage", "migrations:read", "migrations:write",
	}, nil)
}

func (c *cli) token(sub, use, jti string, scopes, servers []string) string {
	return c.tokenIssAud(sub, use, jti, scopes, servers, config.DefaultJWTIss, config.DefaultJWTAud)
}

func (c *cli) tokenIssAud(sub, use, jti string, scopes, servers []string, iss, aud string) string {
	c.t.Helper()
	now := time.Now().UTC()
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:     strings.Join(scopes, " "),
		TokenUse:  use,
		ServerIDs: servers,
	}
	if use == auth.TokenUseStaff {
		if c.portalKey == nil {
			c.t.Fatal("staff JWT must be RS256; portal key is not configured")
		}
		return signPortalRS256(c.t, c.portalKey, c.portalKID, claims)
	}
	raw, err := auth.Sign(c.srv.cfg.JWTSecret, claims)
	if err != nil {
		c.t.Fatal(err)
	}
	return raw
}

// hmacToken always HS256-signs with the panel mint secret.
// Staff tokens signed this way must be rejected.
func (c *cli) hmacToken(sub, use, jti string, scopes, servers []string) string {
	c.t.Helper()
	now := time.Now().UTC()
	raw, err := auth.Sign(c.srv.cfg.JWTSecret, auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    config.DefaultJWTIss,
			Subject:   sub,
			Audience:  jwt.ClaimStrings{config.DefaultJWTAud},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:     strings.Join(scopes, " "),
		TokenUse:  use,
		ServerIDs: servers,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	return raw
}

func (c *cli) idem() string {
	c.n++
	return fmt.Sprintf("idem-%04d", c.n)
}

func (c *cli) do(method, pth, token, idem string, body any) (int, []byte, http.Header) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+pth, rdr)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	if got := c.srv.WingsAttempts(); got != 0 {
		c.t.Fatalf("wings dispatch %d after %s %s", got, method, pth)
	}
	return resp.StatusCode, b, resp.Header
}

func (c *cli) expect(name, method, pth, token, idem string, body any, status int, code string) caseResult {
	c.t.Helper()
	st, b, hdr := c.do(method, pth, token, idem, body)
	got := errorCode(b)
	if st != status || got != code {
		c.t.Fatalf("%s: %s %s got %d %q want %d %q body %s", name, method, pth, st, got, status, code, b)
	}
	if !strings.Contains(hdr.Get("Content-Type"), "application/json") {
		c.t.Fatalf("%s: content-type %s", name, hdr.Get("Content-Type"))
	}
	if hdr.Get("X-Glass-Wings-Dispatch") != "0" || hdr.Get("X-Glass-Executor") != "noop" {
		c.t.Fatalf("%s: executor headers missing", name)
	}
	return caseResult{Name: name, Method: method, Path: pth, Status: st, Code: got, WingsDispatch: 0, Pass: true}
}

func errorCode(body []byte) string {
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &env)
	return env.Error.Code
}

func TestSecNOAEvidence(t *testing.T) {
	srv, c, ts := newHarness(t)
	d, err := deny.Load()
	if err != nil {
		t.Fatal(err)
	}
	denyUUID := d.UUIDs()[0]
	nonDeny := fixture.NonDenyServerID

	var b1 []caseResult
	for _, u := range d.UUIDs() {
		b1 = append(b1, c.expect(
			"power_deny_uuid_"+u,
			http.MethodPost, "/v1/servers/"+u+"/power", c.staff(), c.idem(),
			map[string]any{"action": "start"}, http.StatusForbidden, "managed_inventory_denied",
		))
	}
	b1 = append(b1, c.expect("console_ticket_deny_uuid", http.MethodPost, "/v1/servers/"+denyUUID+"/console-ticket", c.staff(), c.idem(), nil, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("files_list_deny_uuid", http.MethodGet, "/v1/servers/"+denyUUID+"/files?path=/", c.staff(), "", nil, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("backup_restore_deny_uuid", http.MethodPost, "/v1/servers/"+denyUUID+"/backups/"+fixture.BackupID+"/restore", c.staff(), c.idem(), nil, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("server_patch_deny_uuid", http.MethodPatch, "/v1/servers/"+denyUUID, c.staff(), c.idem(), map[string]any{"name": "nope"}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("server_delete_deny_uuid", http.MethodDelete, "/v1/servers/"+denyUUID, c.staff(), c.idem(), nil, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("server_create_wings_uuid", http.MethodPost, "/v1/servers", c.staff(), c.idem(), map[string]any{
		"name": "x", "egg_id": "egg", "entitlement_id": "ent", "wings_server_id": denyUUID,
	}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("server_create_sid_43", http.MethodPost, "/v1/servers", c.staff(), c.idem(), map[string]any{
		"name": "x", "egg_id": "egg", "entitlement_id": "ent", "sid": 43,
	}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("server_create_whmcs_ct211", http.MethodPost, "/v1/servers", c.staff(), c.idem(), map[string]any{
		"name": "x", "egg_id": "egg", "entitlement_id": "ent", "whmcs_ct": "CT211",
	}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("power_query_sid_99", http.MethodPost, "/v1/servers/"+nonDeny+"/power?sid=99", c.staff(), c.idem(), map[string]any{"action": "stop"}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("power_query_external_id_30", http.MethodPost, "/v1/servers/"+nonDeny+"/power?external_id=30", c.staff(), c.idem(), map[string]any{"action": "restart"}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("power_query_whmcs_ct210", http.MethodPost, "/v1/servers/"+nonDeny+"/power?whmcs_ct=210", c.staff(), c.idem(), map[string]any{"action": "kill"}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("power_query_whmcs_ct1220", http.MethodPost, "/v1/servers/"+nonDeny+"/power?whmcs_ct=CT1220", c.staff(), c.idem(), map[string]any{"action": "start"}, http.StatusForbidden, "managed_inventory_denied"))

	emptyAgent := c.token("agent-empty", auth.TokenUseAgent, "agent-empty", []string{"power"}, nil)
	b1 = append(b1, c.expect("empty_server_ids_still_denied", http.MethodPost, "/v1/servers/"+denyUUID+"/power", emptyAgent, c.idem(), map[string]any{"action": "start"}, http.StatusForbidden, "managed_inventory_denied"))
	wildAgent := c.token("agent-wild", auth.TokenUseAgent, "agent-wild", []string{"power"}, []string{"*"})
	b1 = append(b1, c.expect("overbroad_server_ids_still_denied", http.MethodPost, "/v1/servers/"+denyUUID+"/power", wildAgent, c.idem(), map[string]any{"action": "start"}, http.StatusForbidden, "managed_inventory_denied"))
	narrowAgent := c.token("agent-narrow", auth.TokenUseAgent, "agent-narrow", []string{"power"}, []string{nonDeny})
	b1 = append(b1, c.expect("agent_without_deny_id_still_denied", http.MethodPost, "/v1/servers/"+denyUUID+"/power", narrowAgent, c.idem(), map[string]any{"action": "start"}, http.StatusForbidden, "managed_inventory_denied"))
	readOnly := c.token("staff-readonly", auth.TokenUseStaff, "staff-readonly", []string{"servers:read"}, nil)
	b1 = append(b1, c.expect("deny_before_scope_check", http.MethodPost, "/v1/servers/"+denyUUID+"/power", readOnly, c.idem(), map[string]any{"action": "start"}, http.StatusForbidden, "managed_inventory_denied"))
	b1 = append(b1, c.expect("deny_before_idempotency", http.MethodPost, "/v1/servers/"+denyUUID+"/power", c.staff(), "", map[string]any{"action": "start"}, http.StatusForbidden, "managed_inventory_denied"))

	// Non-deny controls: empty and over-broad tokens still cannot act as all-servers.
	st, body, _ := c.do(http.MethodPost, "/v1/servers/"+nonDeny+"/power", emptyAgent, c.idem(), map[string]any{"action": "start"})
	if st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte("empty_server_ids")) {
		t.Fatalf("empty server_ids on non-deny: %d %s", st, body)
	}
	b1 = append(b1, caseResult{Name: "empty_server_ids_non_deny_forbidden", Method: http.MethodPost, Path: "/v1/servers/" + nonDeny + "/power", Status: st, Code: "forbidden", Pass: true})
	st, body, _ = c.do(http.MethodPost, "/v1/servers/"+nonDeny+"/power", wildAgent, c.idem(), map[string]any{"action": "start"})
	if st != http.StatusForbidden || !bytes.Contains(body, []byte("overbroad_server_ids")) {
		t.Fatalf("overbroad non-deny: %d %s", st, body)
	}
	b1 = append(b1, caseResult{Name: "overbroad_server_ids_non_deny_forbidden", Method: http.MethodPost, Path: "/v1/servers/" + nonDeny + "/power", Status: st, Code: "forbidden", Pass: true})

	agentRead := c.token("agent-list", auth.TokenUseAgent, "agent-list-evidence", []string{"servers:read"}, []string{nonDeny})
	st, body, _ = c.do(http.MethodGet, "/v1/servers", agentRead, "", nil)
	if st != http.StatusOK || errorCode(body) != "" || !bytes.Contains(body, []byte(nonDeny)) || !bytes.Contains(body, []byte(fixture.CommercialGlassID)) {
		t.Fatalf("list servers: %d %s", st, body)
	}
	for _, u := range d.UUIDs() {
		if bytes.Contains(body, []byte(u)) {
			t.Fatalf("list exposed deny uuid %s", u)
		}
	}
	if bytes.Contains(body, []byte(`"wings_server_id":"`)) {
		t.Fatalf("list named a wings server: %s", body)
	}
	b1 = append(b1, caseResult{Name: "list_servers_agent_non_deny", Method: http.MethodGet, Path: "/v1/servers", Status: st, Pass: true})
	b1 = append(b1, c.expect("get_server_deny_uuid", http.MethodGet, "/v1/servers/"+denyUUID, c.staff(), "", nil, http.StatusForbidden, "managed_inventory_denied"))

	// B3 agent mint.
	var b3 []caseResult
	for _, sc := range []string{"migrations:write", "migrations:read", "agents:manage"} {
		if containsScope(mintableAgentScopes, sc) {
			t.Fatalf("mintable enum contains %s", sc)
		}
		b3 = append(b3, c.expect("reject_scope_"+sc, http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
			"name": "a", "scopes": []string{sc}, "ttl_seconds": 60, "server_ids": []string{nonDeny},
		}, http.StatusBadRequest, "validation_failed"))
	}
	b3 = append(b3, c.expect("reject_empty_server_ids", http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{},
	}, http.StatusBadRequest, "validation_failed"))
	b3 = append(b3, c.expect("reject_omitted_server_ids", http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60,
	}, http.StatusBadRequest, "validation_failed"))
	b3 = append(b3, c.expect("reject_deny_uuid_in_server_ids", http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{denyUUID},
	}, http.StatusForbidden, "managed_inventory_denied"))
	b3 = append(b3, c.expect("reject_ttl_3601", http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 3601, "server_ids": []string{nonDeny},
	}, http.StatusBadRequest, "validation_failed"))
	b3 = append(b3, c.expect("reject_ttl_59", http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 59, "server_ids": []string{nonDeny},
	}, http.StatusBadRequest, "validation_failed"))
	child := c.token("agent:forged", auth.TokenUseAgent, "child-forged", []string{"agents:manage", "power"}, []string{nonDeny})
	st, body, _ = c.do(http.MethodPost, "/v1/agent-tokens", child, c.idem(), map[string]any{
		"name": "child", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{nonDeny},
	})
	if st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte("child")) {
		t.Fatalf("child token: %d %s", st, body)
	}
	b3 = append(b3, caseResult{Name: "reject_child_token", Method: http.MethodPost, Path: "/v1/agent-tokens", Status: st, Code: "forbidden", Pass: true})

	st, body, _ = c.do(http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
		"name": "ok", "scopes": []string{"servers:read", "power", "files"}, "ttl_seconds": 3600, "server_ids": []string{nonDeny},
	})
	if st != http.StatusCreated {
		t.Fatalf("mint: %d %s", st, body)
	}
	var minted struct {
		Scopes    []string `json:"scopes"`
		ServerIDs []string `json:"server_ids"`
		Token     string   `json:"token"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		t.Fatal(err)
	}
	for _, sc := range minted.Scopes {
		if sc == "migrations:read" || sc == "migrations:write" || sc == "agents:manage" {
			t.Fatalf("issued forbidden scope %s", sc)
		}
	}
	issued, err := auth.Parse(srv.cfg.JWTSecret, config.DefaultJWTIss, config.DefaultJWTAud, minted.Token, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !issued.IsAgent() || issued.AuthPath != auth.PathAgentHMAC || issued.HasScope("agents:manage") || issued.HasScope("migrations:write") {
		t.Fatalf("issued principal %+v", issued)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers", minted.Token, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(nonDeny)) {
		t.Fatalf("minted agent list: %d %s", st, body)
	}
	b3 = append(b3, caseResult{Name: "mint_ttl_3600", Method: http.MethodPost, Path: "/v1/agent-tokens", Status: http.StatusCreated, Pass: true})
	b3 = append(b3, caseResult{Name: "minted_agent_hs256_list", Method: http.MethodGet, Path: "/v1/servers", Status: st, Pass: true})
	agentMig := c.token("agent:mig", auth.TokenUseAgent, "agent-mig", []string{"migrations:write"}, []string{nonDeny})
	b3 = append(b3, c.expect("agent_cannot_call_migrations", http.MethodPost, "/v1/migrations/ptero", agentMig, c.idem(), map[string]any{
		"source_base_url": "https://ptero-test.glasshosting.internal", "source_api_token": "not-a-real-token",
	}, http.StatusForbidden, "forbidden"))

	// B4 console ticket.
	var b4ticket struct {
		MaxTTLSeconds             int    `json:"max_ttl_seconds"`
		SingleUse                 bool   `json:"single_use"`
		TTLWithinCap              bool   `json:"ttl_within_cap"`
		BoundServer               bool   `json:"bound_server"`
		BoundSubject              bool   `json:"bound_subject"`
		WebsocketURLHasTicket     bool   `json:"websocket_url_has_ticket"`
		WebsocketURLOmitsBearer   bool   `json:"websocket_url_omits_bearer"`
		FirstUpgradeStatus        int    `json:"first_upgrade_status"`
		SecondUseStatus           int    `json:"second_use_status"`
		BearerHandshakeStatus     int    `json:"bearer_handshake_status"`
		BearerHandshakeCode       string `json:"bearer_handshake_code"`
		BearerDidNotConsumeTicket bool   `json:"bearer_did_not_consume_ticket"`
		OtherServerStatus         int    `json:"other_server_status"`
		DenyMintStatus            int    `json:"deny_mint_status"`
		DenyUpgradeStatus         int    `json:"deny_upgrade_status"`
	}
	var b4cases []caseResult
	staffB4 := c.staff()
	st, body, _ = c.do(http.MethodPost, "/v1/servers/"+nonDeny+"/console-ticket", staffB4, c.idem(), nil)
	if st != http.StatusCreated {
		t.Fatalf("ticket mint: %d %s", st, body)
	}
	var ticket struct {
		Ticket        string `json:"ticket"`
		ExpiresAt     string `json:"expires_at"`
		WebsocketURL  string `json:"websocket_url"`
		ServerID      string `json:"server_id"`
		Subject       string `json:"subject"`
		MaxTTLSeconds int    `json:"max_ttl_seconds"`
		SingleUse     bool   `json:"single_use"`
	}
	if err := json.Unmarshal(body, &ticket); err != nil {
		t.Fatal(err)
	}
	exp, err := time.Parse(time.RFC3339, ticket.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if ticket.MaxTTLSeconds != 120 || !ticket.SingleUse || ticket.ServerID != nonDeny || ticket.Subject != "staff-secnoa" {
		t.Fatalf("ticket fields %+v", ticket)
	}
	if exp.After(time.Now().Add(120*time.Second)) || time.Until(exp) < 90*time.Second {
		t.Fatalf("ttl %s", exp)
	}
	if !strings.Contains(ticket.WebsocketURL, "ticket=") || !strings.Contains(ticket.WebsocketURL, nonDeny) || strings.Contains(ticket.WebsocketURL, "Bearer") {
		t.Fatalf("websocket url %s", ticket.WebsocketURL)
	}
	if !strings.HasPrefix(ticket.WebsocketURL, "wss://panel-api-test.glasshosting.internal/v1/servers/") {
		t.Fatalf("websocket url host %s", ticket.WebsocketURL)
	}
	b4ticket.MaxTTLSeconds = ticket.MaxTTLSeconds
	b4ticket.SingleUse = ticket.SingleUse
	b4ticket.TTLWithinCap = true
	b4ticket.BoundServer = true
	b4ticket.BoundSubject = true
	b4ticket.WebsocketURLHasTicket = true
	b4ticket.WebsocketURLOmitsBearer = true
	b4cases = append(b4cases, caseResult{Name: "mint_ticket", Method: http.MethodPost, Path: "/v1/servers/" + nonDeny + "/console-ticket", Status: st, Pass: true})

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/servers/" + nonDeny + "/console?ticket=" + url.QueryEscape(ticket.Ticket)
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		msg := ""
		if resp != nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			msg = fmt.Sprintf(" status=%d body=%s", resp.StatusCode, b)
		}
		t.Fatalf("ws upgrade: %v%s", err, msg)
	}
	_, frame, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(frame, []byte(`"executor":"noop"`)) || !bytes.Contains(frame, []byte(`"wings_dispatch":false`)) {
		t.Fatalf("frame %s", frame)
	}
	_ = conn.Close()
	b4ticket.FirstUpgradeStatus = http.StatusSwitchingProtocols
	_, resp, err = websocket.DefaultDialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("second use upgraded")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("second use resp %#v", resp)
	}
	resp.Body.Close()
	b4ticket.SecondUseStatus = resp.StatusCode

	st, body, _ = c.do(http.MethodPost, "/v1/servers/"+nonDeny+"/console-ticket", c.staff(), c.idem(), nil)
	if st != http.StatusCreated {
		t.Fatalf("second mint: %d %s", st, body)
	}
	var ticketB struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(body, &ticketB); err != nil {
		t.Fatal(err)
	}
	other := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	otherURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/servers/" + other + "/console?ticket=" + url.QueryEscape(ticketB.Ticket)
	_, resp, err = websocket.DefaultDialer.Dial(otherURL, nil)
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-server upgrade err=%v resp=%v", err, resp)
	}
	resp.Body.Close()
	b4ticket.OtherServerStatus = resp.StatusCode

	st, body, _ = c.do(http.MethodPost, "/v1/servers/"+nonDeny+"/console-ticket", c.staff(), c.idem(), nil)
	if st != http.StatusCreated {
		t.Fatal(string(body))
	}
	var ticketC struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(body, &ticketC); err != nil {
		t.Fatal(err)
	}
	bearerURL := ts.URL + "/v1/servers/" + nonDeny + "/console?ticket=" + url.QueryEscape(ticketC.Ticket)
	req, err := http.NewRequest(http.MethodGet, bearerURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.staff())
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	bresp, err := c.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bb, _ := io.ReadAll(bresp.Body)
	bresp.Body.Close()
	if bresp.StatusCode != http.StatusUnauthorized || errorCode(bb) != "unauthorized" || !bytes.Contains(bb, []byte("bearer_rejected")) {
		t.Fatalf("bearer handshake: %d %s", bresp.StatusCode, bb)
	}
	b4ticket.BearerHandshakeStatus = bresp.StatusCode
	b4ticket.BearerHandshakeCode = "unauthorized"
	b4cases = append(b4cases, caseResult{Name: "ws_bearer_rejected", Method: http.MethodGet, Path: "/v1/servers/" + nonDeny + "/console", Status: bresp.StatusCode, Code: "unauthorized", Pass: true})
	okURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/servers/" + nonDeny + "/console?ticket=" + url.QueryEscape(ticketC.Ticket)
	conn, _, err = websocket.DefaultDialer.Dial(okURL, nil)
	if err != nil {
		t.Fatalf("ticket consumed by rejected bearer: %v", err)
	}
	_ = conn.Close()
	b4ticket.BearerDidNotConsumeTicket = true

	b4cases = append(b4cases, c.expect("console_ticket_managed_inventory_denied", http.MethodPost, "/v1/servers/"+denyUUID+"/console-ticket", c.staff(), c.idem(), nil, http.StatusForbidden, "managed_inventory_denied"))
	b4ticket.DenyMintStatus = http.StatusForbidden
	planted, _, err := srv.plantTicketForTest(denyUUID, "staff-secnoa")
	if err != nil {
		t.Fatal(err)
	}
	denyURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/servers/" + denyUUID + "/console?ticket=" + url.QueryEscape(planted)
	_, resp, err = websocket.DefaultDialer.Dial(denyURL, nil)
	if err == nil || resp == nil {
		t.Fatal("deny server upgraded")
	}
	db, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || errorCode(db) != "managed_inventory_denied" {
		t.Fatalf("deny upgrade: %d %s", resp.StatusCode, db)
	}
	b4ticket.DenyUpgradeStatus = resp.StatusCode
	b4cases = append(b4cases, caseResult{Name: "ws_upgrade_managed_inventory_denied", Method: http.MethodGet, Path: "/v1/servers/" + denyUUID + "/console", Status: resp.StatusCode, Code: "managed_inventory_denied", Pass: true})
	if srv.WingsAttempts() != 0 {
		t.Fatal("wings after console")
	}

	// B2 migration inventory_only.
	var hits atomic.Int32
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "panel must not be dialed", http.StatusInternalServerError)
	}))
	t.Cleanup(source.Close)
	const canary = "CANARY-TOKEN-DO-NOT-LEAK"
	var b2cases []caseResult
	b2cases = append(b2cases, c.expect("include_managed_inventory_true_rejected", http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "source_api_token": canary, "include_managed_inventory": true,
		"founder_yes_attestation_id": "founder-yes-forged", "managed_inventory_allowlist": []string{denyUUID},
		"mode": "inventory_only",
	}, http.StatusForbidden, "forbidden"))
	b2cases = append(b2cases, c.expect("mode_import_rejected", http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "source_api_token": canary, "mode": "import",
	}, http.StatusForbidden, "forbidden"))
	b2cases = append(b2cases, c.expect("mode_cutover_rejected", http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "source_api_token": canary, "mode": "import_and_cutover", "dry_run": false,
	}, http.StatusForbidden, "forbidden"))

	st, body, hdr := c.do(http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "source_api_token": canary, "mode": "inventory_only", "include_managed_inventory": false, "dry_run": false,
	})
	if st != http.StatusAccepted {
		t.Fatalf("inventory: %d %s", st, body)
	}
	if bytes.Contains(body, []byte(canary)) || bytes.Contains(body, []byte("source_api_token")) {
		t.Fatal("source token leaked")
	}
	if hits.Load() != 0 {
		t.Fatalf("source panel hits %d", hits.Load())
	}
	var mig struct {
		ID                            string `json:"id"`
		Mode                          string `json:"mode"`
		DryRun                        bool   `json:"dry_run"`
		IncludeManagedInventory       bool   `json:"include_managed_inventory"`
		ManagedInventoryExcludedCount int    `json:"managed_inventory_excluded_count"`
		ServersPlanned                int    `json:"servers_planned"`
		ServersImported               int    `json:"servers_imported"`
		Status                        string `json:"status"`
	}
	if err := json.Unmarshal(body, &mig); err != nil {
		t.Fatal(err)
	}
	if mig.Mode != "inventory_only" || !mig.DryRun || mig.IncludeManagedInventory || mig.ServersImported != 0 || mig.ManagedInventoryExcludedCount != 11 || mig.ServersPlanned != 1 || mig.Status != "planned" {
		t.Fatalf("migration %+v", mig)
	}
	if hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatal("dispatch header")
	}
	st, body, _ = c.do(http.MethodGet, "/v1/migrations/"+mig.ID+"/remap", c.staff(), "", nil)
	if st != http.StatusOK {
		t.Fatalf("remap: %d %s", st, body)
	}
	var page struct {
		Data []struct {
			SourceServerID   string `json:"source_server_id"`
			Action           string `json:"action"`
			ManagedInventory bool   `json:"managed_inventory"`
			WHMCS            string `json:"whmcs_service_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	seenDeny := map[string]bool{}
	seenCT := map[string]bool{}
	for _, row := range page.Data {
		if row.ManagedInventory && row.Action != "skip_managed_inventory" {
			t.Fatalf("managed-inventory row not skipped: %+v", row)
		}
		if d.IsManagedInventoryUUID(row.SourceServerID) {
			seenDeny[row.SourceServerID] = true
		}
		if row.WHMCS != "" {
			seenCT[row.WHMCS] = row.Action == "skip_managed_inventory"
		}
		if row.SourceServerID == nonDeny && (row.ManagedInventory || row.Action != "import") {
			t.Fatalf("commercial row %+v", row)
		}
	}
	for _, u := range d.UUIDs() {
		if !seenDeny[u] {
			t.Fatalf("remap missing %s", u)
		}
	}
	for _, ct := range []string{"210", "211", "1220"} {
		if !seenCT[ct] {
			t.Fatalf("remap missing ct %s", ct)
		}
	}
	b2cases = append(b2cases, caseResult{Name: "inventory_only_non_deny_fixture", Method: http.MethodPost, Path: "/v1/migrations/ptero", Status: http.StatusAccepted, Pass: true})

	b2cases = append(b2cases, c.expect("remap_force_deny_uuid", http.MethodPatch, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"founder_yes_attestation_id": "forged",
		"rows":                       []any{map[string]any{"source_server_id": denyUUID, "action": "import"}},
	}, http.StatusForbidden, "managed_inventory_denied"))
	ctRow := "c210c210-0210-4210-8210-210210210210"
	b2cases = append(b2cases, c.expect("remap_force_whmcs_ct", http.MethodPatch, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"rows": []any{map[string]any{"source_server_id": ctRow, "action": "merge_existing", "founder_yes_attestation_id": "forged"}},
	}, http.StatusForbidden, "managed_inventory_denied"))
	b2cases = append(b2cases, c.expect("remap_non_deny_allowed", http.MethodPatch, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"rows": []any{map[string]any{"source_server_id": nonDeny, "action": "skip"}},
	}, http.StatusOK, ""))
	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/confirm", c.staff(), c.idem(), nil)
	if st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte("migrate_mode_max")) {
		t.Fatalf("confirm: %d %s", st, body)
	}
	b2cases = append(b2cases, caseResult{Name: "confirm_rejected", Method: http.MethodPost, Path: "/v1/migrations/" + mig.ID + "/confirm", Status: st, Code: "forbidden", Pass: true})
	st, body, hdr = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/rollback", c.staff(), c.idem(), map[string]any{"reason": "test"})
	if st != http.StatusOK || errorCode(body) != "" || !bytes.Contains(body, []byte(`"design_only":true`)) || !bytes.Contains(body, []byte(`"applied":false`)) || !bytes.Contains(body, []byte(`"rollback_window_hours":72`)) {
		t.Fatalf("rollback design: %d %s", st, body)
	}
	if hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatal("rollback executor headers")
	}
	b2cases = append(b2cases, caseResult{Name: "rollback_design_stub", Method: http.MethodPost, Path: "/v1/migrations/" + mig.ID + "/rollback", Status: st, Pass: true})
	st, body, _ = c.do(http.MethodGet, "/v1/migrations/"+mig.ID, c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"status":"planned"`)) || !bytes.Contains(body, []byte(`"servers_imported":0`)) {
		t.Fatalf("rollback mutated migration: %d %s", st, body)
	}

	// B5 exposure and B6 stubs.
	var b5cases []caseResult
	st, body, hdr = c.do(http.MethodGet, "/healthz", "", "", nil)
	if st != http.StatusOK || strings.TrimSpace(string(body)) != `{"ok":true}` {
		t.Fatalf("healthz %d %s", st, body)
	}
	if hdr.Get("X-Glass-Runtime") != "panel-api-test" {
		t.Fatalf("runtime header %s", hdr.Get("X-Glass-Runtime"))
	}
	b5cases = append(b5cases, caseResult{Name: "healthz", Method: http.MethodGet, Path: "/healthz", Status: st, Pass: true})
	for _, pth := range []string{"/docs", "/swagger", "/swagger/index.html", "/openapi.json", "/v1/openapi.json", "/redoc"} {
		b5cases = append(b5cases, c.expect("no_openapi_ui_"+pth, http.MethodGet, pth, "", "", nil, http.StatusNotFound, "not_found"))
	}
	staffHS := c.hmacToken("ops-hs256-staff", auth.TokenUseStaff, "jti-ops-hs256-staff", []string{"servers:read"}, nil)
	b5cases = append(b5cases, c.expect("reject_staff_hs256", http.MethodGet, "/v1/servers", staffHS, "", nil, http.StatusUnauthorized, "unauthorized"))
	prodAud := c.tokenIssAud("prod-user", auth.TokenUseStaff, "prod-aud", []string{"power"}, nil, config.DefaultJWTIss, "https://panel-api.glasshosting.com")
	b5cases = append(b5cases, c.expect("reject_prod_aud", http.MethodPost, "/v1/servers/"+nonDeny+"/power", prodAud, c.idem(), map[string]any{"action": "start"}, http.StatusUnauthorized, "unauthorized"))
	prodIss := c.tokenIssAud("prod-user", auth.TokenUseStaff, "prod-iss", []string{"power"}, nil, "https://portal.glasshosting.com", config.DefaultJWTAud)
	b5cases = append(b5cases, c.expect("reject_prod_iss", http.MethodPost, "/v1/servers/"+nonDeny+"/power", prodIss, c.idem(), map[string]any{"action": "start"}, http.StatusUnauthorized, "unauthorized"))
	b5cases = append(b5cases, c.expect("reject_anonymous_power", http.MethodPost, "/v1/servers/"+nonDeny+"/power", "", "", map[string]any{"action": "start"}, http.StatusUnauthorized, "unauthorized"))

	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	hresp, err := http.Get("http://127.0.0.1:8080/healthz")
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := io.ReadAll(hresp.Body)
	hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK || strings.TrimSpace(string(hb)) != `{"ok":true}` {
		t.Fatalf("loopback healthz %d %s", hresp.StatusCode, hb)
	}
	b5cases = append(b5cases, caseResult{Name: "loopback_8080_healthz", Method: http.MethodGet, Path: "/healthz", Status: hresp.StatusCode, Pass: true})

	accepted := []string{}
	rejected := []string{}
	for _, addr := range []string{"127.0.0.1:8080", "0.0.0.0:8080", "[::1]:8080"} {
		if err := config.ValidateListen(addr); err != nil {
			t.Fatal(err)
		}
		accepted = append(accepted, addr)
	}
	for _, addr := range []string{":8080", "1.2.3.4:8080", "10.10.1.43:8080", "127.0.0.1:9090"} {
		if err := config.ValidateListen(addr); err == nil {
			t.Fatalf("accepted public or odd bind %s", addr)
		}
		rejected = append(rejected, addr)
	}

	var b6cases []caseResult
	st, body, hdr = c.do(http.MethodPost, "/v1/servers/"+nonDeny+"/power", c.staff(), c.idem(), map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("non-deny power %d %s", st, body)
	}
	b6cases = append(b6cases, caseResult{Name: "non_deny_power_noop", Method: http.MethodPost, Path: "/v1/servers/" + nonDeny + "/power", Status: st, Pass: true})
	b6cases = append(b6cases, c.expect("non_deny_files_stub", http.MethodGet, "/v1/servers/"+nonDeny+"/files?path=/", c.staff(), "", nil, http.StatusOK, ""))
	b6cases = append(b6cases, c.expect("non_deny_restore_noop", http.MethodPost, "/v1/servers/"+nonDeny+"/backups/"+fixture.BackupID+"/restore", c.staff(), c.idem(), nil, http.StatusAccepted, ""))
	b6cases = append(b6cases, c.expect("non_deny_patch_stub", http.MethodPatch, "/v1/servers/"+nonDeny, c.staff(), c.idem(), map[string]any{"name": "renamed"}, http.StatusOK, ""))
	b6cases = append(b6cases, c.expect("non_deny_delete_noop", http.MethodDelete, "/v1/servers/"+nonDeny, c.staff(), c.idem(), nil, http.StatusAccepted, ""))
	b6cases = append(b6cases, c.expect("files_write_disabled", http.MethodPut, "/v1/servers/"+nonDeny+"/files/content?path=/server.properties", c.staff(), c.idem(), []byte("nope"), http.StatusForbidden, "forbidden"))
	b6cases = append(b6cases, c.expect("files_write_deny_uuid", http.MethodPut, "/v1/servers/"+denyUUID+"/files/content?path=/server.properties", c.staff(), c.idem(), []byte("nope"), http.StatusForbidden, "managed_inventory_denied"))
	b6cases = append(b6cases, c.expect("missing_idempotency_on_non_deny", http.MethodPost, "/v1/servers/"+nonDeny+"/power", c.staff(), "", map[string]any{"action": "start"}, http.StatusBadRequest, "validation_failed"))
	if srv.WingsAttempts() != 0 || hits.Load() != 0 {
		t.Fatalf("wings=%d source_hits=%d", srv.WingsAttempts(), hits.Load())
	}

	rl := runRateLimit(t)

	root := moduleRoot(t)
	spec, err := os.ReadFile(filepath.Join(root, "openapi", "glass-game-panel-v1.openapi.yaml"))
	if err != nil || !bytes.Contains(spec, []byte("version: 0.1.5-stub")) {
		t.Fatal("openapi 0.1.5-stub not found")
	}
	dir := filepath.Join(root, "artifacts", "api-evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, v any) {
		t.Helper()
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("summary.json", map[string]any{
		"spec":            "openapi/glass-game-panel-v1.openapi.yaml",
		"openapi_version": "0.1.5-stub",
		"runtime":         "cmd/panel-api-test",
		"deny_sha256":     srv.DenySHA256(),
		"wings_dispatch":  srv.WingsAttempts(),
		"result":          "pass",
		"gates":           []string{"B1", "B2", "B3", "B4", "B5", "B6"},
	})
	write("b1-managed-inventory-deny.json", gateDoc{
		Gate:   "B1",
		Proves: "Managed-inventory deny is middleware for power, files, console-ticket, backups/restore, delete, server write, and GET /v1/servers/{serverId}. GET /v1/servers returns the in-memory commercial fixture to an agent token scoped to that id and does not list denied servers. Empty and over-broad agent server_ids still cannot reach denied targets. Deny runs before scope checks, idempotency, and any executor.",
		Cases:  b1,
		Pass:   true,
	})
	write("b2-include-managed-inventory.json", map[string]any{
		"gate":   "B2",
		"proves": "TEST forces include_managed_inventory=false. A client boolean plus founder_yes_attestation_id plus allowlist is rejected. Remap cannot force managed-inventory rows. inventory_only plans a non-deny fixture and skips denied servers. Confirm is refused by the migrate mode ceiling. Rollback is a design stub and does not mutate.",
		"cases":  b2cases,
		"inventory_only": map[string]any{
			"status":                           http.StatusAccepted,
			"mode":                             mig.Mode,
			"include_managed_inventory":        mig.IncludeManagedInventory,
			"dry_run":                          mig.DryRun,
			"managed_inventory_excluded_count": mig.ManagedInventoryExcludedCount,
			"servers_planned":                  mig.ServersPlanned,
			"servers_imported":                 mig.ServersImported,
			"deny_uuids_skipped":               len(d.UUIDs()),
			"whmcs_cts_skipped":                []string{"210", "211", "1220"},
			"source_api_token_leaked":          false,
			"source_http_hits":                 hits.Load(),
		},
		"pass": true,
	})
	write("b3-agent-tokens.json", map[string]any{
		"gate":            "B3",
		"proves":          "Agent mint requires non-empty server_ids, rejects managed-inventory UUIDs, rejects migrations:read, migrations:write, and agents:manage, caps ttl_seconds at 3600, and does not let agent tokens mint children. The minted HS256 agent token is accepted on GET /v1/servers.",
		"mintable_scopes": mintableAgentScopes,
		"cases":           b3,
		"issued": map[string]any{
			"token_use":               "agent",
			"ttl_seconds":             3600,
			"forbidden_scopes_absent": true,
			"server_ids_non_empty":    len(minted.ServerIDs) == 1,
		},
		"pass": true,
	})
	write("b4-console-ticket.json", map[string]any{
		"gate":   "B4",
		"proves": "Console tickets are max 120s, single-use, and bound to serverId plus the minting subject. WebSocket auth is the ticket query only. Bearer on the handshake is rejected and does not consume the ticket. managed-inventory deny applies to mint and upgrade.",
		"cases":  b4cases,
		"ticket": b4ticket,
		"pass":   true,
	})
	write("b5-exposure-jwt.json", map[string]any{
		"gate":            "B5",
		"proves":          "The process defaults to 127.0.0.1:8080, rejects other binds, validates TEST JWT aud/iss, rejects prod aud/iss, rejects staff HS256, serves /healthz, and does not expose an OpenAPI UI. WG allowlist, non-public DNS, and the gateway 60/300 rpm are ops-attested by DevOps.",
		"listen_default":  config.DefaultListenAddr,
		"listen_accepted": accepted,
		"listen_rejected": rejected,
		"cases":           b5cases,
		"ops_attested": []string{
			"Host https://panel-api-test.glasshosting.internal is WG Method A in front of http://10.10.1.43:8080",
			"WG bind 10.99.0.40/32; allowlist 10.99.0.0/24 and 10.10.1.0/24",
			"Gateway rate limit 60 mutate / 300 read rpm already live",
			"No public DNS",
		},
		"pass": true,
	})
	write("b6-no-wings.json", map[string]any{
		"gate":             "B6",
		"proves":           "The executor is a noop. Dispatch count stays 0. The fixture inventory_only path does not dial a source panel. File writes and migration confirm are rejected. Rollback is a design stub and does not mutate. managed-inventory UUIDs are never mutated.",
		"cases":            b6cases,
		"wings_dispatch":   srv.WingsAttempts(),
		"source_http_hits": hits.Load(),
		"pass":             true,
	})
	write("rate-limit-60-300.json", rl)
}

func runRateLimit(t *testing.T) map[string]any {
	t.Helper()
	srv, c, _ := newHarness(t)
	frozen := time.Date(2026, 9, 27, 1, 0, 0, 0, time.UTC)
	srv.SetClockForTest(func() time.Time { return frozen })
	tok := c.token("staff-rate", auth.TokenUseStaff, "rate-limit-jti", []string{"power", "files"}, nil)
	allowed, blocked := 0, 0
	var blockedCode string
	for i := 0; i < 61; i++ {
		st, body, _ := c.do(http.MethodPost, "/v1/servers/"+fixture.NonDenyServerID+"/power", tok, fmt.Sprintf("mutate-%04d", i), map[string]any{"action": "start"})
		if i < 60 {
			if st != http.StatusAccepted {
				t.Fatalf("mutate %d: %d %s", i, st, body)
			}
			allowed++
			continue
		}
		if st != http.StatusTooManyRequests || errorCode(body) != "rate_limited" {
			t.Fatalf("mutate block: %d %s", st, body)
		}
		blocked = st
		blockedCode = errorCode(body)
	}
	readOK, readBlock := 0, 0
	var readCode string
	for i := 0; i < 301; i++ {
		st, body, _ := c.do(http.MethodGet, "/v1/servers/"+fixture.NonDenyServerID+"/files?path=/", tok, "", nil)
		if i < 300 {
			if st != http.StatusOK {
				t.Fatalf("read %d: %d %s", i, st, body)
			}
			readOK++
			continue
		}
		if st != http.StatusTooManyRequests || errorCode(body) != "rate_limited" {
			t.Fatalf("read block: %d %s", st, body)
		}
		readBlock = st
		readCode = errorCode(body)
	}
	if srv.WingsAttempts() != 0 {
		t.Fatal("wings during rate limit")
	}
	return map[string]any{
		"mutate_rpm":          60,
		"read_rpm":            300,
		"gateway_note":        "DevOps WG gateway already enforces 60 mutate / 300 read rpm per token (ops-attested). This binary enforces the same caps and refuses configuration above them.",
		"runtime_enforcement": "in-process fixed window per token jti",
		"mutate_allowed":      allowed,
		"mutate_next_status":  blocked,
		"mutate_next_code":    blockedCode,
		"read_allowed":        readOK,
		"read_next_status":    readBlock,
		"read_next_code":      readCode,
		"wings_dispatch":      srv.WingsAttempts(),
		"pass":                true,
	}
}

func containsScope(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
