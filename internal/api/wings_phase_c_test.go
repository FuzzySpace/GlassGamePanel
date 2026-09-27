package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/fixture"
)

const (
	phaseCAllowUUID = "abababab-abab-4aba-8aba-abababababab"
	phaseCOtherUUID = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd"
	phaseCDenyUUID  = "cfe08e83-08f9-4515-a5d3-f84737b6723a"
)

func newConfiguredHarness(t *testing.T, mutate func(*config.Config)) (*Server, *cli) {
	t.Helper()
	key := genPortalKey(t)
	set := &portalJWKS{}
	const kid = "portal-test-1"
	set.publish(kid, &key.PublicKey)
	jwks := httptest.NewServer(set.handler())
	t.Cleanup(jwks.Close)
	cfg := testConfig()
	cfg.JWTJWKSURL = jwks.URL + "/oidc/jwks.json"
	if mutate != nil {
		mutate(&cfg)
	}
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
	return srv, c
}

func (c *cli) doOpen(method, pth, token, idem string, body any) (int, []byte, http.Header) {
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
	return resp.StatusCode, b, resp.Header
}

func TestPhaseCDefaultNoopDoesNotDispatch(t *testing.T) {
	srv, c := newConfiguredHarness(t, nil)
	if srv.cfg.WingsExecutor != config.WingsExecutorNoop || !srv.cfg.WingsAllowlist.Empty() {
		t.Fatalf("executor=%s allowlist=%d", srv.cfg.WingsExecutor, srv.cfg.WingsAllowlist.Len())
	}
	st, body, hdr := c.doOpen(http.MethodPost, "/v1/servers/"+phaseCAllowUUID+"/power", c.staff(), "idem-noop-power", map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("noop power %d attempts=%d hdr=%s/%s body=%s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Executor"), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
}

func TestPhaseCRealEmptyAllowlistFailClosed(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("empty allowlist dialed %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr := c.doOpen(http.MethodPost, "/v1/servers/"+phaseCAllowUUID+"/power", c.staff(), "idem-empty-power", map[string]any{"action": "start"})
	if st != http.StatusAccepted {
		t.Fatalf("power %d %s", st, body)
	}
	if hdr.Get("X-Glass-Executor") != "real" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("empty allowlist dispatched attempts=%d hdr=%s/%s", srv.WingsAttempts(), hdr.Get("X-Glass-Executor"), hdr.Get("X-Glass-Wings-Dispatch"))
	}
	st, body, hdr = c.doOpen(http.MethodGet, "/v1/servers/"+phaseCAllowUUID+"/files?path=/", c.staff(), "", nil)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("files %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/servers/"+phaseCAllowUUID+"/console-ticket", c.staff(), "idem-empty-console", nil)
	if st != http.StatusCreated || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("console %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if n := len(hits.snapshot()); n != 0 {
		t.Fatalf("empty allowlist hits %d", n)
	}
}

func TestPhaseCAllowlistedUUIDDispatches(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(phaseCAllowUUID)
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/power") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if strings.Contains(r.URL.Path, "/files/list-directory") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"name":"server.properties","file":true}]`))
			return
		}
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	staff := c.staff()

	st, body, hdr := c.doOpen(http.MethodPost, "/v1/servers/"+phaseCAllowUUID+"/power", staff, "idem-allow-power", map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Executor") != "real" || hdr.Get("X-Glass-Wings-Dispatch") != "1" || srv.WingsAttempts() != 1 || !bytes.Contains(body, []byte(`"wings_dialed":true`)) {
		t.Fatalf("allow power %d attempts=%d hdr=%s/%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Executor"), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	st, body, hdr = c.doOpen(http.MethodGet, "/v1/servers/"+phaseCAllowUUID, staff, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"wings_server_id":"`+phaseCAllowUUID+`"`)) {
		t.Fatalf("inventory %d %s", st, body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/servers/"+phaseCAllowUUID+"/power", staff, "idem-allow-power", map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("Idempotency-Replay") != "true" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 1 {
		t.Fatalf("replay %d attempts=%d replay=%s dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("Idempotency-Replay"), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	st, body, hdr = c.doOpen(http.MethodGet, "/v1/servers/"+phaseCAllowUUID+"/files?path=/", staff, "", nil)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "1" || srv.WingsAttempts() != 2 || !bytes.Contains(body, []byte(`"wings_dialed":true`)) {
		t.Fatalf("files %d attempts=%d dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/servers/"+phaseCAllowUUID+"/console-ticket", staff, "idem-allow-console", nil)
	if st != http.StatusCreated || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 2 {
		t.Fatalf("console %d attempts=%d dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/servers/"+phaseCOtherUUID+"/power", staff, "idem-other-power", map[string]any{"action": "stop"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 2 {
		t.Fatalf("unlisted uuid dispatched %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	st, body, hdr = c.doOpen(http.MethodGet, "/v1/servers/"+phaseCAllowUUID+"/files?path=/../etc", staff, "", nil)
	if st != http.StatusBadRequest || srv.WingsAttempts() != 2 {
		t.Fatalf("path escape %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	st, body, hdr = c.doOpen(http.MethodPut, "/v1/servers/"+phaseCAllowUUID+"/files/content?path=/server.properties", staff, "idem-file-write", []byte("nope"))
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" || !bytes.Contains(body, []byte(`"reason":"path_not_allowlisted"`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 2 {
		t.Fatalf("file write outside policy %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	got := hits.snapshot()
	if len(got) != 2 {
		t.Fatalf("wings hits %d", len(got))
	}
	if got[0].Method != http.MethodPost || got[0].Path != "/api/servers/"+phaseCAllowUUID+"/power" || got[0].Auth != "Bearer "+testWingsToken || got[0].Body != `{"action":"start"}` {
		t.Fatalf("power hit %+v", got[0])
	}
	if got[1].Method != http.MethodGet || got[1].Path != "/api/servers/"+phaseCAllowUUID+"/files/list-directory" || got[1].Query != "directory=%2F" || got[1].Auth != "Bearer "+testWingsToken {
		t.Fatalf("files hit %+v", got[1])
	}
	if bytes.Contains(body, []byte(testWingsToken)) {
		t.Fatal("token leaked into file-write response")
	}
}

func TestPhaseCNodeAllowlistDoesNotDial(t *testing.T) {
	allow, err := config.ParseWingsAllowlist("5")
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("node allowlist dialed %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	staff := c.staff()
	st, body, hdr := c.doOpen(http.MethodPost, "/v1/servers", staff, "idem-create-node5", map[string]any{
		"name": "phase-c", "egg_id": "egg", "entitlement_id": "ent-phase-c",
	})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("create dispatched %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	var job map[string]any
	if err := json.Unmarshal(body, &job); err != nil {
		t.Fatal(err)
	}
	id, _ := job["server_id"].(string)
	if id == "" {
		t.Fatalf("missing server_id %s", body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/servers/"+id+"/power", staff, "idem-node5-power", map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 || bytes.Contains(body, []byte(`"wings_dialed":true`)) {
		t.Fatalf("node 5 power dialed %d attempts=%d dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	st, body, hdr = c.doOpen(http.MethodGet, "/v1/servers/"+id, staff, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"wings_server_id":null`)) {
		t.Fatalf("node allowlist invented a wings uuid %d %s", st, body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/servers/"+fixture.NonDenyServerID+"/power", staff, "idem-fixture-power", map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("fixture node dispatched %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if n := len(hits.snapshot()); n != 0 {
		t.Fatalf("node allowlist hits %d", n)
	}
}

func TestPhaseCManagedInventoryDeniedEvenIfAllowlisted(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(phaseCDenyUUID + ",5")
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("managed-inventory dialed %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	rec := srv.ensureServer(phaseCDenyUUID)
	srv.mu.Lock()
	rec.NodeID = "5"
	srv.mu.Unlock()
	staff := c.staff()
	for _, tc := range []struct {
		name   string
		method string
		path   string
		idem   string
		body   any
	}{
		{"power", http.MethodPost, "/v1/servers/" + phaseCDenyUUID + "/power", "idem-sl-power", map[string]any{"action": "start"}},
		{"files", http.MethodGet, "/v1/servers/" + phaseCDenyUUID + "/files?path=/", "", nil},
		{"console", http.MethodPost, "/v1/servers/" + phaseCDenyUUID + "/console-ticket", "idem-sl-console", nil},
		{"whmcs", http.MethodPost, "/v1/servers/" + phaseCAllowUUID + "/power?whmcs_ct=210", "idem-sl-whmcs", map[string]any{"action": "kill"}},
		{"sid", http.MethodPost, "/v1/servers/" + phaseCAllowUUID + "/power?sid=49", "idem-sl-sid", map[string]any{"action": "stop"}},
		{"file_write", http.MethodPut, "/v1/servers/" + phaseCDenyUUID + "/files/content?path=/mods/fabric-api.jar", "idem-sl-write", []byte("nope")},
	} {
		st, body, hdr := c.doOpen(tc.method, tc.path, staff, tc.idem, tc.body)
		if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
			t.Fatalf("%s: %d dispatch=%s %s", tc.name, st, hdr.Get("X-Glass-Wings-Dispatch"), body)
		}
	}
	if srv.WingsAttempts() != 0 {
		t.Fatalf("managed-inventory dispatched %d", srv.WingsAttempts())
	}
	if n := len(hits.snapshot()); n != 0 {
		t.Fatalf("managed-inventory wings hits %d", n)
	}
}

func TestPhaseCAgentMintDenyAndOverbroad(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(phaseCAllowUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
	})
	staff := c.staff()
	st, body, hdr := c.doOpen(http.MethodPost, "/v1/agent-tokens", staff, "idem-mint-deny", map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{phaseCDenyUUID},
	})
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("deny mint %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	st, body, _ = c.doOpen(http.MethodPost, "/v1/agent-tokens", staff, "idem-mint-mix", map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{phaseCAllowUUID, phaseCDenyUUID},
	})
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
		t.Fatalf("mixed mint %d %s", st, body)
	}
	st, body, _ = c.doOpen(http.MethodPost, "/v1/agent-tokens", staff, "idem-mint-empty", map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{},
	})
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" {
		t.Fatalf("empty mint %d %s", st, body)
	}
	st, body, _ = c.doOpen(http.MethodPost, "/v1/agent-tokens", staff, "idem-mint-omit", map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60,
	})
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" {
		t.Fatalf("omitted mint %d %s", st, body)
	}
	st, body, _ = c.doOpen(http.MethodPost, "/v1/agent-tokens", staff, "idem-mint-star", map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{"*"},
	})
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" || !bytes.Contains(body, []byte("overbroad_server_ids")) {
		t.Fatalf("star mint %d %s", st, body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/agent-tokens", staff, "idem-mint-ok", map[string]any{
		"name": "a", "scopes": []string{"power"}, "ttl_seconds": 60, "server_ids": []string{phaseCAllowUUID},
	})
	if st != http.StatusCreated || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("allow mint %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
}
