package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/FuzzySpace/GlassGamePanel/internal/config"
)

const (
	testWingsToken = "test-wings-daemon-token"
	c2WingsUUID    = "d0c77bd4-0a24-4b2d-8e73-213f2b37dce4"
)

type wingsHit struct {
	Method      string
	Path        string
	Query       string
	Auth        string
	Body        string
	RequestID   string
	ContentType string
}

type wingsLog struct {
	mu   sync.Mutex
	hits []wingsHit
}

func (l *wingsLog) snapshot() []wingsHit {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]wingsHit, len(l.hits))
	copy(out, l.hits)
	return out
}

func newRecordingWings(t *testing.T, next http.HandlerFunc) (*httptest.Server, *wingsLog) {
	t.Helper()
	log := &wingsLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(b))
		log.mu.Lock()
		log.hits = append(log.hits, wingsHit{
			Method:      r.Method,
			Path:        r.URL.Path,
			Query:       r.URL.RawQuery,
			Auth:        r.Header.Get("Authorization"),
			Body:        string(b),
			RequestID:   r.Header.Get("X-Request-Id"),
			ContentType: r.Header.Get("Content-Type"),
		})
		log.mu.Unlock()
		if next != nil {
			next(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, log
}

func TestWingsDialAllowlistedPowerSetsInventory(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	const rid = "req-c2-power-dial-0001"
	st, body, hdr := c.doOpenID(http.MethodPost, "/v1/servers/"+c2WingsUUID+"/power", c.staff(), "idem-c2-power", rid, map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Wings-Dispatch") != "1" || hdr.Get("X-Request-Id") != rid || hdr.Get("X-Glass-Wings-HTTP-Status") != "204" || srv.WingsAttempts() != 1 {
		t.Fatalf("power %d attempts=%d dispatch=%s req=%s wings_status=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), hdr.Get("X-Request-Id"), hdr.Get("X-Glass-Wings-HTTP-Status"), body)
	}
	if bytes.Contains(body, []byte(testWingsToken)) {
		t.Fatalf("token leaked %s", body)
	}
	var job map[string]any
	if err := json.Unmarshal(body, &job); err != nil {
		t.Fatal(err)
	}
	if job["wings_dialed"] != true || job["wings_http_status"] != float64(http.StatusNoContent) || job["request_id"] != rid {
		t.Fatalf("job %#v", job)
	}
	got := hits.snapshot()
	if len(got) != 1 || got[0].Method != http.MethodPost || got[0].Path != "/api/servers/"+c2WingsUUID+"/power" || got[0].Auth != "Bearer "+testWingsToken || got[0].Body != `{"action":"start"}` || got[0].RequestID != rid {
		t.Fatalf("hit %+v", got)
	}
	st, body, hdr = c.doOpen(http.MethodGet, "/v1/servers/"+c2WingsUUID, c.staff(), "", nil)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "0" || !bytes.Contains(body, []byte(`"wings_server_id":"`+c2WingsUUID+`"`)) {
		t.Fatalf("get %d dispatch=%s %s", st, hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
}

func TestWingsDialRejectedStillCountsRoundTrip(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"missing `+testWingsToken+`"}`)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr := c.doOpen(http.MethodPost, "/v1/servers/"+c2WingsUUID+"/power", c.staff(), "idem-c2-reject", map[string]any{"action": "stop"})
	if st != http.StatusBadGateway || errorCode(body) != "wings_rejected" || hdr.Get("X-Glass-Wings-Dispatch") != "1" || srv.WingsAttempts() != 1 {
		t.Fatalf("reject %d attempts=%d dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	if bytes.Contains(body, []byte(testWingsToken)) || !bytes.Contains(body, []byte(`"wings_dialed":true`)) || !bytes.Contains(body, []byte(`"wings_http_status":404`)) {
		t.Fatalf("body %s", body)
	}
	if len(hits.snapshot()) != 1 {
		t.Fatalf("hits %d", len(hits.snapshot()))
	}
	st, body, _ = c.doOpen(http.MethodGet, "/v1/servers/"+c2WingsUUID, c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"wings_server_id":null`)) {
		t.Fatalf("inventory updated on reject %d %s", st, body)
	}
}

func TestWingsDialUnconfiguredFailsClosed(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
	})
	st, body, hdr := c.doOpen(http.MethodPost, "/v1/servers/"+c2WingsUUID+"/power", c.staff(), "idem-c2-unconfigured", map[string]any{"action": "restart"})
	if st != http.StatusBadGateway || errorCode(body) != "wings_dial_failed" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("unconfigured %d attempts=%d dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	if bytes.Contains(body, []byte(`"wings_dialed":true`)) || bytes.Contains(body, []byte(`"status":"queued"`)) {
		t.Fatalf("pretended success %s", body)
	}
	st, body, hdr = c.doOpen(http.MethodGet, "/v1/servers/"+c2WingsUUID+"/files?path=/", c.staff(), "", nil)
	if st != http.StatusBadGateway || errorCode(body) != "wings_dial_failed" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("files %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
}

func TestWingsDialNoopAllowlistDoesNotDial(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("noop dialed %s %s", r.Method, r.URL.Path)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorNoop
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr := c.doOpen(http.MethodPost, "/v1/servers/"+c2WingsUUID+"/power", c.staff(), "idem-c2-noop", map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("noop %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if bytes.Contains(body, []byte(`"wings_dialed":true`)) {
		t.Fatalf("noop claimed a dial %s", body)
	}
	if n := len(hits.snapshot()); n != 0 {
		t.Fatalf("noop hits %d", n)
	}
	st, body, _ = c.doOpen(http.MethodGet, "/v1/servers/"+c2WingsUUID, c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"wings_server_id":null`)) {
		t.Fatalf("noop inventory %d %s", st, body)
	}
}

func TestSecNOAClearSID49DoesNotDial(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(c2WingsUUID + "," + phaseCDenyUUID)
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, phaseCDenyUUID) {
			t.Errorf("managed-inventory uuid dialed %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	staff := c.staff()
	const rid = "req-clear-sid49-0001"
	st, body, hdr := c.doOpenID(http.MethodPost, "/v1/servers/"+phaseCDenyUUID+"/power", staff, "idem-clear-sid49", rid, map[string]any{"action": "start"})
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || hdr.Get("X-Glass-Executor") != "real" || srv.WingsAttempts() != 0 {
		t.Fatalf("sid49 uuid %d attempts=%d dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	st, body, hdr = c.doOpen(http.MethodPost, "/v1/servers/"+c2WingsUUID+"/power?sid=49", staff, "idem-clear-sid-query", map[string]any{"action": "stop"})
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("sid=49 %d attempts=%d dispatch=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	if n := len(hits.snapshot()); n != 0 {
		t.Fatalf("managed-inventory hits %d", n)
	}
	st, body, hdr = c.doOpenID(http.MethodPost, "/v1/servers/"+c2WingsUUID+"/power", staff, "idem-clear-uuid", "req-clear-uuid-0001", map[string]any{"action": "start"})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Wings-Dispatch") != "1" || hdr.Get("X-Request-Id") != "req-clear-uuid-0001" || srv.WingsAttempts() != 1 {
		t.Fatalf("allowlisted power %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	got := hits.snapshot()
	if len(got) != 1 || got[0].Path != "/api/servers/"+c2WingsUUID+"/power" || got[0].RequestID != "req-clear-uuid-0001" {
		t.Fatalf("hits %+v", got)
	}
	st, body, _ = c.doOpen(http.MethodGet, "/v1/servers/"+c2WingsUUID, staff, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"wings_server_id":"`+c2WingsUUID+`"`)) {
		t.Fatalf("inventory %d %s", st, body)
	}
}

func (c *cli) doOpenID(method, pth, token, idem, requestID string, body any) (int, []byte, http.Header) {
	c.t.Helper()
	return c.doOpenWithRequestID(method, pth, token, idem, requestID, body)
}

func (c *cli) doOpenWithRequestID(method, pth, token, idem, requestID string, body any) (int, []byte, http.Header) {
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
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
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
