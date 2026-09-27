package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/FuzzySpace/GlassGamePanel/internal/alloc"
	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/fixture"
)

// Phase A smoke A1–A4 and A7. A5 (CT/WHMCS/DNS HOLD) and A6 (Portal
// ModeGuard) are outside this process.
func TestPhaseACreateDualStack(t *testing.T) {
	srv, c, _ := newHarness(t)
	if srv.cfg.WingsExecutor != "noop" || srv.allocPool.Name() != alloc.PoolTorN5ULA || srv.allocPool.NodeID() != "5" {
		t.Fatalf("cfg executor=%s pool=%s node=%s", srv.cfg.WingsExecutor, srv.allocPool.Name(), srv.allocPool.NodeID())
	}
	if srv.allocPool.Prefix() != "fdba:17c8:6c94::/64" {
		t.Fatalf("prefix %s", srv.allocPool.Prefix())
	}
	d, err := deny.Load()
	if err != nil {
		t.Fatal(err)
	}
	staff := c.staff()
	free := srv.allocPool.Free()
	if free != 32 {
		t.Fatalf("free %d", free)
	}

	body := map[string]any{
		"name":           "phase-a-test",
		"egg_id":         "glasshosting-minecraft",
		"entitlement_id": "ent-phase-a-1",
		"limits":         map[string]any{"memory_mb": 2048, "backups": 1},
		"environment":    map[string]any{"DIFFICULTY": "normal"},
	}
	st, raw, hdr := c.do(http.MethodPost, "/v1/servers", staff, "idem-phase-a-1", body)
	if st != http.StatusAccepted {
		t.Fatalf("create: %d %s", st, raw)
	}
	if hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("headers %#v", hdr)
	}
	if srv.WingsAttempts() != 0 {
		t.Fatalf("wings dispatch %d", srv.WingsAttempts())
	}
	if srv.allocPool.Free() != 31 {
		t.Fatalf("free after create %d", srv.allocPool.Free())
	}
	var job map[string]any
	if err := json.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	if job["type"] != "server.create" || job["status"] != "succeeded" || job["wings_server_id"] != nil {
		t.Fatalf("job %#v", job)
	}
	serverID, _ := job["server_id"].(string)
	if !looksUUID(serverID) || serverID == fixture.NonDenyServerID || serverID == fixture.CommercialGlassID {
		t.Fatalf("server id %q", serverID)
	}
	for _, u := range d.UUIDs() {
		if serverID == u || bytes.Contains(raw, []byte(u)) {
			t.Fatalf("create touched deny uuid %s", u)
		}
	}
	if loc := hdr.Get("Location"); loc != "/v1/jobs/"+job["id"].(string) {
		t.Fatalf("location %s", loc)
	}
	assertDualStack(t, job["allocations"])
	result, _ := job["result"].(map[string]any)
	if result == nil || result["glass_server_id"] != serverID || result["wings_server_id"] != nil || result["executor"] != "noop" || result["wings_dispatch"] != false {
		t.Fatalf("result %#v", result)
	}
	if result["node_id"] != "5" || result["alloc_pool"] != "tor-n5-ula-test" || result["ula_prefix"] != "fdba:17c8:6c94::/64" || result["ula_routable"] != false || result["not_public_aaaa"] != true {
		t.Fatalf("ula metadata %#v", result)
	}
	assertDualStack(t, result["allocations"])

	st, got, hdr := c.do(http.MethodGet, "/v1/jobs/"+job["id"].(string), staff, "", nil)
	if st != http.StatusOK || hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("get job: %d %s", st, got)
	}
	var polled map[string]any
	if err := json.Unmarshal(got, &polled); err != nil {
		t.Fatal(err)
	}
	if polled["status"] != "succeeded" || polled["server_id"] != serverID {
		t.Fatalf("polled %#v", polled)
	}
	assertDualStack(t, polled["allocations"])

	st, got, _ = c.do(http.MethodGet, "/v1/servers/"+serverID, staff, "", nil)
	if st != http.StatusOK {
		t.Fatalf("get server: %d %s", st, got)
	}
	var server map[string]any
	if err := json.Unmarshal(got, &server); err != nil {
		t.Fatal(err)
	}
	if server["id"] != serverID || server["glass_server_id"] != serverID || server["wings_server_id"] != nil || server["node_id"] != "5" || server["alloc_pool"] != "tor-n5-ula-test" || server["entitlement_id"] != "ent-phase-a-1" {
		t.Fatalf("server %#v", server)
	}
	assertDualStack(t, server["allocations"])
	if bytes.Contains(got, []byte("45.45.239.7")) || bytes.Contains(got, []byte("10.99.0.34")) {
		t.Fatalf("server body named a forbidden address: %s", got)
	}

	// A7: same Idempotency-Key returns the original job and does not claim again.
	st, replay, hdr := c.do(http.MethodPost, "/v1/servers", staff, "idem-phase-a-1", body)
	if st != http.StatusAccepted || hdr.Get("Idempotency-Replay") != "true" || !bytes.Equal(replay, raw) {
		t.Fatalf("replay: %d replay=%q body=%s", st, hdr.Get("Idempotency-Replay"), replay)
	}
	if srv.allocPool.Free() != 31 {
		t.Fatalf("replay claimed again, free=%d", srv.allocPool.Free())
	}
	// A different key for the same entitlement must not claim a second pair.
	st, got, _ = c.do(http.MethodPost, "/v1/servers", staff, "idem-phase-a-2", body)
	if st != http.StatusConflict || errorCode(got) != "conflict" || !bytes.Contains(got, []byte("entitlement_already_created")) || !bytes.Contains(got, []byte(serverID)) {
		t.Fatalf("second entitlement: %d %s", st, got)
	}
	if srv.allocPool.Free() != 31 {
		t.Fatalf("entitlement replay claimed again, free=%d", srv.allocPool.Free())
	}

	// Explicit allowlisted node still claims one pair.
	st, got, _ = c.do(http.MethodPost, "/v1/servers", staff, "idem-phase-a-3", map[string]any{
		"name": "node-pin", "egg_id": "egg", "entitlement_id": "ent-phase-a-2", "node_id": "5",
	})
	if st != http.StatusAccepted || srv.allocPool.Free() != 30 {
		t.Fatalf("node 5 pin: %d free=%d %s", st, srv.allocPool.Free(), got)
	}

	before := srv.allocPool.Free()
	denyCases := []struct {
		name string
		path string
		body map[string]any
	}{
		{"uuid", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-uuid", "wings_server_id": d.UUIDs()[4]}},
		{"sid", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-sid", "sid": 43}},
		{"external", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-ext", "external_id": "48"}},
		{"ct", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-ct", "whmcs_ct": "CT1220"}},
		{"chi-node", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-node", "node_id": "1"}},
		{"chi-node-num", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-node-n", "node_id": 1}},
		{"chi-ip", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-ip", "ip": "45.45.239.7", "port": 25665}},
		{"chi-port", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-port", "port": 25566}},
		{"chi-alloc", "/v1/servers", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-alloc", "allocations": []any{map[string]any{"ip": "45.45.239.7", "port": 25667}}}},
		{"sid-query", "/v1/servers?sid=99", map[string]any{"name": "x", "egg_id": "e", "entitlement_id": "ent-deny-q"}},
	}
	for _, tc := range denyCases {
		st, got, hdr := c.do(http.MethodPost, tc.path, staff, c.idem(), tc.body)
		if st != http.StatusForbidden || errorCode(got) != "managed_inventory_denied" || !bytes.Contains(got, []byte(`"wings_dispatch":false`)) {
			t.Fatalf("%s: %d %s", tc.name, st, got)
		}
		if hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
			t.Fatalf("%s headers", tc.name)
		}
	}
	st, got, _ = c.do(http.MethodGet, "/v1/servers/"+d.UUIDs()[4], staff, "", nil)
	if st != http.StatusForbidden || errorCode(got) != "managed_inventory_denied" {
		t.Fatalf("get deny: %d %s", st, got)
	}
	st, got, hdr = c.do(http.MethodPost, "/v1/servers/"+d.UUIDs()[4]+"/power", staff, c.idem(), map[string]any{"action": "start"})
	if st != http.StatusForbidden || errorCode(got) != "managed_inventory_denied" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("power deny: %d %s", st, got)
	}
	if srv.allocPool.Free() != before || srv.WingsAttempts() != 0 {
		t.Fatalf("deny path mutated pool or wings: free %d attempts %d", srv.allocPool.Free(), srv.WingsAttempts())
	}

	st, got, _ = c.do(http.MethodPost, "/v1/servers", staff, c.idem(), map[string]any{
		"name": "x", "egg_id": "e", "entitlement_id": "ent-other-node", "node_id": "9",
	})
	if st != http.StatusForbidden || errorCode(got) != "forbidden" || !bytes.Contains(got, []byte("node_not_allowlisted")) {
		t.Fatalf("node 9: %d %s", st, got)
	}
	st, got, _ = c.do(http.MethodPost, "/v1/servers", staff, c.idem(), map[string]any{
		"name": "x", "egg_id": "e", "entitlement_id": "ent-opt-in", "include_managed_inventory": true,
	})
	if st != http.StatusForbidden || errorCode(got) != "forbidden" || !bytes.Contains(got, []byte("include_managed_inventory")) {
		t.Fatalf("opt-in: %d %s", st, got)
	}
	st, got, _ = c.do(http.MethodPost, "/v1/servers", staff, c.idem(), map[string]any{
		"name": "x", "egg_id": "e", "entitlement_id": "ent-pin-port", "port": 25600,
	})
	if st != http.StatusBadRequest || errorCode(got) != "validation_failed" || !bytes.Contains(got, []byte("allocation_pin_not_accepted")) {
		t.Fatalf("pool port pin: %d %s", st, got)
	}
	if srv.allocPool.Free() != before {
		t.Fatalf("refused create claimed a pair, free=%d want %d", srv.allocPool.Free(), before)
	}

	agent := c.token("agent-create", auth.TokenUseAgent, "agent-create", []string{"servers:write", "servers:read"}, []string{fixture.NonDenyServerID})
	st, got, hdr = c.do(http.MethodPost, "/v1/servers", agent, "idem-agent-create", map[string]any{
		"name": "agent-srv", "egg_id": "egg", "entitlement_id": "ent-agent-1",
	})
	if st != http.StatusAccepted || hdr.Get("X-Glass-Executor") != "noop" {
		t.Fatalf("agent create: %d %s", st, got)
	}
	if srv.allocPool.Free() != before-1 {
		t.Fatalf("agent free %d", srv.allocPool.Free())
	}
}

func TestCreateAllowlistRejectsManagedInventorySID(t *testing.T) {
	cfg := testConfig()
	cfg.JWTJWKSURL = "http://127.0.0.1:9/oidc/jwks.json"
	cfg.CreateNodeAllowlist = []string{"5", "43"}
	cfg.AllocPool = alloc.PoolTorN5ULA
	cfg.WingsExecutor = "noop"
	if _, err := New(cfg); err == nil {
		t.Fatal("allowlist containing managed-inventory SID 43 was accepted")
	}
	cfg.WingsExecutor = "real"
	cfg.CreateNodeAllowlist = []string{"5"}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if srv.cfg.WingsExecutor != "real" || !srv.cfg.WingsAllowlist.Empty() || srv.WingsAttempts() != 0 {
		t.Fatalf("real empty allowlist executor=%s attempts=%d", srv.cfg.WingsExecutor, srv.WingsAttempts())
	}
	cfg.WingsAllowlist = config.WingsAllowlist{Nodes: map[string]struct{}{"43": {}}}
	if _, err := New(cfg); err == nil {
		t.Fatal("wings allowlist node equal to managed-inventory SID 43 was accepted")
	}
}

func assertDualStack(t *testing.T, raw any) {
	t.Helper()
	arr, ok := raw.([]any)
	if !ok || len(arr) != 2 {
		t.Fatalf("allocations %#v", raw)
	}
	var v4, v6 map[string]any
	for _, item := range arr {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("row %#v", item)
		}
		switch row["family"] {
		case "ipv4":
			v4 = row
		case "ipv6":
			v6 = row
		default:
			t.Fatalf("family %#v", row["family"])
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("missing family %#v", arr)
	}
	port4, ok4 := v4["port"].(float64)
	port6, ok6 := v6["port"].(float64)
	if !ok4 || !ok6 || port4 != port6 || port4 < 25600 || port4 > 25631 {
		t.Fatalf("ports %#v %#v", v4["port"], v6["port"])
	}
	if v4["ip"] != "38.135.179.34" || v4["routable"] != true || v4["node_id"] != "5" || v4["alloc_pool"] != alloc.PoolTorN5ULA {
		t.Fatalf("ipv4 %#v", v4)
	}
	ip6, _ := v6["ip"].(string)
	if len(ip6) < len("fdba:17c8:6c94::") || ip6[:len("fdba:17c8:6c94::")] != "fdba:17c8:6c94::" || v6["routable"] != false || v6["node_id"] != "5" {
		t.Fatalf("ipv6 %#v", v6)
	}
	notes, _ := v6["notes"].(string)
	if notes == "" || !bytes.Contains([]byte(notes), []byte("not public AAAA")) {
		t.Fatalf("ipv6 notes %q", notes)
	}
	if v4["ip"] == "45.45.239.7" || v6["ip"] == "45.45.239.7" || v4["ip"] == "10.99.0.34" {
		t.Fatalf("forbidden address %#v %#v", v4, v6)
	}
}

func TestCreatePolicyZeroConfigStillValid(t *testing.T) {
	cfg := testConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg = cfg.WithCreateDefaults()
	if cfg.AllocPool != alloc.PoolTorN5ULA || cfg.CreateNodeAllowlist[0] != alloc.NodeTorN5 || cfg.WingsExecutor != "noop" {
		t.Fatalf("%+v", cfg)
	}
	if _, ok := config.CanonNodeID("05"); ok {
		t.Fatal("leading zero accepted")
	}
}
