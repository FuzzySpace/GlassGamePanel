package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/ptero"
)

func TestPhaseBMigrateDryRun(t *testing.T) {
	d, err := deny.Load()
	if err != nil {
		t.Fatal(err)
	}
	denyUUID := d.UUIDs()[0]
	sid49 := ""
	for _, u := range d.UUIDs() {
		hits := d.Match(deny.Targets{UUIDs: []string{u}})
		if len(hits) > 0 && hits[0].SID == 49 {
			sid49 = u
			break
		}
	}
	if sid49 == "" {
		t.Fatal("sid 49 uuid missing")
	}
	const (
		envToken  = "test-ro-application-token"
		bodyToken = "request-body-token-unused"
		liveUUID  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
		extUUID   = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		ctUUID    = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	)
	var hits atomic.Int32
	var sawAuth atomic.Value
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("source method %s", r.Method)
		}
		if !strings.Contains(r.URL.Path, "/api/application/servers") {
			t.Errorf("path %s", r.URL.Path)
		}
		auth := r.Header.Get("Authorization")
		sawAuth.Store(auth)
		if strings.Contains(auth, bodyToken) || strings.Contains(r.URL.RawQuery, envToken) {
			t.Errorf("token leaked to source request")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
			{"attributes":{"id":19,"external_id":"19","uuid":"` + liveUUID + `","name":"Commercial Live","node":5,"nest":11,"egg":15,"relationships":{"allocations":{"data":[
				{"attributes":{"ip":"203.0.113.10","port":25565,"is_default":true}},
				{"attributes":{"ip":"2001:db8::20","port":25565,"is_default":false}}
			]}}}},
			{"attributes":{"id":49,"external_id":"53","uuid":"` + sid49 + `","name":"GlassMC HyTale","node":1,"nest":11,"egg":1}},
			{"attributes":{"id":8,"external_id":"8","uuid":"` + denyUUID + `","name":"Deny UUID","node":1,"nest":4,"egg":2}},
			{"attributes":{"id":4,"external_id":"47","uuid":"` + extUUID + `","name":"External deny","node":1,"nest":5,"egg":3}},
			{"attributes":{"id":7,"external_id":"CT1220","uuid":"` + ctUUID + `","name":"WHMCS CT","node":1,"nest":6,"egg":4}}
		],"meta":{"pagination":{"current_page":1,"total_pages":1}}}`))
	}))
	t.Cleanup(source.Close)

	client, err := ptero.New(source.URL, envToken)
	if err != nil {
		t.Fatal(err)
	}
	srv, c, _ := newHarness(t)
	srv.source = client

	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "other origin", http.StatusOK)
	}))
	t.Cleanup(other.Close)

	if st, body, _ := c.do(http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "source_api_token": bodyToken, "include_managed_inventory": true,
		"founder_yes_attestation_id": "forged", "managed_inventory_allowlist": []string{sid49},
	}); st != http.StatusForbidden || errorCode(body) != "forbidden" || hits.Load() != 0 {
		t.Fatalf("include probe: %d %s hits %d", st, body, hits.Load())
	}
	if st, body, _ := c.do(http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "mode": "import",
	}); st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte("migrate_mode_max")) || hits.Load() != 0 {
		t.Fatalf("import: %d %s hits %d", st, body, hits.Load())
	}
	if st, body, _ := c.do(http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "mode": "import_and_cutover", "dry_run": false,
	}); st != http.StatusForbidden || errorCode(body) != "forbidden" || hits.Load() != 0 {
		t.Fatalf("cutover: %d %s hits %d", st, body, hits.Load())
	}
	if st, body, _ := c.do(http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": other.URL, "mode": "inventory_only",
	}); st != http.StatusBadRequest || hits.Load() != 0 {
		t.Fatalf("origin mismatch: %d %s hits %d", st, body, hits.Load())
	}

	replayKey := "phaseb-replay-01"
	staff := c.staff()
	st, body, hdr := c.do(http.MethodPost, "/v1/migrations/ptero", staff, replayKey, map[string]any{
		"source_base_url": source.URL, "source_api_token": bodyToken, "mode": "inventory_only", "dry_run": false,
	})
	if st != http.StatusAccepted {
		t.Fatalf("inventory: %d %s", st, body)
	}
	if hdr.Get("X-Glass-Executor") != "noop" || hdr.Get("X-Glass-Wings-Dispatch") != "0" {
		t.Fatalf("headers executor=%s dispatch=%s", hdr.Get("X-Glass-Executor"), hdr.Get("X-Glass-Wings-Dispatch"))
	}
	if bytes.Contains(body, []byte(envToken)) || bytes.Contains(body, []byte(bodyToken)) || bytes.Contains(bytes.ToLower(body), []byte("nest")) {
		t.Fatalf("leak in plan: %s", body)
	}
	if hits.Load() != 1 {
		t.Fatalf("source hits %d", hits.Load())
	}
	if auth, _ := sawAuth.Load().(string); auth != "Bearer "+envToken {
		t.Fatalf("auth %q", auth)
	}
	var mig struct {
		ID       string `json:"id"`
		Mode     string `json:"mode"`
		ModeMax  string `json:"mode_max"`
		DryRun   bool   `json:"dry_run"`
		Include  bool   `json:"include_managed_inventory"`
		Excluded int    `json:"managed_inventory_excluded_count"`
		Planned  int    `json:"servers_planned"`
		Imported int    `json:"servers_imported"`
		Status   string `json:"status"`
		Executor string `json:"executor"`
		Dispatch bool   `json:"wings_dispatch"`
		WHMCS    bool   `json:"whmcs_mutate"`
	}
	if err := json.Unmarshal(body, &mig); err != nil {
		t.Fatal(err)
	}
	if mig.Mode != "inventory_only" || mig.ModeMax != "inventory_only" || !mig.DryRun || mig.Include || mig.Excluded != 4 || mig.Planned != 1 || mig.Imported != 0 || mig.Status != "planned" || mig.Executor != "noop" || mig.Dispatch || mig.WHMCS {
		t.Fatalf("migration %+v", mig)
	}
	for _, secret := range []string{sid49, denyUUID, extUUID, ctUUID} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatalf("plan listed managed-inventory %s", secret)
		}
	}

	st, body2, hdr2 := c.do(http.MethodPost, "/v1/migrations/ptero", staff, replayKey, map[string]any{
		"source_base_url": source.URL, "source_api_token": bodyToken, "mode": "inventory_only", "dry_run": false,
	})
	if st != http.StatusAccepted || hdr2.Get("Idempotency-Replay") != "true" || !bytes.Equal(body, body2) || hits.Load() != 1 {
		t.Fatalf("replay %d hits %d", st, hits.Load())
	}

	st, body, _ = c.do(http.MethodGet, "/v1/migrations", c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(mig.ID)) {
		t.Fatalf("list: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/migrations/"+mig.ID, c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"dry_run":true`)) {
		t.Fatalf("get: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/migrations/"+mig.ID+"/remap", c.staff(), "", nil)
	if st != http.StatusOK {
		t.Fatalf("remap: %d %s", st, body)
	}
	for _, secret := range []string{sid49, denyUUID, extUUID, ctUUID, "nest"} {
		if bytes.Contains(bytes.ToLower(body), []byte(strings.ToLower(secret))) {
			t.Fatalf("remap listed %s: %s", secret, body)
		}
	}
	var page struct {
		Data []struct {
			SourceServerID   string `json:"source_server_id"`
			Action           string `json:"action"`
			ManagedInventory bool   `json:"managed_inventory"`
			GlassServerID    string `json:"glass_server_id"`
			SourceEggID      string `json:"source_egg_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Data) != 1 || page.Data[0].SourceServerID != liveUUID || page.Data[0].Action != "import" || page.Data[0].ManagedInventory || page.Data[0].SourceEggID != "15" || page.Data[0].GlassServerID == "" {
		t.Fatalf("remap rows %+v", page.Data)
	}
	if !bytes.Contains(body, []byte("203.0.113.10")) || !bytes.Contains(body, []byte("2001:db8::20")) {
		t.Fatalf("allocations missing: %s", body)
	}
	glassID := page.Data[0].GlassServerID
	st, body, _ = c.do(http.MethodGet, "/v1/servers", c.staff(), "", nil)
	if st != http.StatusOK || bytes.Contains(body, []byte(glassID)) || bytes.Contains(body, []byte(liveUUID)) {
		t.Fatalf("plan uuid was written into server inventory: %d %s", st, body)
	}

	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"egg_map":  map[string]string{"15": "11"},
		"node_map": map[string]string{"5": "glass.node.tor5"},
	})
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" {
		t.Fatalf("numeric egg: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"egg_map": map[string]string{"15": "glass.nest.paper"},
	})
	if st != http.StatusBadRequest {
		t.Fatalf("nest egg key: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"nest_id": 11,
		"egg_map": map[string]string{"15": "glass.minecraft.paper"},
	})
	if st != http.StatusBadRequest || !bytes.Contains(body, []byte("customer_nest_id_rejected")) {
		t.Fatalf("nest field: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"rows": []any{map[string]any{"source_server_id": sid49, "action": "import"}},
	})
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
		t.Fatalf("remap managed-inventory: %d %s", st, body)
	}
	st, body, hdr = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/remap", c.staff(), c.idem(), map[string]any{
		"egg_map":  map[string]string{"15": "glass.minecraft.paper"},
		"node_map": map[string]string{"5": "glass.node.tor5"},
	})
	if st != http.StatusOK || bytes.Contains(bytes.ToLower(body), []byte("nest")) || !bytes.Contains(body, []byte("glass.minecraft.paper")) || !bytes.Contains(body, []byte("glass.node.tor5")) {
		t.Fatalf("egg map: %d %s", st, body)
	}
	if hdr.Get("X-Glass-Wings-Dispatch") != "0" || srv.WingsAttempts() != 0 {
		t.Fatal("remap dispatched")
	}

	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/confirm", c.staff(), c.idem(), map[string]any{
		"source_server_id": sid49,
	})
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
		t.Fatalf("confirm managed-inventory: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/confirm", c.staff(), c.idem(), nil)
	if st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte("migrate_mode_max")) {
		t.Fatalf("confirm ceiling: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodPost, "/v1/migrations/"+mig.ID+"/rollback", c.staff(), c.idem(), map[string]any{"reason": "design"})
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"design_only":true`)) || !bytes.Contains(body, []byte(`"applied":false`)) || !bytes.Contains(body, []byte(`"rollback_window_hours":72`)) {
		t.Fatalf("rollback: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/migrations/"+mig.ID, c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"status":"planned"`)) || !bytes.Contains(body, []byte(`"servers_imported":0`)) {
		t.Fatalf("status after stub: %d %s", st, body)
	}

	st, body, _ = c.do(http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "mode": "dry_run",
	})
	if st != http.StatusAccepted || !bytes.Contains(body, []byte(`"mode":"dry_run"`)) || !bytes.Contains(body, []byte(`"dry_run":true`)) || !bytes.Contains(body, []byte(`"servers_imported":0`)) {
		t.Fatalf("dry_run: %d %s", st, body)
	}
	if bytes.Contains(body, []byte(sid49)) || bytes.Contains(bytes.ToLower(body), []byte("nest")) {
		t.Fatalf("dry_run plan leaked: %s", body)
	}

	srv.cfg.MigrateDisabled = true
	before := hits.Load()
	st, body, _ = c.do(http.MethodPost, "/v1/migrations/ptero", c.staff(), c.idem(), map[string]any{
		"source_base_url": source.URL, "mode": "inventory_only",
	})
	if st != http.StatusForbidden || !bytes.Contains(body, []byte("migrate_disabled")) || hits.Load() != before {
		t.Fatalf("disabled: %d %s hits %d", st, body, hits.Load())
	}
	if srv.WingsAttempts() != 0 {
		t.Fatalf("wings %d", srv.WingsAttempts())
	}
}
