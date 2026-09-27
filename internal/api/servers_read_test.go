package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/fixture"
)

func TestListAndGetServers(t *testing.T) {
	srv, c, _ := newHarness(t)
	d, err := deny.Load()
	if err != nil {
		t.Fatal(err)
	}
	nonDeny := fixture.NonDenyServerID
	glassID := fixture.CommercialGlassID
	denyUUID := d.UUIDs()[0]

	agent := c.token("agent-list", auth.TokenUseAgent, "agent-list", []string{"servers:read"}, []string{nonDeny})
	st, body, hdr := c.do(http.MethodGet, "/v1/servers", agent, "", nil)
	if st != http.StatusOK {
		t.Fatalf("list: %d %s", st, body)
	}
	if hdr.Get("X-Glass-Wings-Dispatch") != "0" || hdr.Get("X-Glass-Executor") != "noop" {
		t.Fatalf("list executor headers: %#v", hdr)
	}
	var page struct {
		Data []map[string]any `json:"data"`
		Next any              `json:"next_cursor"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if page.Next != nil {
		t.Fatalf("next_cursor %#v", page.Next)
	}
	if len(page.Data) != 1 {
		t.Fatalf("list data %#v", page.Data)
	}
	row := page.Data[0]
	if row["id"] != nonDeny || row["glass_server_id"] != glassID || row["name"] != "Commercial Fixture" || row["status"] != "offline" {
		t.Fatalf("fixture row %#v", row)
	}
	if row["wings_server_id"] != nil {
		t.Fatalf("wings_server_id %#v", row["wings_server_id"])
	}
	for _, key := range []string{"egg_id", "node_id", "created_at"} {
		s, _ := row[key].(string)
		if s == "" {
			t.Fatalf("missing %s in %#v", key, row)
		}
	}
	if _, ok := row["allocations"].([]any); !ok {
		t.Fatalf("allocations %#v", row["allocations"])
	}
	for _, u := range d.UUIDs() {
		if bytes.Contains(body, []byte(u)) {
			t.Fatalf("list exposed deny uuid %s: %s", u, body)
		}
	}

	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+nonDeny, agent, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(nonDeny)) || !bytes.Contains(body, []byte(glassID)) {
		t.Fatalf("get fixture: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+glassID, c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(nonDeny)) || !bytes.Contains(body, []byte(glassID)) {
		t.Fatalf("get glass id: %d %s", st, body)
	}

	for _, u := range d.UUIDs() {
		st, body, _ = c.do(http.MethodGet, "/v1/servers/"+u, agent, "", nil)
		if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
			t.Fatalf("get deny %s: %d %s", u, st, body)
		}
		if !bytes.Contains(body, []byte(`"wings_dispatch":false`)) {
			t.Fatalf("get deny dispatch flag: %s", body)
		}
	}
	powerOnly := c.token("agent-power", auth.TokenUseAgent, "agent-power-get-deny", []string{"power"}, []string{nonDeny})
	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+denyUUID, powerOnly, "", nil)
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
		t.Fatalf("deny before scope: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+nonDeny+"?sid=43", c.staff(), "", nil)
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
		t.Fatalf("get query sid: %d %s", st, body)
	}

	other := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	otherAgent := c.token("agent-other", auth.TokenUseAgent, "agent-other", []string{"servers:read"}, []string{other})
	st, body, _ = c.do(http.MethodGet, "/v1/servers", otherAgent, "", nil)
	if st != http.StatusOK || bytes.Contains(body, []byte(nonDeny)) || !bytes.Contains(body, []byte(`"data":[]`)) {
		t.Fatalf("unrelated agent list: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+nonDeny, otherAgent, "", nil)
	if st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte("server_not_in_token")) {
		t.Fatalf("unrelated agent get: %d %s", st, body)
	}
	empty := c.token("agent-empty-list", auth.TokenUseAgent, "agent-empty-list", []string{"servers:read"}, nil)
	st, body, _ = c.do(http.MethodGet, "/v1/servers", empty, "", nil)
	if st != http.StatusForbidden || !bytes.Contains(body, []byte("empty_server_ids")) {
		t.Fatalf("empty list: %d %s", st, body)
	}
	wild := c.token("agent-wild-list", auth.TokenUseAgent, "agent-wild-list", []string{"servers:read"}, []string{"*"})
	st, body, _ = c.do(http.MethodGet, "/v1/servers", wild, "", nil)
	if st != http.StatusForbidden || !bytes.Contains(body, []byte("overbroad_server_ids")) {
		t.Fatalf("overbroad list: %d %s", st, body)
	}
	noScope := c.token("agent-noscope", auth.TokenUseAgent, "agent-noscope", []string{"power"}, []string{nonDeny})
	st, body, _ = c.do(http.MethodGet, "/v1/servers", noScope, "", nil)
	if st != http.StatusForbidden || errorCode(body) != "forbidden" || !bytes.Contains(body, []byte("servers:read")) {
		t.Fatalf("missing scope: %d %s", st, body)
	}

	now := time.Now().UTC().Truncate(time.Second)
	srv.mu.Lock()
	srv.servers[denyUUID] = &serverRec{ID: denyUUID, Name: "deny-not-listable", Status: "running", EggID: "test-egg", NodeID: "test-node", Created: now, Updated: now}
	srv.mu.Unlock()
	st, body, _ = c.do(http.MethodGet, "/v1/servers", agent, "", nil)
	if st != http.StatusOK || bytes.Contains(body, []byte(denyUUID)) || !bytes.Contains(body, []byte(nonDeny)) {
		t.Fatalf("planted deny uuid listed: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+denyUUID, c.staff(), "", nil)
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
		t.Fatalf("planted deny get: %d %s", st, body)
	}
	if srv.WingsAttempts() != 0 {
		t.Fatalf("wings dispatch %d", srv.WingsAttempts())
	}

	st, body, _ = c.do(http.MethodGet, "/v1/servers?status=running", agent, "", nil)
	if st != http.StatusOK || bytes.Contains(body, []byte(nonDeny)) {
		t.Fatalf("status filter: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers?status=offline", c.staff(), "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(nonDeny)) {
		t.Fatalf("status offline: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers?status=nope", c.staff(), "", nil)
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" {
		t.Fatalf("bad status: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers/not-a-uuid", c.staff(), "", nil)
	if st != http.StatusBadRequest || errorCode(body) != "validation_failed" {
		t.Fatalf("bad path: %d %s", st, body)
	}
	unknown := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+unknown, c.staff(), "", nil)
	if st != http.StatusNotFound || errorCode(body) != "not_found" {
		t.Fatalf("unknown: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers?cursor="+nonDeny, agent, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(`"data":[]`)) {
		t.Fatalf("cursor past end: %d %s", st, body)
	}

	st, body, _ = c.do(http.MethodPost, "/v1/agent-tokens", c.staff(), c.idem(), map[string]any{
		"name": "smoke", "scopes": []string{"servers:read"}, "ttl_seconds": 60, "server_ids": []string{nonDeny},
	})
	if st != http.StatusCreated {
		t.Fatalf("mint: %d %s", st, body)
	}
	var minted struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &minted); err != nil {
		t.Fatal(err)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers", minted.Token, "", nil)
	if st != http.StatusOK || !bytes.Contains(body, []byte(nonDeny)) || bytes.Contains(body, []byte(denyUUID)) {
		t.Fatalf("minted agent list: %d %s", st, body)
	}
	st, body, _ = c.do(http.MethodGet, "/v1/servers/"+denyUUID, minted.Token, "", nil)
	if st != http.StatusForbidden || errorCode(body) != "managed_inventory_denied" {
		t.Fatalf("minted agent get deny: %d %s", st, body)
	}
	if srv.WingsAttempts() != 0 {
		t.Fatalf("wings dispatch %d", srv.WingsAttempts())
	}
}
