package deny

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDenyMapIntact(t *testing.T) {
	root := moduleRoot(t)
	disk, err := os.ReadFile(filepath.Join(root, "managed-inventory-deny.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(disk, Raw()) {
		t.Fatalf("managed-inventory-deny.json drifted from the embedded map")
	}
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	wantUUIDs := []string{
		"d0ea9cbd-9706-443b-a734-d98a5055a450",
		"f060b25f-d720-4f36-ad00-2edba918eef0",
		"fdbfea6b-83aa-4fa3-8456-86f84369916c",
		"54f48d15-89e8-44e3-949c-f980547aedaf",
		"cfe08e83-08f9-4515-a5d3-f84737b6723a",
		"eaf90a23-50c5-43c5-bd57-9bd25bf6b22a",
		"8fc56418-30ac-4273-9e9a-1cdf9a24d7fd",
		"10f50377-a420-4269-8a09-a8fac9da27b8",
	}
	wantSIDs := []int{43, 46, 47, 48, 49, 99, 100, 101}
	wantCT := []int{210, 211, 1220}
	if !reflect.DeepEqual(s.UUIDs(), wantUUIDs) {
		t.Fatalf("uuids %#v", s.UUIDs())
	}
	if !reflect.DeepEqual(s.SIDs(), wantSIDs) {
		t.Fatalf("sids %#v", s.SIDs())
	}
	if !reflect.DeepEqual(s.WHMCS(), wantCT) {
		t.Fatalf("whmcs %#v", s.WHMCS())
	}

	spec, err := os.ReadFile(filepath.Join(root, "openapi", "glass-game-panel-v1.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(spec, []byte("version: 0.1.5-stub")) {
		t.Fatal("openapi version drifted from 0.1.5-stub")
	}
	// OpenAPI documents refuse behavior only. Inventory catalogs must not be
	// republished in the human-readable spec (machine deny map stays authoritative).
	if !bytes.Contains(spec, []byte("x-glass-managed-inventory-deny:")) {
		t.Fatal("openapi missing managed-inventory deny extension")
	}
	if !bytes.Contains(spec, []byte("managed_inventory_denied")) {
		t.Fatal("openapi missing managed_inventory_denied error code")
	}
	if !bytes.Contains(spec, []byte("embedded-deny-catalog")) {
		t.Fatal("openapi missing embedded-deny-catalog pointer")
	}
	for _, u := range wantUUIDs {
		if bytes.Contains(spec, []byte(u)) {
			t.Fatalf("openapi must not republish deny uuid %s", u)
		}
	}
	for _, leak := range []string{"whmcs_cts:", "by_sid:", "velocity_port_map:", "sids: [43"} {
		if bytes.Contains(spec, []byte(leak)) {
			t.Fatalf("openapi must not republish inventory catalog field %q", leak)
		}
	}
}

func TestMatchKeys(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	sid43 := s.Match(Targets{SIDs: []int{43}})
	if len(sid43) != 1 || sid43[0].UUID != "d0ea9cbd-9706-443b-a734-d98a5055a450" || sid43[0].ExternalID != "47" || sid43[0].Kind != "sid" {
		t.Fatalf("sid 43: %#v", sid43)
	}
	ext43 := s.Match(Targets{ExternalIDs: []string{"43"}})
	if len(ext43) != 1 || ext43[0].SID != 48 || ext43[0].UUID != "54f48d15-89e8-44e3-949c-f980547aedaf" {
		t.Fatalf("external_id 43 must be Palworld SID 48, got %#v", ext43)
	}
	ct := s.Match(Extract("", mapQuery("whmcs_ct", "CT1220"), nil))
	if len(ct) != 1 || ct[0].Kind != "whmcs_ct" || ct[0].Value != "1220" {
		t.Fatalf("ct: %#v", ct)
	}
	upper := s.Match(Extract("D0EA9CBD-9706-443B-A734-D98A5055A450", nil, nil))
	if len(upper) != 1 || upper[0].Kind != "uuid" {
		t.Fatalf("uuid case: %#v", upper)
	}
	// Ports and unrelated integers are not deny keys.
	body := []byte(`{"port":25566,"memory_mb":43,"name":"node-48","notes":"ct 210 nearby"}`)
	if hits := s.Match(Extract("11111111-1111-4111-8111-111111111111", nil, body)); len(hits) != 0 {
		t.Fatalf("unrelated integers matched: %#v", hits)
	}
	body = []byte(`{"action":"start","sid":46}`)
	hits := s.Match(Extract("11111111-1111-4111-8111-111111111111", nil, body))
	if len(hits) != 1 || hits[0].SID != 46 {
		t.Fatalf("body sid: %#v", hits)
	}
	body = []byte(`{"server_ids":["10f50377-a420-4269-8a09-a8fac9da27b8"]}`)
	hits = s.Match(Extract("", nil, body))
	if len(hits) != 1 || hits[0].SID != 101 {
		t.Fatalf("server_ids: %#v", hits)
	}
}

func TestServerWriteFootprint(t *testing.T) {
	s, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// A catalog port in an unrelated shape is still not a Match key.
	plain := []byte(`{"port":25566,"memory_mb":43,"name":"node-48","notes":"ct 210 nearby"}`)
	if hits := s.Match(Extract("", nil, plain)); len(hits) != 0 {
		t.Fatalf("match treated port as a deny key: %#v", hits)
	}
	// The same body is a server_write CHI port target.
	hits := s.ServerWriteFootprint(nil, plain)
	if len(hits) != 1 || hits[0].Kind != "chi_port" || hits[0].Value != "25566" {
		t.Fatalf("footprint port: %#v", hits)
	}
	if hits := s.ServerWriteFootprint(nil, []byte(`{"memory_mb":43,"name":"node-48","notes":"ct 210 nearby"}`)); len(hits) != 0 {
		t.Fatalf("notes are not a footprint: %#v", hits)
	}
	if hits := s.ServerWriteFootprint(nil, []byte(`{"port":25600,"node_id":"5"}`)); len(hits) != 0 {
		t.Fatalf("node 5 pool port is not CHI: %#v", hits)
	}
	if hits := s.ServerWriteFootprint(nil, []byte(`{"node_id":"1"}`)); len(hits) != 1 || hits[0].Kind != "chi_node" {
		t.Fatalf("node 1: %#v", hits)
	}
	if hits := s.ServerWriteFootprint(nil, []byte(`{"node_id":1}`)); len(hits) != 1 || hits[0].Kind != "chi_node" {
		t.Fatalf("node 1 number: %#v", hits)
	}
	body := []byte(`{"ip":"45.45.239.7","port":25665}`)
	hits = s.ServerWriteFootprint(nil, body)
	if len(hits) != 2 || hits[0].Kind != "chi_address" || hits[1].Kind != "chi_port" {
		t.Fatalf("chi ip+port: %#v", hits)
	}
	if hits := s.ServerWriteFootprint(nil, []byte(`{"notes":"45.45.239.70 is not the CHI address"}`)); len(hits) != 0 {
		t.Fatalf("boundary: %#v", hits)
	}
	if hits := s.ServerWriteFootprint(nil, []byte(`{"allocations":[{"ip":"38.135.179.34","port":25667}]}`)); len(hits) != 1 || hits[0].Value != "25667" {
		t.Fatalf("alloc port: %#v", hits)
	}
	q := mapQuery("port", "5500")
	if hits := s.ServerWriteFootprint(q, nil); len(hits) != 1 || hits[0].Kind != "chi_port" {
		t.Fatalf("query port: %#v", hits)
	}
}

func mapQuery(k, v string) map[string][]string {
	return map[string][]string{k: {v}}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
