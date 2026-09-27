package deny

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

//go:embed managed-inventory-deny.json
var rawMap []byte

// Hit is one deny-map match. Kind is uuid, sid, external_id, or whmcs_ct.
type Hit struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	SID        int    `json:"sid,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	ExternalID string `json:"external_id,omitempty"`
	Name       string `json:"name,omitempty"`
}

type serverRef struct {
	SID        int
	UUID       string
	ExternalID string
	Name       string
	Port       int
}

type fileMap struct {
	SIDs     []int    `json:"sids"`
	UUIDs    []string `json:"uuids"`
	WHMCSCTS []int    `json:"whmcs_cts"`
}

// Set is the loaded managed-inventory deny map. It cannot be disabled at runtime.
type Set struct {
	raw        []byte
	byUUID     map[string]serverRef
	bySID      map[int]serverRef
	byExternal map[string]serverRef
	whmcs      map[int]struct{}
	uuids      []string
	sids       []int
	cts        []int
}

// Raw returns the embedded deny file bytes (intact map).
func Raw() []byte {
	out := make([]byte, len(rawMap))
	copy(out, rawMap)
	return out
}

// SHA256 returns the hex digest of the embedded deny file.
func (s *Set) SHA256() string {
	sum := sha256.Sum256(s.raw)
	return hex.EncodeToString(sum[:])
}

// UUIDs returns deny UUIDs in map order.
func (s *Set) UUIDs() []string {
	out := make([]string, len(s.uuids))
	copy(out, s.uuids)
	return out
}

// SIDs returns deny SIDs in map order.
func (s *Set) SIDs() []int {
	out := make([]int, len(s.sids))
	copy(out, s.sids)
	return out
}

// WHMCS returns deny WHMCS CT ids in map order.
func (s *Set) WHMCS() []int {
	out := make([]int, len(s.cts))
	copy(out, s.cts)
	return out
}

// Load parses the embedded map and refuses to boot if it drifts from the
// OpenAPI catalog or the WHMCS CT set. A mismatch is fail-closed: the
// process does not start with a partial or substitute deny map.
func Load() (*Set, error) {
	var fm fileMap
	dec := json.NewDecoder(bytes.NewReader(rawMap))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fm); err != nil {
		return nil, fmt.Errorf("managed-inventory deny map: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("managed-inventory deny map: trailing json")
	}
	if len(fm.UUIDs) != len(catalog) || len(fm.SIDs) != len(catalog) {
		return nil, fmt.Errorf("managed-inventory deny map: want %d sids and uuids", len(catalog))
	}

	uuidSet := map[string]struct{}{}
	for _, u := range fm.UUIDs {
		n := normUUID(u)
		if n == "" {
			return nil, fmt.Errorf("managed-inventory deny map: bad uuid %q", u)
		}
		uuidSet[n] = struct{}{}
	}
	sidSet := map[int]struct{}{}
	for _, sid := range fm.SIDs {
		sidSet[sid] = struct{}{}
	}
	if len(uuidSet) != len(catalog) || len(sidSet) != len(catalog) {
		return nil, fmt.Errorf("managed-inventory deny map: duplicate entries")
	}

	s := &Set{
		raw:        append([]byte(nil), rawMap...),
		byUUID:     map[string]serverRef{},
		bySID:      map[int]serverRef{},
		byExternal: map[string]serverRef{},
		whmcs:      map[int]struct{}{},
		uuids:      make([]string, len(fm.UUIDs)),
		sids:       append([]int(nil), fm.SIDs...),
		cts:        append([]int(nil), fm.WHMCSCTS...),
	}
	for i, u := range fm.UUIDs {
		s.uuids[i] = normUUID(u)
	}
	for _, row := range catalog {
		u := normUUID(row.UUID)
		if _, ok := uuidSet[u]; !ok {
			return nil, fmt.Errorf("managed-inventory deny map missing catalog uuid %s", u)
		}
		if _, ok := sidSet[row.SID]; !ok {
			return nil, fmt.Errorf("managed-inventory deny map missing catalog sid %d", row.SID)
		}
		row.UUID = u
		s.byUUID[u] = row
		s.bySID[row.SID] = row
		if row.ExternalID == "" {
			return nil, fmt.Errorf("catalog sid %d missing external_id", row.SID)
		}
		s.byExternal[row.ExternalID] = row
		delete(uuidSet, u)
		delete(sidSet, row.SID)
	}
	if len(uuidSet) != 0 || len(sidSet) != 0 {
		return nil, fmt.Errorf("managed-inventory deny map has entries outside the OpenAPI catalog")
	}

	if len(fm.WHMCSCTS) != len(whmcsCTs) {
		return nil, fmt.Errorf("managed-inventory deny map: whmcs_cts drifted")
	}
	wantCT := map[int]struct{}{}
	for _, ct := range whmcsCTs {
		wantCT[ct] = struct{}{}
	}
	for _, ct := range fm.WHMCSCTS {
		if _, ok := wantCT[ct]; !ok {
			return nil, fmt.Errorf("managed-inventory deny map: unexpected whmcs ct %d", ct)
		}
		s.whmcs[ct] = struct{}{}
		delete(wantCT, ct)
	}
	if len(wantCT) != 0 {
		return nil, fmt.Errorf("managed-inventory deny map: missing whmcs ct")
	}
	return s, nil
}

// Targets are identifiers pulled from a request.
type Targets struct {
	UUIDs       []string
	SIDs        []int
	ExternalIDs []string
	WHMCS       []int
}

// Extract collects deny keys from the path id, query, and JSON body.
// UUID matches also scan the raw body so a deny UUID cannot hide in an
// unexpected field. SID, external_id, and WHMCS match structured keys only
// so unrelated integers (ports, limits) are not deny keys.
func Extract(serverID string, q url.Values, body []byte) Targets {
	var t Targets
	if u := normUUID(serverID); u != "" {
		t.UUIDs = append(t.UUIDs, u)
	}
	if q != nil {
		for _, v := range q["wings_server_id"] {
			if u := normUUID(v); u != "" {
				t.UUIDs = append(t.UUIDs, u)
			}
		}
		for _, v := range q["server_id"] {
			if u := normUUID(v); u != "" {
				t.UUIDs = append(t.UUIDs, u)
			}
		}
		for _, key := range []string{"sid", "wings_sid"} {
			for _, v := range q[key] {
				if n, ok := atoiStrict(v); ok {
					t.SIDs = append(t.SIDs, n)
				}
			}
		}
		for _, v := range q["external_id"] {
			if v = strings.TrimSpace(v); v != "" {
				t.ExternalIDs = append(t.ExternalIDs, v)
			}
		}
		for _, key := range []string{"whmcs_ct", "whmcs_service_id"} {
			for _, v := range q[key] {
				if n, ok := parseWHMCS(v); ok {
					t.WHMCS = append(t.WHMCS, n)
				}
			}
		}
	}
	if len(body) > 0 {
		t.UUIDs = append(t.UUIDs, rawUUIDHits(body)...)
		var v any
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if err := dec.Decode(&v); err == nil {
			walk(v, &t)
		}
	}
	return t
}

// Match returns deny hits for the extracted identifiers.
func (s *Set) Match(t Targets) []Hit {
	var hits []Hit
	seen := map[string]struct{}{}
	add := func(h Hit) {
		k := h.Kind + ":" + h.Value
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		hits = append(hits, h)
	}
	for _, u := range t.UUIDs {
		if row, ok := s.byUUID[normUUID(u)]; ok {
			add(Hit{Kind: "uuid", Value: row.UUID, SID: row.SID, UUID: row.UUID, ExternalID: row.ExternalID, Name: row.Name})
		}
	}
	for _, sid := range t.SIDs {
		if row, ok := s.bySID[sid]; ok {
			add(Hit{Kind: "sid", Value: strconv.Itoa(sid), SID: row.SID, UUID: row.UUID, ExternalID: row.ExternalID, Name: row.Name})
		}
	}
	for _, ext := range t.ExternalIDs {
		ext = strings.TrimSpace(ext)
		if row, ok := s.byExternal[ext]; ok {
			add(Hit{Kind: "external_id", Value: ext, SID: row.SID, UUID: row.UUID, ExternalID: row.ExternalID, Name: row.Name})
		}
	}
	for _, ct := range t.WHMCS {
		if _, ok := s.whmcs[ct]; ok {
			add(Hit{Kind: "whmcs_ct", Value: strconv.Itoa(ct)})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Kind == hits[j].Kind {
			return hits[i].Value < hits[j].Value
		}
		return hits[i].Kind < hits[j].Kind
	})
	return hits
}

// IsManagedInventoryUUID reports whether u is a deny-listed server UUID.
func (s *Set) IsManagedInventoryUUID(u string) bool {
	_, ok := s.byUUID[normUUID(u)]
	return ok
}

// IsManagedInventorySID reports whether sid is deny-listed.
func (s *Set) IsManagedInventorySID(sid int) bool {
	_, ok := s.bySID[sid]
	return ok
}

// IsManagedInventoryExternal reports whether external_id is deny-listed.
func (s *Set) IsManagedInventoryExternal(ext string) bool {
	_, ok := s.byExternal[strings.TrimSpace(ext)]
	return ok
}

// IsManagedInventoryWHMCS reports whether a WHMCS service id is CT210/211/1220.
func (s *Set) IsManagedInventoryWHMCS(ct int) bool {
	_, ok := s.whmcs[ct]
	return ok
}

func normUUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !uuidRe(s) {
		return ""
	}
	return s
}

func uuidRe(s string) bool {
	// 8-4-4-4-12 hex
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
	}
	return true
}

func rawUUIDHits(body []byte) []string {
	lower := strings.ToLower(string(body))
	var out []string
	for _, row := range catalog {
		u := normUUID(row.UUID)
		if strings.Contains(lower, u) {
			out = append(out, u)
		}
	}
	return out
}

func walk(v any, t *Targets) {
	switch n := v.(type) {
	case map[string]any:
		for k, child := range n {
			consider(k, child, t)
			walk(child, t)
		}
	case []any:
		for _, child := range n {
			walk(child, t)
		}
	}
}

func consider(key string, v any, t *Targets) {
	switch key {
	case "server_id", "serverId", "wings_server_id", "source_server_id", "glass_server_id", "uuid":
		if u := uuidFrom(v); u != "" {
			t.UUIDs = append(t.UUIDs, u)
		}
	case "server_ids", "managed_inventory_allowlist", "uuids":
		for _, item := range asArray(v) {
			if u := uuidFrom(item); u != "" {
				t.UUIDs = append(t.UUIDs, u)
			}
		}
	case "sid", "wings_sid", "server_sid":
		if n, ok := asInt(v); ok {
			t.SIDs = append(t.SIDs, n)
		}
	case "sids":
		for _, item := range asArray(v) {
			if n, ok := asInt(item); ok {
				t.SIDs = append(t.SIDs, n)
			}
		}
	case "external_id", "externalId":
		if s, ok := asString(v); ok && s != "" {
			t.ExternalIDs = append(t.ExternalIDs, s)
		}
	case "external_ids":
		for _, item := range asArray(v) {
			if s, ok := asString(item); ok && s != "" {
				t.ExternalIDs = append(t.ExternalIDs, s)
			}
		}
	case "whmcs_service_id", "whmcs_ct", "whmcsServiceId":
		if n, ok := asWHMCS(v); ok {
			t.WHMCS = append(t.WHMCS, n)
		}
	case "whmcs_cts":
		for _, item := range asArray(v) {
			if n, ok := asWHMCS(item); ok {
				t.WHMCS = append(t.WHMCS, n)
			}
		}
	}
}

func asArray(v any) []any {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	return a
}

func uuidFrom(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return normUUID(s)
}

func asString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t), true
	case json.Number:
		return t.String(), true
	default:
		return "", false
	}
}

func asInt(v any) (int, bool) {
	switch t := v.(type) {
	case json.Number:
		i, err := t.Int64()
		if err != nil || i < 0 || i > 1_000_000 {
			return 0, false
		}
		return int(i), true
	case string:
		return atoiStrict(t)
	default:
		return 0, false
	}
}

func asWHMCS(v any) (int, bool) {
	switch t := v.(type) {
	case json.Number:
		return asInt(t)
	case string:
		return parseWHMCS(t)
	default:
		return 0, false
	}
}

func atoiStrict(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func parseWHMCS(s string) (int, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimPrefix(s, "CT")
	return atoiStrict(s)
}
