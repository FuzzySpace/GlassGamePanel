package deny

import (
	"bytes"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	// CHIAddress is the managed-inventory CHI Wings public IPv4 (the ".7" footprint).
	// Phase A must not claim its ports.
	CHIAddress = "45.45.239.7"
	// CHINodeID is the panel node that owns managed-inventory SIDs. Node 5 is the
	// allowlisted TEST capacity node and is not this id.
	CHINodeID = "1"
)

// ServerWriteFootprint reports managed-inventory CHI targets on a server_write
// body or query. Catalog ports are not generic deny keys (a bare integer in
// an unrelated field is ignored). A port hit requires a port field whose
// value is a managed-inventory catalog port, a node_id of the CHI node, or the
// CHI address itself.
func (s *Set) ServerWriteFootprint(q url.Values, body []byte) []Hit {
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
	if q != nil {
		for _, key := range []string{"ip", "address", "allocation_ip"} {
			for _, v := range q[key] {
				if chiAddr(v) {
					add(chiAddressHit())
				}
			}
		}
		for _, key := range []string{"node_id", "node"} {
			for _, v := range q[key] {
				if chiNode(v) {
					add(chiNodeHit())
				}
			}
		}
		for _, key := range []string{"port", "allocation_port", "listen_port"} {
			for _, v := range q[key] {
				if n, ok := atoiStrict(v); ok && s.IsManagedInventoryPort(n) {
					add(chiPortHit(n))
				}
			}
		}
	}
	if containsCHI(string(body)) {
		add(chiAddressHit())
	}
	if len(body) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			if m, ok := v.(map[string]any); ok {
				s.scanFootprintObject(m, add)
				for _, item := range asArray(m["allocations"]) {
					if child, ok := item.(map[string]any); ok {
						s.scanFootprintObject(child, add)
					}
				}
			}
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

// IsManagedInventoryPort reports whether port is a catalog managed-inventory listen port.
func (s *Set) IsManagedInventoryPort(port int) bool {
	for _, row := range catalog {
		if row.Port == port {
			return true
		}
	}
	return false
}

func (s *Set) scanFootprintObject(m map[string]any, add func(Hit)) {
	for _, key := range []string{"ip", "address", "allocation_ip", "bind_ip"} {
		if v, ok := m[key]; ok {
			if str, ok := asString(v); ok && chiAddr(str) {
				add(chiAddressHit())
			}
		}
	}
	for _, key := range []string{"node_id", "node"} {
		if v, ok := m[key]; ok && chiNodeValue(v) {
			add(chiNodeHit())
		}
	}
	for _, key := range []string{"port", "allocation_port", "listen_port"} {
		if v, ok := m[key]; ok {
			if n, ok := asInt(v); ok && s.IsManagedInventoryPort(n) {
				add(chiPortHit(n))
			}
		}
	}
}

func chiAddressHit() Hit {
	return Hit{Kind: "chi_address", Value: CHIAddress, Name: "managed-inventory address"}
}

func chiNodeHit() Hit {
	return Hit{Kind: "chi_node", Value: CHINodeID, Name: "managed-inventory node"}
}

func chiPortHit(port int) Hit {
	return Hit{Kind: "chi_port", Value: strconv.Itoa(port), Name: "managed-inventory port"}
}

func chiAddr(s string) bool {
	return strings.TrimSpace(s) == CHIAddress
}

func chiNode(s string) bool {
	return strings.TrimSpace(s) == CHINodeID
}

func chiNodeValue(v any) bool {
	if s, ok := asString(v); ok && chiNode(s) {
		return true
	}
	n, ok := asInt(v)
	return ok && n == 1
}

func containsCHI(s string) bool {
	const ip = CHIAddress
	for {
		i := strings.Index(s, ip)
		if i < 0 {
			return false
		}
		end := i + len(ip)
		if end >= len(s) || s[end] < '0' || s[end] > '9' {
			return true
		}
		s = s[end:]
	}
}
