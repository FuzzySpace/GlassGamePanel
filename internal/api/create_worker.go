package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/alloc"
	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
)

// createServer is the server.create worker. It claims one free IPv4+IPv6
// pair from the allowlisted node pool, records the Glass UUID with
// wings_server_id null, and completes the job before the 202 is written.
// The noop executor is not called. managed-inventory deny has already run.
func (s *Server) createServer(w http.ResponseWriter, r *http.Request, body []byte, rid string) {
	var probe map[string]any
	if err := json.Unmarshal(body, &probe); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid JSON body", rid, nil)
		return
	}
	if _, ok := probe["include_managed_inventory"]; ok {
		writeError(w, http.StatusForbidden, "forbidden", "TEST forces include_managed_inventory=false", rid, map[string]any{
			"reason":                    "test_forces_include_managed_inventory_false",
			"include_managed_inventory": false,
		})
		return
	}
	if _, ok := probe["founder_yes_attestation_id"]; ok {
		writeError(w, http.StatusForbidden, "forbidden", "managed-inventory opt-in is not authorized", rid, map[string]any{
			"reason": "managed_inventory_opt_in_denied",
		})
		return
	}
	for _, key := range []string{
		"sid", "wings_sid", "server_sid", "sids",
		"external_id", "externalId", "external_ids",
		"whmcs_ct", "whmcs_service_id", "whmcs_cts",
		"wings_server_id", "ip", "address", "port", "allocations", "allocation_port", "listen_port",
	} {
		if _, ok := probe[key]; ok {
			writeError(w, http.StatusBadRequest, "validation_failed", "create assigns allocations from the allowlisted pool and does not accept a Wings or address pin", rid, map[string]any{
				"field":  key,
				"reason": "allocation_pin_not_accepted",
			})
			return
		}
	}
	name, ok := asTrimmedString(probe["name"])
	eggID, eggOK := asTrimmedString(probe["egg_id"])
	entitlementID, entOK := asTrimmedString(probe["entitlement_id"])
	if !ok || !eggOK || !entOK || name == "" || eggID == "" || entitlementID == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "name, egg_id, and entitlement_id are required", rid, nil)
		return
	}
	if len(name) > 64 {
		writeError(w, http.StatusBadRequest, "validation_failed", "name must be 1..64 characters", rid, map[string]any{"field": "name"})
		return
	}
	if err := validateCreateExtras(probe); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), rid, nil)
		return
	}
	if r != nil {
		q := r.URL.Query()
		for _, key := range []string{"sid", "wings_sid", "external_id", "whmcs_ct", "whmcs_service_id", "port", "ip", "address", "allocation_port"} {
			if strings.TrimSpace(q.Get(key)) != "" {
				writeError(w, http.StatusBadRequest, "validation_failed", "create assigns allocations from the allowlisted pool and does not accept a Wings or address pin", rid, map[string]any{
					"field":  key,
					"reason": "allocation_pin_not_accepted",
				})
				return
			}
		}
	}
	nodeVal := probe["node_id"]
	if r != nil && strings.TrimSpace(r.URL.Query().Get("node_id")) != "" {
		qNode := strings.TrimSpace(r.URL.Query().Get("node_id"))
		if nodeVal == nil {
			nodeVal = qNode
		} else {
			bodyNode, st, code, details := s.resolveCreateNode(nodeVal)
			qResolved, qSt, qCode, qDetails := s.resolveCreateNode(qNode)
			if st != 0 {
				writeError(w, st, code, details["message"].(string), rid, details["details"])
				return
			}
			if qSt != 0 {
				writeError(w, qSt, qCode, qDetails["message"].(string), rid, qDetails["details"])
				return
			}
			if bodyNode != qResolved {
				writeError(w, http.StatusBadRequest, "validation_failed", "node_id query and body disagree", rid, map[string]any{"field": "node_id"})
				return
			}
			nodeVal = bodyNode
		}
	}
	nodeID, status, code, details := s.resolveCreateNode(nodeVal)
	if status != 0 {
		writeError(w, status, code, details["message"].(string), rid, details["details"])
		return
	}

	job, status, code, details := s.claimCreate(name, eggID, entitlementID, nodeID)
	if status != http.StatusAccepted {
		writeError(w, status, code, details["message"].(string), rid, details["details"])
		return
	}
	w.Header().Set("Location", "/v1/jobs/"+job["id"].(string))
	writeJSON(w, http.StatusAccepted, job)
}

func validateCreateExtras(probe map[string]any) error {
	if v, ok := probe["limits"]; ok && v != nil {
		if _, ok := v.(map[string]any); !ok {
			return errString("limits must be an object")
		}
	}
	if v, ok := probe["environment"]; ok && v != nil {
		m, ok := v.(map[string]any)
		if !ok {
			return errString("environment must be an object")
		}
		for _, val := range m {
			if _, ok := val.(string); !ok {
				return errString("environment values must be strings")
			}
		}
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }

func (s *Server) resolveCreateNode(v any) (string, int, string, map[string]any) {
	if v == nil {
		return s.allocPool.NodeID(), 0, "", nil
	}
	var raw string
	switch t := v.(type) {
	case string:
		raw = strings.TrimSpace(t)
		if raw == "" {
			return s.allocPool.NodeID(), 0, "", nil
		}
	case float64:
		if t != float64(int(t)) || t <= 0 {
			return "", http.StatusBadRequest, "validation_failed", failDetails("node_id must be a node id", map[string]any{"field": "node_id"})
		}
		raw = strconv.Itoa(int(t))
	case json.Number:
		i, err := t.Int64()
		if err != nil || i <= 0 {
			return "", http.StatusBadRequest, "validation_failed", failDetails("node_id must be a node id", map[string]any{"field": "node_id"})
		}
		raw = strconv.FormatInt(i, 10)
	default:
		return "", http.StatusBadRequest, "validation_failed", failDetails("node_id must be a node id", map[string]any{"field": "node_id"})
	}
	id, ok := config.CanonNodeID(raw)
	if !ok {
		return "", http.StatusBadRequest, "validation_failed", failDetails("node_id must be a node id", map[string]any{"field": "node_id"})
	}
	if id == config.ManagedInventoryCHINodeID || id == deny.CHINodeID {
		return "", http.StatusForbidden, "managed_inventory_denied", failDetails("managed-inventory target is denied", map[string]any{
			"op":             opServerWrite,
			"reason":         "chi_node",
			"node_id":        id,
			"wings_dispatch": false,
		})
	}
	if sid, err := strconv.Atoi(id); err == nil && s.deny.IsManagedInventorySID(sid) {
		return "", http.StatusForbidden, "managed_inventory_denied", failDetails("managed-inventory target is denied", map[string]any{
			"op":             opServerWrite,
			"reason":         "managed_inventory_sid",
			"node_id":        id,
			"wings_dispatch": false,
		})
	}
	if !s.cfg.AllowsCreateNode(id) {
		return "", http.StatusForbidden, "forbidden", failDetails("node is not on the create allowlist", map[string]any{
			"reason":  "node_not_allowlisted",
			"node_id": id,
		})
	}
	if id != s.allocPool.NodeID() {
		return "", http.StatusForbidden, "forbidden", failDetails("node has no dual-stack allocation pool", map[string]any{
			"reason":     "node_not_in_alloc_pool",
			"node_id":    id,
			"alloc_pool": s.allocPool.Name(),
		})
	}
	return id, 0, "", nil
}

func (s *Server) claimCreate(name, eggID, entitlementID, nodeID string) (map[string]any, int, string, map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.byEntitlement[entitlementID]; ok {
		return nil, http.StatusConflict, "conflict", failDetails("entitlement already has a server", map[string]any{
			"reason":         "entitlement_already_created",
			"server_id":      prev.ServerID,
			"job_id":         prev.JobID,
			"entitlement_id": entitlementID,
		})
	}
	pair, ok := s.allocPool.Claim()
	if !ok {
		return nil, http.StatusConflict, "conflict", failDetails("allocation pool has no free IPv4+IPv6 pair", map[string]any{
			"reason":     "allocation_pool_exhausted",
			"alloc_pool": s.allocPool.Name(),
			"node_id":    nodeID,
			"free_pairs": 0,
		})
	}
	now := time.Now().UTC().Truncate(time.Second)
	id := s.freshServerID()
	rec := &serverRec{
		ID:            id,
		Name:          name,
		Status:        "offline",
		EggID:         eggID,
		NodeID:        nodeID,
		GlassID:       id,
		EntitlementID: entitlementID,
		AllocPool:     s.allocPool.Name(),
		Allocations:   []alloc.Record{pair.IPv4, pair.IPv6},
		Created:       now,
		Updated:       now,
	}
	s.servers[id] = rec
	job := s.succeededCreateJob(newID(), rec, now)
	s.jobs[job["id"].(string)] = job
	s.byEntitlement[entitlementID] = createBinding{ServerID: id, JobID: job["id"].(string)}
	return job, http.StatusAccepted, "", nil
}

func (s *Server) freshServerID() string {
	for i := 0; i < 5; i++ {
		id := newID()
		if _, exists := s.servers[id]; exists || s.deny.IsManagedInventoryUUID(id) {
			continue
		}
		return id
	}
	return newID()
}

func (s *Server) succeededCreateJob(jobID string, rec *serverRec, now time.Time) map[string]any {
	allocs := recordsJSON(rec.Allocations)
	stamp := now.Format(time.RFC3339)
	return map[string]any{
		"id":               jobID,
		"type":             "server.create",
		"status":           "succeeded",
		"server_id":        rec.ID,
		"wings_server_id":  nil,
		"progress_percent": 100,
		"error_code":       nil,
		"created_at":       stamp,
		"updated_at":       stamp,
		"completed_at":     stamp,
		"allocations":      allocs,
		"result": map[string]any{
			"id":              rec.ID,
			"glass_server_id": rec.GlassID,
			"wings_server_id": nil,
			"node_id":         rec.NodeID,
			"alloc_pool":      rec.AllocPool,
			"ula_prefix":      alloc.PrefixTorN5ULA,
			"ula_routable":    false,
			"not_public_aaaa": true,
			"executor":        "noop",
			"wings_dispatch":  false,
			"entitlement_id":  rec.EntitlementID,
			"allocations":     allocs,
		},
	}
}

func failDetails(message string, details any) map[string]any {
	return map[string]any{"message": message, "details": details}
}

func asTrimmedString(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(s), true
}
