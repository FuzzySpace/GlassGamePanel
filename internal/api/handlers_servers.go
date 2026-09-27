package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/alloc"
	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/fixture"
)

// seedInventory puts the commercial non-deny fixture in memory so
// GET /v1/servers can return it without dialing Wings. managed-inventory deny
// UUIDs are never seeded.
func (s *Server) seedInventory() {
	now := time.Now().UTC().Truncate(time.Second)
	c := fixture.CommercialFixture()
	id := strings.ToLower(fixture.NonDenyServerID)
	s.servers[id] = &serverRec{
		ID:      id,
		Name:    c.SourceName,
		Status:  "offline",
		EggID:   "test-egg",
		NodeID:  "test-node",
		GlassID: strings.ToLower(fixture.CommercialGlassID),
		Created: now,
		Updated: now,
	}
}

func (s *Server) handleCreateServer(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	s.createServer(w, r, body, rid)
}

func (s *Server) handlePatchServer(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	var req struct {
		Name *string  `json:"name"`
		Tags []string `json:"tags"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "validation_failed", "invalid JSON body", rid, nil)
			return
		}
	}
	rec := s.ensureServer(id)
	s.mu.Lock()
	if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
		rec.Name = strings.TrimSpace(*req.Name)
	}
	if req.Tags != nil {
		rec.Tags = append([]string(nil), req.Tags...)
	}
	rec.Updated = time.Now().UTC().Truncate(time.Second)
	out := serverJSON(rec)
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	limit, err := parsePageLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "limit must be an integer from 1 to 100", rid, map[string]any{"field": "limit"})
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && !validServerStatus(status) {
		writeError(w, http.StatusBadRequest, "validation_failed", "status is not a known server status", rid, map[string]any{"field": "status"})
		return
	}
	rows := s.visibleServers(p)
	if status != "" {
		filtered := make([]serverRec, 0, len(rows))
		for _, rec := range rows {
			if rec.Status == status {
				filtered = append(filtered, rec)
			}
		}
		rows = filtered
	}
	start := 0
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		start = len(rows)
		for i := range rows {
			if rows[i].ID == cursor {
				start = i + 1
				break
			}
		}
	}
	end := start + limit
	var next any
	if end < len(rows) {
		next = rows[end-1].ID
	}
	if end > len(rows) {
		end = len(rows)
	}
	data := make([]any, 0)
	if start < end {
		data = make([]any, 0, end-start)
		for i := start; i < end; i++ {
			rec := rows[i]
			data = append(data, serverJSON(&rec))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data, "next_cursor": next})
}

func (s *Server) handleGetServer(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	rec, ok := s.lookupServer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "server not found", rid, nil)
		return
	}
	writeJSON(w, http.StatusOK, serverJSON(&rec))
}

func (s *Server) handleDeleteServer(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	s.mu.Lock()
	delete(s.servers, id)
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, s.queueJob("server.delete", id))
}

func (s *Server) handlePower(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	var req struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid JSON body", rid, nil)
		return
	}
	switch req.Action {
	case "start", "stop", "restart", "kill":
	default:
		writeError(w, http.StatusBadRequest, "validation_failed", "action must be start, stop, restart, or kill", rid, map[string]any{"field": "action"})
		return
	}
	_ = s.ensureServer(id)
	res, outcome := s.dialAllowlisted(r.Context(), w, rid, opPower, id, req.Action, "")
	switch outcome {
	case dialSkip:
		writeJSON(w, http.StatusAccepted, s.queueJob("power", id))
	case dialOK:
		if s.cfg.WingsAllowlist.HasUUID(id) {
			s.rememberWingsServerID(id, id)
		}
		job := s.queueJob("power", id)
		job["wings_dialed"] = true
		job["wings_http_status"] = res.Status
		job["wings_body_summary"] = res.Summary
		job["request_id"] = rid
		writeJSON(w, http.StatusAccepted, job)
	default:
	}
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := r.PathValue("jobId")
	s.mu.Lock()
	job, ok := s.jobs[id]
	s.mu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "job not found", rid, nil)
		return
	}
	if p.IsAgent() {
		sid, _ := job["server_id"].(string)
		if sid != "" && !agentLists(p, sid) {
			writeError(w, http.StatusForbidden, "forbidden", "agent token cannot read this job", rid, map[string]any{"reason": "server_not_in_token"})
			return
		}
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Server) ensureServer(id string) *serverRec {
	id = strings.ToLower(id)
	now := time.Now().UTC().Truncate(time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.servers[id]; ok {
		return rec
	}
	rec := &serverRec{
		ID: id, Name: "test-fixture", Status: "offline", EggID: "test-egg", NodeID: "test-node",
		Created: now, Updated: now,
	}
	s.servers[id] = rec
	return rec
}

// rememberWingsServerID stores the Wings server UUID on the Glass row.
// Call it only after a successful allowlisted power whose path UUID is the
// Wings server id. managed-inventory rows are not updated.
func (s *Server) rememberWingsServerID(glassID, wingsID string) {
	glassID = strings.ToLower(strings.TrimSpace(glassID))
	wingsID = strings.ToLower(strings.TrimSpace(wingsID))
	if glassID == "" || wingsID == "" || s.deny.IsManagedInventoryUUID(glassID) || s.deny.IsManagedInventoryUUID(wingsID) {
		return
	}
	now := time.Now().UTC().Truncate(time.Second)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.servers[glassID]
	if rec == nil {
		return
	}
	rec.WingsServerID = wingsID
	rec.Updated = now
}

func (s *Server) queueJob(typ, serverID string) map[string]any {
	now := time.Now().UTC().Truncate(time.Second)
	id := newID()
	var sid any
	if serverID != "" {
		sid = serverID
	}
	job := map[string]any{
		"id":               id,
		"type":             typ,
		"status":           "queued",
		"server_id":        sid,
		"progress_percent": 0,
		"error_code":       nil,
		"created_at":       now.Format(time.RFC3339),
		"updated_at":       now.Format(time.RFC3339),
		"completed_at":     nil,
	}
	s.mu.Lock()
	s.jobs[id] = job
	s.mu.Unlock()
	return job
}

func serverJSON(rec *serverRec) map[string]any {
	tags := rec.Tags
	if tags == nil {
		tags = []string{}
	}
	var entitlement any
	if rec.EntitlementID != "" {
		entitlement = rec.EntitlementID
	}
	var wingsID any
	if rec.WingsServerID != "" {
		wingsID = rec.WingsServerID
	}
	out := map[string]any{
		"id":              rec.ID,
		"wings_server_id": wingsID,
		"name":            rec.Name,
		"status":          rec.Status,
		"egg_id":          rec.EggID,
		"node_id":         rec.NodeID,
		"entitlement_id":  entitlement,
		"allocations":     recordsJSON(rec.Allocations),
		"alloc_pool":      emptyAsNil(rec.AllocPool),
		"tags":            tags,
		"created_at":      rec.Created.Format(time.RFC3339),
		"updated_at":      rec.Updated.Format(time.RFC3339),
	}
	if rec.GlassID != "" {
		out["glass_server_id"] = rec.GlassID
	}
	return out
}

func (s *Server) visibleServers(p auth.Principal) []serverRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.servers))
	for id := range s.servers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	_, fixturePresent := s.servers[fixture.NonDenyServerID]
	rows := make([]serverRec, 0, len(ids))
	for _, id := range ids {
		rec := s.servers[id]
		if s.deny.IsManagedInventoryUUID(rec.ID) {
			continue
		}
		if rec.ID == fixture.CommercialGlassID && fixturePresent {
			continue
		}
		if !agentCanSeeServer(p, rec.ID) {
			continue
		}
		rows = append(rows, *rec)
	}
	return rows
}

func (s *Server) lookupServer(id string) (serverRec, bool) {
	id = strings.ToLower(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec, ok := s.servers[id]; ok && !s.deny.IsManagedInventoryUUID(rec.ID) {
		return *rec, true
	}
	if id == fixture.CommercialGlassID {
		if rec, ok := s.servers[fixture.NonDenyServerID]; ok && !s.deny.IsManagedInventoryUUID(rec.ID) {
			return *rec, true
		}
	}
	return serverRec{}, false
}

func agentCanSeeServer(p auth.Principal, id string) bool {
	if !p.IsAgent() {
		return true
	}
	if agentLists(p, id) {
		return true
	}
	id = strings.ToLower(id)
	if id == fixture.NonDenyServerID && agentLists(p, fixture.CommercialGlassID) {
		return true
	}
	if id == fixture.CommercialGlassID && agentLists(p, fixture.NonDenyServerID) {
		return true
	}
	return false
}

func parsePageLimit(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 25, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 100 {
		return 0, strconv.ErrRange
	}
	return n, nil
}

func validServerStatus(status string) bool {
	switch status {
	case "pending", "installing", "offline", "starting", "running", "stopping", "stopping_force", "suspended", "deleted":
		return true
	default:
		return false
	}
}

func looksUUID(s string) bool {
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
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

func recordsJSON(recs []alloc.Record) []any {
	if len(recs) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]any{
			"ip":         rec.IP,
			"port":       rec.Port,
			"family":     rec.Family,
			"notes":      rec.Notes,
			"ip_alias":   rec.IPAlias,
			"routable":   rec.Routable,
			"node_id":    rec.NodeID,
			"alloc_pool": rec.Pool,
		})
	}
	return out
}

func emptyAsNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func agentLists(p auth.Principal, serverID string) bool {
	serverID = strings.ToLower(serverID)
	for _, id := range p.ServerIDs {
		if id == serverID {
			return true
		}
	}
	return false
}
