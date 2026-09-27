package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/fixture"
	"github.com/FuzzySpace/GlassGamePanel/internal/ptero"
)

// sourceAPI is the read-only Application API. Implementations must not write
// to the source panel and must not dispatch to an executor.
type sourceAPI interface {
	ListServers(ctx context.Context) ([]ptero.Server, error)
	Origin() *url.URL
}

const rollbackWindowHours = 72

type migrationRec struct {
	ID            string
	Status        string
	SourceBaseURL string
	Mode          string
	ModeMax       string
	Filtered      int
	Excluded      int
	Planned       int
	Created       time.Time
	Updated       time.Time
	Rows          []remapRow
}

type planAlloc struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Default bool   `json:"default,omitempty"`
}

type remapRow struct {
	SourceServerID   string      `json:"source_server_id"`
	SourceName       string      `json:"source_name,omitempty"`
	SID              int         `json:"sid,omitempty"`
	ExternalID       string      `json:"external_id,omitempty"`
	WHMCSServiceID   string      `json:"whmcs_service_id,omitempty"`
	SourceNodeID     string      `json:"source_node_id,omitempty"`
	SourceEggID      string      `json:"source_egg_id,omitempty"`
	GlassServerID    *string     `json:"glass_server_id"`
	GlassNodeKey     string      `json:"glass_node_key,omitempty"`
	GlassEggKey      string      `json:"glass_egg_key,omitempty"`
	Allocations      []planAlloc `json:"allocations,omitempty"`
	ManagedInventory bool        `json:"managed_inventory"`
	Action           string      `json:"action"`
	Notes            string      `json:"notes,omitempty"`
}

func (s *Server) handleStartMigration(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	if s.cfg.MigrateDisabled {
		writeError(w, http.StatusForbidden, "forbidden", "migrate client is disabled", rid, map[string]any{
			"reason":         "migrate_disabled",
			"wings_dispatch": false,
			"executor":       "noop",
		})
		return
	}
	var req struct {
		SourceBaseURL             string   `json:"source_base_url"`
		SourceAPIToken            string   `json:"source_api_token"`
		Mode                      *string  `json:"mode"`
		IncludeManagedInventory   *bool    `json:"include_managed_inventory"`
		FounderYesAttestationID   string   `json:"founder_yes_attestation_id"`
		ManagedInventoryAllowlist []string `json:"managed_inventory_allowlist"`
		DryRun                    *bool    `json:"dry_run"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid JSON body", rid, nil)
		return
	}
	if req.IncludeManagedInventory != nil && *req.IncludeManagedInventory {
		// TEST forces include_managed_inventory=false. Attestation and allowlist
		// cannot opt in. No inventory row is imported and the source is not read.
		writeError(w, http.StatusForbidden, "forbidden", "TEST forces include_managed_inventory=false", rid, map[string]any{
			"reason":                    "test_forces_include_managed_inventory_false",
			"include_managed_inventory": false,
			"attestation_present":       strings.TrimSpace(req.FounderYesAttestationID) != "",
			"allowlist_ignored":         true,
			"wings_dispatch":            false,
			"executor":                  "noop",
		})
		return
	}
	mode, ok := planMode(req.Mode)
	if !ok {
		writeError(w, http.StatusForbidden, "forbidden", "GLASSPANEL_MIGRATE_MODE_MAX refuses import and import_and_cutover", rid, map[string]any{
			"reason":         "migrate_mode_max",
			"mode_max":       s.modeMax(),
			"wings_dispatch": false,
			"executor":       "noop",
		})
		return
	}
	u, err := url.Parse(strings.TrimSpace(req.SourceBaseURL))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "source_base_url must be an http(s) URL without userinfo", rid, map[string]any{"field": "source_base_url"})
		return
	}
	// The request token is never stored, logged, or sent. Discovery uses
	// PTERO_SOURCE_API_TOKEN only, and only against PTERO_SOURCE_API_URL.
	if s.source == nil && len(req.SourceAPIToken) < 8 {
		writeError(w, http.StatusBadRequest, "validation_failed", "source_api_token is required", rid, map[string]any{"field": "source_api_token"})
		return
	}
	var rows []remapRow
	filtered := 0
	if s.source != nil {
		origin := s.source.Origin()
		if origin == nil || !sameOrigin(u, origin) {
			writeError(w, http.StatusBadRequest, "validation_failed", "source_base_url must match PTERO_SOURCE_API_URL", rid, map[string]any{
				"field":  "source_base_url",
				"reason": "source_origin_mismatch",
			})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		rows, filtered, err = s.rowsFromSource(ctx)
		if err != nil {
			writeError(w, http.StatusBadGateway, "migration_source_unreachable", "source application api read failed", rid, map[string]any{
				"wings_dispatch": false,
				"executor":       "noop",
			})
			return
		}
	} else {
		rows = s.inventoryRows()
	}
	if rows == nil {
		rows = []remapRow{}
	}
	now := time.Now().UTC().Truncate(time.Second)
	rec := &migrationRec{
		ID:            newID(),
		Status:        "planned",
		SourceBaseURL: u.Scheme + "://" + u.Host,
		Mode:          mode,
		ModeMax:       s.modeMax(),
		Filtered:      filtered,
		Created:       now,
		Updated:       now,
		Rows:          rows,
	}
	rec.recount()
	s.mu.Lock()
	s.migs[rec.ID] = rec
	s.mu.Unlock()
	w.Header().Set("Location", "/v1/migrations/"+rec.ID)
	writeJSON(w, http.StatusAccepted, rec.public())
}

func (s *Server) handleListMigrations(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	if status != "" && !knownMigrationStatus(status) {
		writeError(w, http.StatusBadRequest, "validation_failed", "unknown migration status", rid, map[string]any{"field": "status"})
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 100 {
			writeError(w, http.StatusBadRequest, "validation_failed", "limit must be 1..100", rid, map[string]any{"field": "limit"})
			return
		}
		limit = n
	}
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	s.mu.Lock()
	list := make([]*migrationRec, 0, len(s.migs))
	for _, m := range s.migs {
		list = append(list, m)
	}
	s.mu.Unlock()
	sort.Slice(list, func(i, j int) bool {
		if list[i].Created.Equal(list[j].Created) {
			return list[i].ID < list[j].ID
		}
		return list[i].Created.After(list[j].Created)
	})
	if cursor != "" {
		idx := -1
		for i := range list {
			if list[i].ID == cursor {
				idx = i
				break
			}
		}
		if idx < 0 {
			writeError(w, http.StatusBadRequest, "validation_failed", "cursor is not a migration id", rid, map[string]any{"field": "cursor"})
			return
		}
		list = list[idx+1:]
	}
	var data []map[string]any
	var next any
	for _, m := range list {
		if status != "" && m.Status != status {
			continue
		}
		if len(data) == limit {
			next = data[len(data)-1]["id"]
			break
		}
		data = append(data, m.public())
	}
	if data == nil {
		data = []map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"data":        data,
		"next_cursor": next,
	})
}

func (s *Server) handleGetMigration(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	rec := s.migration(r.PathValue("migrationId"))
	if rec == nil {
		writeError(w, http.StatusNotFound, "not_found", "migration not found", rid, nil)
		return
	}
	writeJSON(w, http.StatusOK, rec.public())
}

func (s *Server) handleGetRemap(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	rec := s.migration(r.PathValue("migrationId"))
	if rec == nil {
		writeError(w, http.StatusNotFound, "not_found", "migration not found", rid, nil)
		return
	}
	writeJSON(w, http.StatusOK, remapPage(rec))
}

func (s *Server) handlePatchRemap(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	s.writeRemap(w, r, body, rid, false)
}

func (s *Server) handlePostRemap(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	s.writeRemap(w, r, body, rid, true)
}

func (s *Server) writeRemap(w http.ResponseWriter, r *http.Request, body []byte, rid string, allowMaps bool) {
	if customerNestKey(body) {
		writeError(w, http.StatusBadRequest, "validation_failed", "customer Nest IDs are not accepted", rid, map[string]any{
			"field":  "nest",
			"reason": "customer_nest_id_rejected",
		})
		return
	}
	rec := s.migration(r.PathValue("migrationId"))
	if rec == nil {
		writeError(w, http.StatusNotFound, "not_found", "migration not found", rid, nil)
		return
	}
	var req struct {
		Rows []struct {
			SourceServerID          string `json:"source_server_id"`
			Action                  string `json:"action"`
			GlassEggKey             string `json:"glass_egg_key"`
			GlassNodeKey            string `json:"glass_node_key"`
			GlassEggID              string `json:"glass_egg_id"`
			FounderYesAttestationID string `json:"founder_yes_attestation_id"`
		} `json:"rows"`
		EggMap                  map[string]string `json:"egg_map"`
		NodeMap                 map[string]string `json:"node_map"`
		FounderYesAttestationID string            `json:"founder_yes_attestation_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid JSON body", rid, nil)
		return
	}
	if len(req.Rows) == 0 && (!allowMaps || (len(req.EggMap) == 0 && len(req.NodeMap) == 0)) {
		writeError(w, http.StatusBadRequest, "validation_failed", "rows is required", rid, map[string]any{"field": "rows"})
		return
	}
	if !allowMaps && (len(req.EggMap) > 0 || len(req.NodeMap) > 0) {
		writeError(w, http.StatusBadRequest, "validation_failed", "egg_map and node_map are set with POST remap", rid, map[string]any{"field": "egg_map"})
		return
	}
	for src, dst := range req.EggMap {
		if !sourceMapKey(src) || !validGlassEggKey(dst) {
			writeError(w, http.StatusBadRequest, "validation_failed", "egg_map values must be internal Glass egg keys", rid, map[string]any{
				"field":  "egg_map",
				"reason": "glass_egg_key_rejected",
			})
			return
		}
	}
	for src, dst := range req.NodeMap {
		if !sourceMapKey(src) || !validGlassNodeKey(dst) {
			writeError(w, http.StatusBadRequest, "validation_failed", "node_map values must be internal Glass node keys", rid, map[string]any{
				"field":  "node_map",
				"reason": "glass_node_key_rejected",
			})
			return
		}
	}
	for i := range req.Rows {
		key := strings.TrimSpace(req.Rows[i].GlassEggKey)
		if alt := strings.TrimSpace(req.Rows[i].GlassEggID); alt != "" {
			if key != "" && key != alt {
				writeError(w, http.StatusBadRequest, "validation_failed", "glass_egg_id must match glass_egg_key", rid, map[string]any{"field": "glass_egg_id"})
				return
			}
			key = alt
		}
		req.Rows[i].GlassEggKey = key
		if key != "" && !validGlassEggKey(key) {
			writeError(w, http.StatusBadRequest, "validation_failed", "glass_egg_key must be an internal Glass egg key", rid, map[string]any{
				"field":  "glass_egg_key",
				"reason": "glass_egg_key_rejected",
			})
			return
		}
		req.Rows[i].GlassNodeKey = strings.TrimSpace(req.Rows[i].GlassNodeKey)
		if req.Rows[i].GlassNodeKey != "" && !validGlassNodeKey(req.Rows[i].GlassNodeKey) {
			writeError(w, http.StatusBadRequest, "validation_failed", "glass_node_key must be an internal Glass node key", rid, map[string]any{
				"field":  "glass_node_key",
				"reason": "glass_node_key_rejected",
			})
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	type change struct {
		idx     int
		action  string
		eggKey  string
		nodeKey string
		hasAct  bool
	}
	var changes []change
	for _, patch := range req.Rows {
		if patch.Action != "" {
			switch patch.Action {
			case "import", "skip", "skip_managed_inventory", "merge_existing":
			default:
				writeError(w, http.StatusBadRequest, "validation_failed", "invalid remap action", rid, map[string]any{"field": "action"})
				return
			}
		}
		idx := -1
		for i := range rec.Rows {
			if strings.EqualFold(rec.Rows[i].SourceServerID, patch.SourceServerID) {
				idx = i
				break
			}
		}
		if idx < 0 {
			writeError(w, http.StatusNotFound, "not_found", "remap source_server_id not in this migration", rid, nil)
			return
		}
		row := rec.Rows[idx]
		force := patch.Action == "import" || patch.Action == "merge_existing"
		if row.ManagedInventory && (force || patch.GlassEggKey != "" || patch.GlassNodeKey != "") {
			writeError(w, http.StatusForbidden, "managed_inventory_denied", "remap cannot force a managed-inventory row on TEST", rid, map[string]any{
				"reason":              "remap_managed_inventory_force_rejected",
				"source_server_id":    row.SourceServerID,
				"attestation_present": strings.TrimSpace(patch.FounderYesAttestationID+req.FounderYesAttestationID) != "",
				"wings_dispatch":      false,
				"executor":            "noop",
			})
			return
		}
		changes = append(changes, change{
			idx: idx, action: patch.Action, eggKey: patch.GlassEggKey, nodeKey: patch.GlassNodeKey, hasAct: patch.Action != "",
		})
	}
	for _, ch := range changes {
		row := &rec.Rows[ch.idx]
		if row.ManagedInventory {
			row.Action = "skip_managed_inventory"
			continue
		}
		if ch.hasAct {
			row.Action = ch.action
		}
		if ch.eggKey != "" {
			row.GlassEggKey = ch.eggKey
		}
		if ch.nodeKey != "" {
			row.GlassNodeKey = ch.nodeKey
		}
	}
	for i := range rec.Rows {
		row := &rec.Rows[i]
		if row.ManagedInventory || (row.Action != "import" && row.Action != "merge_existing") {
			continue
		}
		if k, ok := req.EggMap[row.SourceEggID]; ok {
			row.GlassEggKey = k
		}
		if k, ok := req.NodeMap[row.SourceNodeID]; ok {
			row.GlassNodeKey = k
		}
	}
	rec.Updated = time.Now().UTC().Truncate(time.Second)
	rec.recount()
	writeJSON(w, http.StatusOK, remapPage(rec))
}

func (s *Server) handleConfirmMigration(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	rec := s.migration(r.PathValue("migrationId"))
	if rec == nil {
		writeError(w, http.StatusNotFound, "not_found", "migration not found", rid, nil)
		return
	}
	// Hard ceiling: this binary never starts import or cutover.
	writeError(w, http.StatusForbidden, "forbidden", "confirm is refused while GLASSPANEL_MIGRATE_MODE_MAX is inventory_only or dry_run", rid, map[string]any{
		"reason":         "migrate_mode_max",
		"mode_max":       s.modeMax(),
		"migration_mode": rec.Mode,
		"wings_dispatch": false,
		"executor":       "noop",
		"whmcs_mutate":   false,
	})
}

func (s *Server) handleRollbackDesign(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	rec := s.migration(r.PathValue("migrationId"))
	if rec == nil {
		writeError(w, http.StatusNotFound, "not_found", "migration not found", rid, nil)
		return
	}
	// Design stub only. Status, rows, Wings, and WHMCS are left unchanged.
	// The 72h window is SoT and is not started under the dry_run ceiling.
	writeJSON(w, http.StatusOK, map[string]any{
		"migration_id":             rec.ID,
		"design_only":              true,
		"applied":                  false,
		"eligible":                 false,
		"status":                   rec.Status,
		"rollback_window_hours":    rollbackWindowHours,
		"rollback_until":           nil,
		"mode_max":                 s.modeMax(),
		"wings_dispatch":           false,
		"executor":                 "noop",
		"whmcs_mutate":             false,
		"managed_inventory_mutate": false,
		"servers_imported":         0,
		"notes":                    "Design stub. The 72h rollback window is not started because confirm and cutover are refused while GLASSPANEL_MIGRATE_MODE_MAX is inventory_only or dry_run. No source writes, no Wings volume rewrite, no WHMCS mutate. managed-inventory rows stay excluded.",
	})
}

func (s *Server) rowsFromSource(ctx context.Context) ([]remapRow, int, error) {
	list, err := s.source.ListServers(ctx)
	if err != nil {
		return nil, 0, err
	}
	var rows []remapRow
	excluded := 0
	seen := map[string]struct{}{}
	for _, srv := range list {
		id := strings.ToLower(strings.TrimSpace(srv.UUID))
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if s.managedInventorySource(srv) {
			excluded++
			continue
		}
		gid := newID()
		var allocs []planAlloc
		for _, a := range srv.Allocations {
			allocs = append(allocs, planAlloc{IP: a.IP, Port: a.Port, Default: a.Default})
		}
		ext := srv.ExternalID
		row := remapRow{
			SourceServerID:   id,
			SourceName:       srv.Name,
			SID:              srv.ID,
			ExternalID:       ext,
			SourceNodeID:     strconv.Itoa(srv.NodeID),
			SourceEggID:      strconv.Itoa(srv.EggID),
			GlassServerID:    &gid,
			Allocations:      allocs,
			ManagedInventory: false,
			Action:           "import",
			Notes:            "dry_run plan from source Application API; Wings noop; no WHMCS mutate; managed-inventory filtered out",
		}
		rows = append(rows, row)
	}
	return rows, excluded, nil
}

func (s *Server) managedInventorySource(srv ptero.Server) bool {
	t := deny.Targets{}
	if u := strings.ToLower(strings.TrimSpace(srv.UUID)); u != "" {
		t.UUIDs = []string{u}
	}
	if srv.ID > 0 {
		t.SIDs = []int{srv.ID}
	}
	if ext := strings.TrimSpace(srv.ExternalID); ext != "" {
		t.ExternalIDs = []string{ext}
		if n, ok := whmcsToken(ext); ok {
			t.WHMCS = []int{n}
		}
	}
	return len(s.deny.Match(t)) > 0
}

func (s *Server) migration(id string) *migrationRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.migs[id]
}

func (s *Server) modeMax() string {
	if s.cfg.MigrateModeMax == "" {
		return "inventory_only"
	}
	return s.cfg.MigrateModeMax
}

func (m *migrationRec) recount() {
	// Filtered is the managed-inventory count removed from a live discovery plan.
	// Fixture rows stay in the remap as skip_managed_inventory and are counted here.
	excluded := m.Filtered
	planned := 0
	for _, row := range m.Rows {
		if row.Action == "skip_managed_inventory" || row.ManagedInventory {
			excluded++
			continue
		}
		if row.Action == "import" {
			planned++
		}
	}
	m.Excluded = excluded
	m.Planned = planned
}

func (m *migrationRec) public() map[string]any {
	return map[string]any{
		"id":                               m.ID,
		"kind":                             "ptero_import",
		"status":                           m.Status,
		"source_base_url":                  m.SourceBaseURL,
		"mode":                             m.Mode,
		"mode_max":                         m.ModeMax,
		"dry_run":                          true,
		"include_managed_inventory":        false,
		"managed_inventory_excluded_count": m.Excluded,
		"servers_planned":                  m.Planned,
		"servers_imported":                 0,
		"servers_failed":                   0,
		"job_id":                           nil,
		"rollback_until":                   nil,
		"rollback_window_hours":            rollbackWindowHours,
		"rollback_notes":                   "TEST inventory_only/dry_run: no cutover, no Wings writes, managed-inventory rows stay excluded. Rollback window default remains 72h and is not started.",
		"executor":                         "noop",
		"wings_dispatch":                   false,
		"whmcs_mutate":                     false,
		"created_at":                       m.Created.Format(time.RFC3339),
		"updated_at":                       m.Updated.Format(time.RFC3339),
		"completed_at":                     nil,
	}
}

func remapPage(rec *migrationRec) map[string]any {
	return map[string]any{
		"migration_id":   rec.ID,
		"data":           rec.Rows,
		"next_cursor":    nil,
		"executor":       "noop",
		"wings_dispatch": false,
	}
}

func (s *Server) inventoryRows() []remapRow {
	var rows []remapRow
	for _, u := range s.deny.UUIDs() {
		hits := s.deny.Match(deny.Targets{UUIDs: []string{u}})
		row := remapRow{
			SourceServerID:   u,
			ManagedInventory: true,
			Action:           "skip_managed_inventory",
			Notes:            "excluded by managed-inventory deny map; TEST include_managed_inventory is forced false",
		}
		if len(hits) > 0 {
			row.SourceName = hits[0].Name
			row.SID = hits[0].SID
			row.ExternalID = hits[0].ExternalID
		}
		rows = append(rows, row)
	}
	for _, f := range fixture.WHMCSDenyFixtures() {
		rows = append(rows, remapRow{
			SourceServerID:   f.SourceServerID,
			SourceName:       f.SourceName,
			WHMCSServiceID:   f.WHMCSServiceID,
			ManagedInventory: true,
			Action:           "skip_managed_inventory",
			Notes:            "excluded by the managed-inventory deny map",
		})
	}
	c := fixture.CommercialFixture()
	gid := fixture.CommercialGlassID
	rows = append(rows, remapRow{
		SourceServerID:   c.SourceServerID,
		SourceName:       c.SourceName,
		SID:              c.SID,
		ExternalID:       c.ExternalID,
		GlassServerID:    &gid,
		ManagedInventory: false,
		Action:           "import",
		Notes:            "inventory_only plan for a non-deny fixture; not dispatched to Wings",
	})
	return rows
}

func planMode(mode *string) (string, bool) {
	raw := ""
	if mode != nil {
		raw = *mode
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "inventory_only":
		return "inventory_only", true
	case "dry_run":
		return "dry_run", true
	default:
		return "", false
	}
}

func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func whmcsToken(s string) (int, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.TrimPrefix(s, "CT")
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func knownMigrationStatus(s string) bool {
	switch s {
	case "queued", "discovering", "planned", "awaiting_confirm", "copying", "cutting_over",
		"succeeded", "partial", "failed", "rolling_back", "rolled_back", "cancelled":
		return true
	default:
		return false
	}
}

var (
	glassEggKeyRe  = regexp.MustCompile(`^glass\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
	glassNodeKeyRe = regexp.MustCompile(`^glass\.node\.[a-z][a-z0-9_-]*$`)
	sourceMapKeyRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)
)

func validGlassEggKey(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(strings.ToLower(s), "nest") {
		return false
	}
	if _, err := strconv.Atoi(s); err == nil {
		return false
	}
	return glassEggKeyRe.MatchString(s)
}

func validGlassNodeKey(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(strings.ToLower(s), "nest") {
		return false
	}
	return glassNodeKeyRe.MatchString(s)
}

func sourceMapKey(s string) bool {
	return sourceMapKeyRe.MatchString(strings.TrimSpace(s))
}

func customerNestKey(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return false
	}
	return walkNestKey(v)
}

func walkNestKey(v any) bool {
	switch n := v.(type) {
	case map[string]any:
		for k, child := range n {
			switch strings.ToLower(k) {
			case "nest", "nest_id", "nestid":
				return true
			}
			if walkNestKey(child) {
				return true
			}
		}
	case []any:
		for _, child := range n {
			if walkNestKey(child) {
				return true
			}
		}
	}
	return false
}
