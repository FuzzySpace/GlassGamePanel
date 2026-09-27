package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/wings"
)

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "path query parameter is required", rid, map[string]any{"field": "path"})
		return
	}
	if strings.Contains(path, "..") {
		writeError(w, http.StatusBadRequest, "validation_failed", "path must stay inside the server jail", rid, map[string]any{"field": "path"})
		return
	}
	_ = s.ensureServer(id)
	res, outcome := s.dialAllowlisted(r.Context(), w, rid, opFiles, id, "", path)
	switch outcome {
	case dialSkip:
		writeJSON(w, http.StatusOK, map[string]any{
			"path":    path,
			"entries": []any{},
		})
	case dialOK:
		writeJSON(w, http.StatusOK, map[string]any{
			"path":               path,
			"entries":            fileEntries(res.Body),
			"wings_dialed":       true,
			"wings_http_status":  res.Status,
			"wings_body_summary": res.Summary,
			"request_id":         rid,
		})
	default:
	}
}

func fileEntries(body []byte) []any {
	if len(body) == 0 {
		return []any{}
	}
	var raw []any
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return []any{}
	}
	return raw
}

func (s *Server) handlePutFileContent(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	s.handleFileContent(w, r, body, rid, true)
}

func (s *Server) handleDeleteFileContent(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	s.handleFileContent(w, r, body, rid, false)
}

// handleFileContent writes or deletes one archive under mods/ or plugins/.
// managed-inventory is already refused by middleware. noop, an empty allowlist,
// and a UUID that is not on PANEL_WINGS_ALLOWLIST refuse without a dial.
// A path outside the volume policy refuses before Dial.
func (s *Server) handleFileContent(w http.ResponseWriter, r *http.Request, body []byte, rid string, write bool) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	if s.deny.IsManagedInventoryUUID(id) {
		s.writeManagedInventory(w, rid, "files_write")
		return
	}
	if !s.fileWriteEligible(id) {
		s.refuseFileWrite(w, rid, id)
		return
	}
	file, err := wings.CleanVolumeFile(r.URL.Query().Get("path"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "path is outside the mod volume policy", rid, map[string]any{
			"field":          "path",
			"reason":         "path_not_allowlisted",
			"wings_dispatch": false,
		})
		return
	}
	op := "files_delete"
	var content []byte
	if write {
		op = "files_write"
		if !wings.ModArchive(body) {
			writeError(w, http.StatusBadRequest, "validation_failed", "file content must be a jar or zip archive", rid, map[string]any{
				"field":          "body",
				"reason":         "content_not_archive",
				"wings_dispatch": false,
			})
			return
		}
		content = body
	}
	res, outcome := s.dialWings(r.Context(), w, rid, wingsCall{
		Op: op, ServerID: id, File: file, Content: content,
	})
	switch outcome {
	case dialSkip:
		s.refuseFileWrite(w, rid, id)
	case dialOK:
		evidence := map[string]any{
			"path":               file,
			"wings_dialed":       true,
			"wings_http_status":  res.Status,
			"wings_body_summary": res.Summary,
			"request_id":         rid,
		}
		if write {
			evidence["written"] = true
		} else {
			evidence["deleted"] = true
		}
		writeJSON(w, http.StatusOK, evidence)
	default:
	}
}

// fileWriteEligible is true only for executor=real and a non–managed-inventory
// UUID that is itself on PANEL_WINGS_ALLOWLIST. An empty allowlist and a
// node id are not eligible. Dial configuration is checked inside dialWings.
func (s *Server) fileWriteEligible(id string) bool {
	if s.deny.IsManagedInventoryUUID(id) {
		return false
	}
	if s.cfg.WingsExecutor != config.WingsExecutorReal {
		return false
	}
	if s.cfg.WingsAllowlist.Empty() || !s.cfg.WingsAllowlist.HasUUID(id) {
		return false
	}
	return true
}

func (s *Server) refuseFileWrite(w http.ResponseWriter, rid, id string) {
	reason := "test_files_write_disabled"
	if s.cfg.WingsExecutor == config.WingsExecutorReal {
		switch {
		case s.deny.IsManagedInventoryUUID(id):
			s.writeManagedInventory(w, rid, "files_write")
			return
		case s.cfg.WingsAllowlist.Empty():
			reason = "wings_allowlist_empty"
		case !s.cfg.WingsAllowlist.HasUUID(id):
			reason = "wings_uuid_not_allowlisted"
		}
	}
	writeError(w, http.StatusForbidden, "forbidden", "TEST runtime does not write server files", rid, map[string]any{
		"reason":         reason,
		"wings_dispatch": false,
	})
}
