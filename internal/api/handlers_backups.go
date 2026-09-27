package api

import (
	"net/http"
	"strings"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
)

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	_ = s.ensureServer(id)
	writeJSON(w, http.StatusOK, map[string]any{"data": []any{}, "next_cursor": nil})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	_ = s.ensureServer(id)
	writeJSON(w, http.StatusAccepted, s.queueJob("backup.create", id))
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	backupID := strings.ToLower(r.PathValue("backupId"))
	if !looksUUID(id) || !looksUUID(backupID) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId and backupId must be uuids", rid, nil)
		return
	}
	_ = s.ensureServer(id)
	job := s.queueJob("backup.restore", id)
	writeJSON(w, http.StatusAccepted, job)
}
