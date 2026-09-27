package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/golang-jwt/jwt/v5"
)

// mintableAgentScopes is the AgentTokenCreate enum. migrations:* and
// agents:manage are intentionally absent (SecNOA B3).
var mintableAgentScopes = []string{
	"servers:read",
	"servers:write",
	"power",
	"console",
	"files",
	"backups",
	"metrics",
	"eggs:read",
	"entitlements:read",
	"network",
}

func mintableSet() map[string]struct{} {
	m := make(map[string]struct{}, len(mintableAgentScopes))
	for _, s := range mintableAgentScopes {
		m[s] = struct{}{}
	}
	return m
}

func (s *Server) handleCreateAgentToken(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	var req struct {
		Name       string   `json:"name"`
		Scopes     []string `json:"scopes"`
		TTLSeconds *int     `json:"ttl_seconds"`
		ServerIDs  []string `json:"server_ids"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "invalid JSON body", rid, nil)
		return
	}
	hits := s.deny.Match(deny.Extract("", nil, body))
	if len(hits) > 0 {
		writeError(w, http.StatusForbidden, "managed_inventory_denied", "managed-inventory UUID rejected in agent server_ids", rid, map[string]any{
			"op":             "agent_token",
			"matched":        hits,
			"wings_dispatch": false,
		})
		return
	}
	if strings.TrimSpace(req.Name) == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "name is required", rid, map[string]any{"field": "name"})
		return
	}
	if len(req.Scopes) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "scopes must contain at least one mintable scope", rid, map[string]any{"field": "scopes"})
		return
	}
	allowed := mintableSet()
	var rejected []string
	for _, sc := range req.Scopes {
		if _, ok := allowed[sc]; !ok {
			rejected = append(rejected, sc)
		}
	}
	if len(rejected) > 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "scope is not mintable on TEST agent tokens", rid, map[string]any{
			"field":           "scopes",
			"rejected_scopes": rejected,
			"mintable_scopes": mintableAgentScopes,
			"wings_dispatch":  false,
		})
		return
	}
	if req.ServerIDs == nil || len(req.ServerIDs) == 0 {
		writeError(w, http.StatusBadRequest, "validation_failed", "server_ids is required and must contain at least one server", rid, map[string]any{"field": "server_ids"})
		return
	}
	norm := make([]string, 0, len(req.ServerIDs))
	for _, id := range req.ServerIDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if id == "" || id == "*" || id == "all" {
			writeError(w, http.StatusBadRequest, "validation_failed", "over-broad server_ids are rejected", rid, map[string]any{"field": "server_ids", "reason": "overbroad_server_ids"})
			return
		}
		if !looksUUID(id) {
			writeError(w, http.StatusBadRequest, "validation_failed", "server_ids entries must be uuids", rid, map[string]any{"field": "server_ids"})
			return
		}
		if s.deny.IsManagedInventoryUUID(id) {
			writeError(w, http.StatusForbidden, "managed_inventory_denied", "managed-inventory UUID rejected in agent server_ids", rid, map[string]any{
				"op":             "agent_token",
				"wings_dispatch": false,
			})
			return
		}
		norm = append(norm, id)
	}
	if req.TTLSeconds == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "ttl_seconds is required", rid, map[string]any{"field": "ttl_seconds"})
		return
	}
	ttl := *req.TTLSeconds
	if ttl < 60 || ttl > 3600 {
		writeError(w, http.StatusBadRequest, "validation_failed", "ttl_seconds must be between 60 and 3600 on TEST", rid, map[string]any{"field": "ttl_seconds", "max": 3600})
		return
	}

	now := time.Now().UTC().Truncate(time.Second)
	id := newID()
	claims := auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.cfg.JWTIss,
			Subject:   "agent:" + id,
			Audience:  jwt.ClaimStrings{s.cfg.JWTAud},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Duration(ttl) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        id,
		},
		Scope:     strings.Join(req.Scopes, " "),
		TokenUse:  auth.TokenUseAgent,
		ServerIDs: norm,
		MintedBy:  p.Subject,
	}
	// Panel-minted agent JWTs are HS256 with PANEL_JWT_HMAC_SECRET.
	// That secret is not a staff accept path. Portal OIDC RS256 tokens are
	// minted by GlassPortal, not here, and are accepted by the JWKS verifier.
	signed, err := auth.Sign(s.cfg.JWTSecret, claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not mint token", rid, nil)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"name":       strings.TrimSpace(req.Name),
		"scopes":     req.Scopes,
		"server_ids": norm,
		"expires_at": claims.ExpiresAt.Time.UTC().Format(time.RFC3339),
		"created_at": now.Format(time.RFC3339),
		"revoked_at": nil,
		"token":      signed,
	})
}
