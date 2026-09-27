package api

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/ticket"
	"github.com/gorilla/websocket"
)

func (s *Server) handleConsoleTicket(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string) {
	id := strings.ToLower(r.PathValue("serverId"))
	if !looksUUID(id) {
		writeError(w, http.StatusBadRequest, "validation_failed", "serverId must be a uuid", rid, nil)
		return
	}
	tok, exp, err := s.tickets.Mint(id, p.Subject, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not mint ticket", rid, nil)
		return
	}
	// Wings console is a daemon websocket (GET /api/servers/{uuid}/ws). That
	// dial is out of scope. This ticket stays local and does not set
	// X-Glass-Wings-Dispatch.
	writeJSON(w, http.StatusCreated, map[string]any{
		"ticket":          tok,
		"expires_at":      exp.Format(time.RFC3339),
		"websocket_url":   s.consoleURL(id, tok),
		"server_id":       id,
		"subject":         p.Subject,
		"max_ttl_seconds": int(ticket.MaxTTL / time.Second),
		"single_use":      true,
	})
}

func (s *Server) consoleURL(serverID, tok string) string {
	u, err := url.Parse(s.cfg.PublicBaseURL)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}
	u.Path = "/v1/servers/" + serverID + "/console"
	q := url.Values{}
	q.Set("ticket", tok)
	u.RawQuery = q.Encode()
	u.Fragment = ""
	return u.String()
}

// handleConsole is the WebSocket stub. Bearer on the handshake is rejected.
// managed-inventory deny runs before upgrade. The ticket is single-use after a
// successful upgrade and is bound to this serverId.
func (s *Server) handleConsole(w http.ResponseWriter, r *http.Request) {
	rid := requestID(r)
	w.Header().Set("X-Request-Id", rid)
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "console websocket does not accept Authorization; use the ticket query parameter", rid, map[string]any{"reason": "bearer_rejected"})
		return
	}
	ipKey := "ws:" + r.RemoteAddr
	if ok, limit := s.limit.Allow(ipKey, "read"); !ok {
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded", rid, map[string]any{"class": "read", "limit_rpm": limit})
		return
	}
	if s.blockDeny(w, r, opConsole, nil, rid) {
		return
	}
	tok := r.URL.Query().Get("ticket")
	if tok == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "console ticket required", rid, map[string]any{"reason": "ticket_missing"})
		return
	}
	serverID := strings.ToLower(r.PathValue("serverId"))
	if _, err := s.tickets.Begin(tok, serverID, time.Now()); err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "console ticket is invalid, expired, already used, or bound to another server", rid, map[string]any{"reason": "ticket_rejected"})
		return
	}
	if !headerUpgrade(r) {
		s.tickets.Abort(tok)
		writeError(w, http.StatusBadRequest, "validation_failed", "console endpoint requires a WebSocket upgrade", rid, nil)
		return
	}
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.tickets.Abort(tok)
		return
	}
	s.tickets.Commit(tok)
	frame := fmt.Sprintf(`{"type":"console_stub","executor":%q,"wings_dispatch":false}`, s.executorName())
	_ = conn.WriteMessage(websocket.TextMessage, []byte(frame))
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "stub"), time.Now().Add(time.Second))
	_ = conn.Close()
}

func headerUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// plantTicketForTest mints a ticket without the HTTP deny gate so upgrade
// denial can be proven even when mint would have returned managed_inventory_denied.
func (s *Server) plantTicketForTest(serverID, subject string) (string, time.Time, error) {
	return s.tickets.Mint(serverID, subject, time.Now())
}
