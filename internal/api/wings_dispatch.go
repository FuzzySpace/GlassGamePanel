package api

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/wings"
)

type dialOutcome int

const (
	// dialSkip means this request must not dial. The caller keeps the
	// non-Wings response and leaves X-Glass-Wings-Dispatch at 0.
	dialSkip dialOutcome = iota
	// dialFailed means an error response was already written.
	dialFailed
	// dialOK means Wings returned 2xx. The dispatch header is already 1.
	dialOK
)

// wingsCall is one daemon operation. File and Content are set for a
// path-policy file write or delete. Content is not logged.
type wingsCall struct {
	Op        string
	ServerID  string
	Action    string
	Directory string
	File      string
	Content   []byte
}

// dialAllowlisted dials the Wings daemon when the executor is real, the
// path UUID itself is on PANEL_WINGS_ALLOWLIST, and the target is not Soft
// Launch. A node id does not authorize a dial. A managed-inventory UUID is never
// passed to the client. An empty allowlist, the noop executor, and a target
// that is not listed return dialSkip.
// A missing daemon origin or a transport failure writes wings_dial_failed
// and does not set the dispatch header. A completed round-trip, including a
// Wings 4xx, sets X-Glass-Wings-Dispatch to 1.
func (s *Server) dialAllowlisted(ctx context.Context, w http.ResponseWriter, rid, op, serverID, action, directory string) (wings.Result, dialOutcome) {
	return s.dialWings(ctx, w, rid, wingsCall{
		Op: op, ServerID: serverID, Action: action, Directory: directory,
	})
}

func (s *Server) dialWings(ctx context.Context, w http.ResponseWriter, rid string, call wingsCall) (wings.Result, dialOutcome) {
	id := strings.ToLower(strings.TrimSpace(call.ServerID))
	if id != "" && s.deny.IsManagedInventoryUUID(id) {
		s.writeManagedInventory(w, rid, call.Op)
		return wings.Result{}, dialFailed
	}
	if s.cfg.WingsExecutor != config.WingsExecutorReal || !s.wingsAllowlisted(id) {
		return wings.Result{}, dialSkip
	}
	target := s.wingsDialTarget(id)
	if s.deny.IsManagedInventoryUUID(target) {
		s.writeManagedInventory(w, rid, call.Op)
		return wings.Result{}, dialFailed
	}
	res, err := s.exec.Dial(ctx, wings.Request{
		Op:        call.Op,
		ServerID:  target,
		Action:    call.Action,
		Directory: call.Directory,
		File:      call.File,
		Content:   call.Content,
		RequestID: rid,
	})
	if err != nil {
		log.Printf("wings_dial_failed request_id=%s op=%s server_id=%s wings_dialed=false", rid, call.Op, id)
		writeError(w, http.StatusBadGateway, "wings_dial_failed", safeDialErr(err), rid, map[string]any{
			"wings_dialed": false,
			"op":           call.Op,
			"request_id":   rid,
		})
		return wings.Result{}, dialFailed
	}
	log.Printf("wings_dial request_id=%s op=%s server_id=%s wings_dialed=true wings_http_status=%d body_summary=%q", rid, call.Op, id, res.Status, res.Summary)
	w.Header().Set("X-Glass-Wings-Dispatch", "1")
	w.Header().Set("X-Glass-Wings-HTTP-Status", strconv.Itoa(res.Status))
	if res.Status < 200 || res.Status >= 300 {
		writeError(w, http.StatusBadGateway, "wings_rejected", "wings daemon rejected the request", rid, map[string]any{
			"wings_dialed":       true,
			"wings_http_status":  res.Status,
			"wings_body_summary": res.Summary,
			"op":                 call.Op,
			"request_id":         rid,
		})
		return res, dialFailed
	}
	return res, dialOK
}

func (s *Server) writeManagedInventory(w http.ResponseWriter, rid, op string) {
	log.Printf("managed_inventory_denied request_id=%s op=%s hits=1", rid, op)
	writeError(w, http.StatusForbidden, "managed_inventory_denied", "managed-inventory target is denied", rid, map[string]any{
		"op":             op,
		"wings_dispatch": false,
	})
}

func safeDialErr(err error) string {
	switch {
	case errors.Is(err, wings.ErrNotConfigured):
		return wings.ErrNotConfigured.Error()
	case errors.Is(err, wings.ErrUnreachable):
		return wings.ErrUnreachable.Error()
	case errors.Is(err, wings.ErrRedirect):
		return wings.ErrRedirect.Error()
	case errors.Is(err, wings.ErrBadTarget):
		return wings.ErrBadTarget.Error()
	default:
		return "wings daemon dial failed"
	}
}

// wingsAllowlisted matches the path UUID only. SecNOA CLEAR is UUID-narrow:
// a node id on PANEL_WINGS_ALLOWLIST does not authorize a dial. An empty
// allowlist matches nothing. managed-inventory UUIDs are refused before this
// returns true is acted on.
func (s *Server) wingsAllowlisted(id string) bool {
	if s.cfg.WingsAllowlist.Empty() {
		return false
	}
	return s.cfg.WingsAllowlist.HasUUID(id)
}

// wingsDialTarget is the Wings server UUID for this Glass id.
// A stored wings_server_id wins. Otherwise the Glass path UUID is used,
// which is the TEST mapping when that UUID is the Wings server id.
func (s *Server) wingsDialTarget(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rec := s.servers[id]; rec != nil && rec.WingsServerID != "" {
		return rec.WingsServerID
	}
	return id
}

func (s *Server) executorName() string {
	if s.cfg.WingsExecutor == config.WingsExecutorReal {
		return config.WingsExecutorReal
	}
	return config.WingsExecutorNoop
}
