package api

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/FuzzySpace/GlassGamePanel/internal/alloc"
	"github.com/FuzzySpace/GlassGamePanel/internal/auth"
	"github.com/FuzzySpace/GlassGamePanel/internal/config"
	"github.com/FuzzySpace/GlassGamePanel/internal/deny"
	"github.com/FuzzySpace/GlassGamePanel/internal/executor"
	"github.com/FuzzySpace/GlassGamePanel/internal/ptero"
	"github.com/FuzzySpace/GlassGamePanel/internal/ratelimit"
	"github.com/FuzzySpace/GlassGamePanel/internal/ticket"
	"github.com/FuzzySpace/GlassGamePanel/internal/wings"
	"github.com/gorilla/websocket"
)

const (
	opPower       = "power"
	opFiles       = "files"
	opConsole     = "console-ticket"
	opBackups     = "backups"
	opDelete      = "delete"
	opRestore     = "restore"
	opServerWrite = "server_write"
	opServerRead  = "server_read"

	scopePower        = "power"
	scopeConsole      = "console"
	scopeFiles        = "files"
	scopeBackups      = "backups"
	scopeServersWrite = "servers:write"
	scopeServersRead  = "servers:read"
	scopeAgentsManage = "agents:manage"
	scopeMigrationsW  = "migrations:write"
	scopeMigrationsR  = "migrations:read"
)

// Server is the TEST-only control plane. The default executor is noop and
// does not dial. PANEL_WINGS_EXECUTOR=real dials Wings only for an allowlisted
// non–managed-inventory power, file list, or path-policy file write when the daemon
// origin and token are set. File writes stay under mods/ or plugins/ and never
// run for a managed-inventory target.
type Server struct {
	cfg      config.Config
	deny     *deny.Set
	exec     *executor.Runner
	authn    *auth.Validator
	tickets  *ticket.Store
	limit    *ratelimit.Limiter
	upgrader websocket.Upgrader

	mu            sync.Mutex
	servers       map[string]*serverRec
	jobs          map[string]map[string]any
	migs          map[string]*migrationRec
	source        sourceAPI
	byEntitlement map[string]createBinding
	allocPool     *alloc.Pool

	idemMu sync.Mutex
	idem   map[string]idemEntry

	mux http.Handler
}

type serverRec struct {
	ID            string
	Name          string
	Status        string
	EggID         string
	NodeID        string
	GlassID       string
	WingsServerID string
	EntitlementID string
	AllocPool     string
	Allocations   []alloc.Record
	Tags          []string
	Created       time.Time
	Updated       time.Time
}

// createBinding remembers the server and job produced for one entitlement
// so a second create does not claim another pair.
type createBinding struct {
	ServerID string
	JobID    string
}

type handleFunc func(w http.ResponseWriter, r *http.Request, p auth.Principal, body []byte, rid string)

type route struct {
	op              string
	scope           string
	mutate          bool
	bindServer      bool
	deny            bool
	maxBody         int64
	staffOnlyReason string
	h               handleFunc
}

// New builds the HTTP API. It refuses invalid TEST config and a drifted deny map.
func New(cfg config.Config) (*Server, error) {
	cfg = cfg.WithCreateDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	var source sourceAPI
	if cfg.PteroSourceAPIURL != "" {
		client, err := ptero.New(cfg.PteroSourceAPIURL, cfg.PteroSourceAPIToken)
		if err != nil {
			return nil, err
		}
		source = client
	}
	d, err := deny.Load()
	if err != nil {
		return nil, err
	}
	for _, nodeID := range cfg.CreateNodeAllowlist {
		sid, sidErr := strconv.Atoi(nodeID)
		if sidErr == nil && d.IsManagedInventorySID(sid) {
			return nil, fmt.Errorf("PANEL_CREATE_NODE_ALLOWLIST contains managed-inventory SID %s", nodeID)
		}
	}
	for nodeID := range cfg.WingsAllowlist.Nodes {
		sid, sidErr := strconv.Atoi(nodeID)
		if sidErr == nil && d.IsManagedInventorySID(sid) {
			return nil, fmt.Errorf("PANEL_WINGS_ALLOWLIST contains managed-inventory SID %s", nodeID)
		}
	}
	pool, err := alloc.New(cfg.AllocPool)
	if err != nil {
		return nil, err
	}
	var wingsClient *wings.Client
	if cfg.WingsBaseURL != "" {
		wingsClient, err = wings.New(cfg.WingsBaseURL, cfg.WingsToken)
		if err != nil {
			return nil, err
		}
	}
	verifier, err := auth.NewValidator(cfg.JWTSecret, cfg.JWTIss, cfg.JWTAud, cfg.JWTJWKSURL)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:           cfg,
		deny:          d,
		exec:          executor.NewRunner(cfg.WingsExecutor, wingsClient),
		authn:         verifier,
		tickets:       ticket.New(),
		limit:         ratelimit.New(cfg.MutateRPM, cfg.ReadRPM, time.Minute, time.Now),
		servers:       map[string]*serverRec{},
		jobs:          map[string]map[string]any{},
		migs:          map[string]*migrationRec{},
		source:        source,
		byEntitlement: map[string]createBinding{},
		allocPool:     pool,
		idem:          map[string]idemEntry{},
	}
	s.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			// Agents omit Origin. Browser OpenAPI UI is not served.
			return r.Header.Get("Origin") == ""
		},
	}
	s.seedInventory()
	s.mux = s.routes()
	return s, nil
}

// WingsAttempts is the number of completed Wings HTTP round-trips since
// process start. The default noop executor stays at 0. A dial that does not
// finish, an empty allowlist, and managed-inventory deny do not increment it.
func (s *Server) WingsAttempts() int64 { return s.exec.Attempts() }

// DenySHA256 is the loaded managed-inventory deny file digest.
func (s *Server) DenySHA256() string { return s.deny.SHA256() }

// Handler is the public HTTP handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Glass-Runtime", "panel-api-test")
		w.Header().Set("X-Glass-Executor", s.executorName())
		w.Header().Set("X-Glass-Wings-Dispatch", "0")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		s.mux.ServeHTTP(w, r)
	})
}

// SetClockForTest freezes the rate-limit window.
func (s *Server) SetClockForTest(now func() time.Time) { s.limit.SetNow(now) }

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /v1/healthz", s.handleHealth)

	s.handle(mux, "GET /v1/servers", route{op: opServerRead, scope: scopeServersRead, bindServer: true, h: s.handleListServers})
	s.handle(mux, "POST /v1/servers", route{op: opServerWrite, scope: scopeServersWrite, mutate: true, deny: true, h: s.handleCreateServer})
	s.handle(mux, "GET /v1/servers/{serverId}", route{op: opServerRead, scope: scopeServersRead, bindServer: true, deny: true, h: s.handleGetServer})
	s.handle(mux, "PATCH /v1/servers/{serverId}", route{op: opServerWrite, scope: scopeServersWrite, mutate: true, bindServer: true, deny: true, h: s.handlePatchServer})
	s.handle(mux, "DELETE /v1/servers/{serverId}", route{op: opDelete, scope: scopeServersWrite, mutate: true, bindServer: true, deny: true, h: s.handleDeleteServer})
	s.handle(mux, "POST /v1/servers/{serverId}/power", route{op: opPower, scope: scopePower, mutate: true, bindServer: true, deny: true, h: s.handlePower})
	s.handle(mux, "POST /v1/servers/{serverId}/console-ticket", route{op: opConsole, scope: scopeConsole, mutate: true, bindServer: true, deny: true, h: s.handleConsoleTicket})
	mux.HandleFunc("GET /v1/servers/{serverId}/console", s.handleConsole)
	s.handle(mux, "GET /v1/servers/{serverId}/files", route{op: opFiles, scope: scopeFiles, bindServer: true, deny: true, h: s.handleListFiles})
	s.handle(mux, "PUT /v1/servers/{serverId}/files/content", route{op: opFiles, scope: scopeFiles, mutate: true, bindServer: true, deny: true, maxBody: wings.MaxWriteBytes, h: s.handlePutFileContent})
	s.handle(mux, "DELETE /v1/servers/{serverId}/files/content", route{op: opFiles, scope: scopeFiles, mutate: true, bindServer: true, deny: true, h: s.handleDeleteFileContent})
	s.handle(mux, "GET /v1/servers/{serverId}/backups", route{op: opBackups, scope: scopeBackups, bindServer: true, deny: true, h: s.handleListBackups})
	s.handle(mux, "POST /v1/servers/{serverId}/backups", route{op: opBackups, scope: scopeBackups, mutate: true, bindServer: true, deny: true, h: s.handleCreateBackup})
	s.handle(mux, "POST /v1/servers/{serverId}/backups/{backupId}/restore", route{op: opRestore, scope: scopeBackups, mutate: true, bindServer: true, deny: true, h: s.handleRestoreBackup})
	s.handle(mux, "POST /v1/agent-tokens", route{op: "agent_token", scope: scopeAgentsManage, mutate: true, staffOnlyReason: "agent tokens cannot mint child tokens", h: s.handleCreateAgentToken})
	s.handle(mux, "POST /v1/migrations/ptero", route{op: "migration", scope: scopeMigrationsW, mutate: true, staffOnlyReason: "agent tokens cannot call migrations", h: s.handleStartMigration})
	s.handle(mux, "GET /v1/migrations", route{op: "migration", scope: scopeMigrationsR, staffOnlyReason: "agent tokens cannot call migrations", h: s.handleListMigrations})
	s.handle(mux, "GET /v1/migrations/{migrationId}", route{op: "migration", scope: scopeMigrationsR, staffOnlyReason: "agent tokens cannot call migrations", h: s.handleGetMigration})
	s.handle(mux, "GET /v1/migrations/{migrationId}/remap", route{op: "migration", scope: scopeMigrationsR, staffOnlyReason: "agent tokens cannot call migrations", h: s.handleGetRemap})
	s.handle(mux, "PATCH /v1/migrations/{migrationId}/remap", route{op: "migration", scope: scopeMigrationsW, mutate: true, deny: true, staffOnlyReason: "agent tokens cannot call migrations", h: s.handlePatchRemap})
	s.handle(mux, "POST /v1/migrations/{migrationId}/remap", route{op: "migration", scope: scopeMigrationsW, mutate: true, deny: true, staffOnlyReason: "agent tokens cannot call migrations", h: s.handlePostRemap})
	s.handle(mux, "POST /v1/migrations/{migrationId}/confirm", route{op: "migration", scope: scopeMigrationsW, mutate: true, deny: true, staffOnlyReason: "agent tokens cannot call migrations", h: s.handleConfirmMigration})
	s.handle(mux, "POST /v1/migrations/{migrationId}/rollback", route{op: "migration", scope: scopeMigrationsW, mutate: true, deny: true, staffOnlyReason: "agent tokens cannot call migrations", h: s.handleRollbackDesign})
	s.handle(mux, "GET /v1/jobs/{jobId}", route{op: "job", scope: scopeServersRead, h: s.handleGetJob})

	mux.HandleFunc("/", s.handleFallback)
	return mux
}

func (s *Server) handle(mux *http.ServeMux, pattern string, rt route) {
	mux.HandleFunc(pattern, s.chain(rt))
}

func (s *Server) chain(rt route) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rid := requestID(r)
		w.Header().Set("X-Request-Id", rid)
		p, ok := s.authenticate(w, r, rid)
		if !ok {
			return
		}
		if !s.allowRate(w, p, rt.mutate, rid) {
			return
		}
		body, ok := readBody(w, r, rid, rt.maxBody)
		if !ok {
			return
		}
		if rt.deny && s.blockDeny(w, r, rt.op, body, rid) {
			return
		}
		if rt.staffOnlyReason != "" && p.IsAgent() {
			writeError(w, http.StatusForbidden, "forbidden", rt.staffOnlyReason, rid, map[string]any{"reason": "agent_not_permitted"})
			return
		}
		if rt.scope != "" && !p.HasScope(rt.scope) {
			writeError(w, http.StatusForbidden, "forbidden", "missing required scope", rid, map[string]any{"required_scope": rt.scope})
			return
		}
		if rt.bindServer {
			if details := s.authorizeAgent(p, r); details != nil {
				writeError(w, http.StatusForbidden, "forbidden", "agent token cannot target this server", rid, details)
				return
			}
		}
		if rt.mutate {
			s.withIdempotency(w, r, p.JTI, body, rid, func(w http.ResponseWriter) {
				rt.h(w, r, p, body, rid)
			})
			return
		}
		rt.h(w, r, p, body, rid)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Request-Id", requestID(r))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("{\"ok\":true}\n"))
}

func (s *Server) handleFallback(w http.ResponseWriter, r *http.Request) {
	rid := requestID(r)
	w.Header().Set("X-Request-Id", rid)
	writeError(w, http.StatusNotFound, "not_found", "no such route", rid, nil)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, rid string) (auth.Principal, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) || strings.TrimSpace(h[len(prefix):]) == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "bearer token required", rid, nil)
		return auth.Principal{}, false
	}
	raw := strings.TrimSpace(h[len(prefix):])
	p, err := s.authn.Parse(raw, time.Now())
	if err != nil {
		msg := "unauthorized"
		var details any
		if errors.Is(err, auth.ErrProdRejected) {
			msg = "prod Portal tokens are rejected on TEST"
			details = map[string]any{"reason": "prod_aud_or_iss_rejected"}
		}
		writeError(w, http.StatusUnauthorized, "unauthorized", msg, rid, details)
		return auth.Principal{}, false
	}
	return p, true
}

func (s *Server) allowRate(w http.ResponseWriter, p auth.Principal, mutate bool, rid string) bool {
	class := "read"
	if mutate {
		class = "mutate"
	}
	ok, limit := s.limit.Allow(p.JTI, class)
	if ok {
		return true
	}
	w.Header().Set("Retry-After", "60")
	writeError(w, http.StatusTooManyRequests, "rate_limited", "rate limit exceeded", rid, map[string]any{
		"class":     class,
		"limit_rpm": limit,
		"note":      "TEST cap 60 mutate / 300 read rpm per token; WG gateway enforces the same limits",
	})
	return false
}

func readBody(w http.ResponseWriter, r *http.Request, rid string, limit int64) ([]byte, bool) {
	if r.Body == nil {
		return nil, true
	}
	if limit <= 0 {
		limit = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "request body too large or unreadable", rid, nil)
		return nil, false
	}
	return b, true
}

// blockDeny is the managed-inventory middleware. It returns before any handler and
// before the noop executor. Dispatch is not called.
func (s *Server) blockDeny(w http.ResponseWriter, r *http.Request, op string, body []byte, rid string) bool {
	hits := s.deny.Match(deny.Extract(r.PathValue("serverId"), r.URL.Query(), body))
	if op == opServerWrite {
		hits = append(hits, s.deny.ServerWriteFootprint(r.URL.Query(), body)...)
	}
	if len(hits) == 0 {
		return false
	}
	log.Printf("managed_inventory_denied request_id=%s op=%s hits=%d", rid, op, len(hits))
	writeError(w, http.StatusForbidden, "managed_inventory_denied", "managed-inventory target is denied", rid, map[string]any{
		"op":             op,
		"matched":        hits,
		"wings_dispatch": false,
	})
	return true
}

func (s *Server) authorizeAgent(p auth.Principal, r *http.Request) map[string]any {
	if !p.IsAgent() {
		return nil
	}
	if len(p.ServerIDs) == 0 {
		return map[string]any{"reason": "empty_server_ids"}
	}
	for _, id := range p.ServerIDs {
		if id == "*" || id == "all" || id == "" {
			return map[string]any{"reason": "overbroad_server_ids"}
		}
	}
	sid := strings.ToLower(strings.TrimSpace(r.PathValue("serverId")))
	if sid == "" {
		return nil
	}
	for _, id := range p.ServerIDs {
		if id == sid {
			return nil
		}
	}
	return map[string]any{"reason": "server_not_in_token"}
}
