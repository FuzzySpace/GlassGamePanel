package api

import (
	"bytes"
	"crypto/sha256"
	"net/http"
)

type idemEntry struct {
	sum         [32]byte
	status      int
	contentType string
	body        []byte
}

type capture struct {
	http.ResponseWriter
	status int
	wrote  bool
	buf    bytes.Buffer
}

func (c *capture) WriteHeader(code int) {
	if c.wrote {
		return
	}
	c.status = code
	c.wrote = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *capture) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	_, _ = c.buf.Write(b)
	return c.ResponseWriter.Write(b)
}

// withIdempotency replays a stored response or runs h and stores it.
// The caller must already have authenticated the request.
func (s *Server) withIdempotency(w http.ResponseWriter, r *http.Request, jti string, body []byte, rid string, h func(http.ResponseWriter)) {
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 8 || len(key) > 128 || !safeToken(key) {
		writeError(w, http.StatusBadRequest, "validation_failed", "Idempotency-Key is required (8..128 token characters) on mutating requests", rid, map[string]any{"field": "Idempotency-Key"})
		return
	}
	sum := sha256.Sum256(body)
	ikey := jti + "\n" + r.Method + "\n" + r.URL.RequestURI() + "\n" + key

	s.idemMu.Lock()
	defer s.idemMu.Unlock()
	if e, ok := s.idem[ikey]; ok {
		if e.sum != sum {
			writeError(w, http.StatusConflict, "conflict", "Idempotency-Key reused with a different body", rid, nil)
			return
		}
		if e.contentType != "" {
			w.Header().Set("Content-Type", e.contentType)
		}
		w.Header().Set("Idempotency-Replay", "true")
		w.WriteHeader(e.status)
		_, _ = w.Write(e.body)
		return
	}
	cw := &capture{ResponseWriter: w, status: http.StatusOK}
	h(cw)
	if !cw.wrote {
		cw.WriteHeader(http.StatusOK)
	}
	if len(s.idem) > 4096 {
		s.idem = map[string]idemEntry{}
	}
	s.idem[ikey] = idemEntry{
		sum:         sum,
		status:      cw.status,
		contentType: cw.Header().Get("Content-Type"),
		body:        append([]byte(nil), cw.buf.Bytes()...),
	}
}
