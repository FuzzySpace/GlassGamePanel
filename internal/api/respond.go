package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"unicode"
)

type errorEnvelope struct {
	Error errorObject `json:"error"`
}

type errorObject struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
	Details   any    `json:"details,omitempty"`
}

func writeError(w http.ResponseWriter, status int, code, message, requestID string, details any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: errorObject{
		Code: code, Message: message, RequestID: requestID, Details: details,
	}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func requestID(r *http.Request) string {
	id := r.Header.Get("X-Request-Id")
	if len(id) >= 8 && len(id) <= 64 && safeToken(id) {
		return id
	}
	return newID()
}

func safeToken(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
