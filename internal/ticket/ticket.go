package ticket

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
)

// MaxTTL is the SecNOA B4 hard cap.
const MaxTTL = 120 * time.Second

// ErrInvalid is an expired, used, mismatched, or unknown ticket.
var ErrInvalid = errors.New("console ticket invalid")

type entry struct {
	serverID string
	subject  string
	expires  time.Time
	used     bool
	inflight bool
}

// Store holds single-use console tickets in memory.
type Store struct {
	mu sync.Mutex
	m  map[string]*entry
}

// New returns an empty store.
func New() *Store {
	return &Store{m: map[string]*entry{}}
}

// Mint issues a ticket bound to serverID and subject. TTL is exactly MaxTTL.
func (s *Store) Mint(serverID, subject string, now time.Time) (id string, exp time.Time, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", time.Time{}, err
	}
	id = hex.EncodeToString(buf)
	now = now.UTC().Truncate(time.Second)
	exp = now.Add(MaxTTL)
	s.mu.Lock()
	s.m[id] = &entry{serverID: strings.ToLower(serverID), subject: subject, expires: exp}
	s.mu.Unlock()
	return id, exp, nil
}

// Begin reserves a ticket for an upgrade. It does not mark the ticket used.
// A second Begin fails until Abort or Commit (single-use / in-flight).
func (s *Store) Begin(id, serverID string, now time.Time) (subject string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok {
		return "", ErrInvalid
	}
	if !strings.EqualFold(e.serverID, serverID) {
		return "", ErrInvalid
	}
	if e.used || e.inflight || !now.Before(e.expires) {
		return "", ErrInvalid
	}
	e.inflight = true
	return e.subject, nil
}

// Commit invalidates the ticket after a successful WebSocket upgrade.
func (s *Store) Commit(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok {
		e.used = true
		e.inflight = false
	}
}

// Abort releases an in-flight reservation when the upgrade did not succeed.
func (s *Store) Abort(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.m[id]; ok && !e.used {
		e.inflight = false
	}
}

// Subject returns the minting subject when the ticket exists.
func (s *Store) Subject(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok {
		return "", false
	}
	return e.subject, true
}
