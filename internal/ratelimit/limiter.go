package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a fixed-window counter per token id.
// TEST caps are 60 mutate rpm and 300 read rpm (also enforced at the WG gateway).
type Limiter struct {
	mutate int
	read   int
	window time.Duration
	now    func() time.Time
	mu     sync.Mutex
	bucket map[string]*counts
}

type counts struct {
	start  time.Time
	mutate int
	read   int
}

// New builds a limiter. mutate and read are requests per window.
func New(mutate, read int, window time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	if window <= 0 {
		window = time.Minute
	}
	return &Limiter{
		mutate: mutate,
		read:   read,
		window: window,
		now:    now,
		bucket: map[string]*counts{},
	}
}

// SetNow overrides the clock (tests freeze the window).
func (l *Limiter) SetNow(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
}

// Allow consumes one request. class is "mutate" or "read".
// The second return is the configured rpm for that class.
func (l *Limiter) Allow(tokenID, class string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.bucket[tokenID]
	if b == nil || now.Sub(b.start) >= l.window {
		b = &counts{start: now}
		l.bucket[tokenID] = b
	}
	limit := l.read
	if class == "mutate" {
		limit = l.mutate
		if b.mutate >= limit {
			return false, limit
		}
		b.mutate++
		return true, limit
	}
	if b.read >= limit {
		return false, limit
	}
	b.read++
	return true, limit
}
