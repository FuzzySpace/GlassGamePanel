package ratelimit

import (
	"testing"
	"time"
)

func TestFixedWindow(t *testing.T) {
	cur := time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC)
	l := New(2, 3, time.Minute, func() time.Time { return cur })
	for i := 0; i < 2; i++ {
		ok, limit := l.Allow("tok", "mutate")
		if !ok || limit != 2 {
			t.Fatalf("mutate %d ok=%v limit=%d", i, ok, limit)
		}
	}
	if ok, _ := l.Allow("tok", "mutate"); ok {
		t.Fatal("third mutate allowed")
	}
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("tok", "read"); !ok {
			t.Fatalf("read %d", i)
		}
	}
	if ok, limit := l.Allow("tok", "read"); ok || limit != 3 {
		t.Fatalf("fourth read ok=%v limit=%d", ok, limit)
	}
	// Mutate and read buckets are independent; a different token is fresh.
	if ok, _ := l.Allow("other", "mutate"); !ok {
		t.Fatal("other token limited")
	}
	cur = cur.Add(time.Minute)
	if ok, _ := l.Allow("tok", "mutate"); !ok {
		t.Fatal("window did not reset")
	}
}
