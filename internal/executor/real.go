package executor

import (
	"context"
	"sync/atomic"

	"github.com/FuzzySpace/GlassGamePanel/internal/wings"
)

// Real dials the Wings daemon for an allowlisted call. A nil client fails
// closed: Dial returns ErrNotConfigured and does not increment the counter.
// The counter increments only after Wings returns an HTTP status, including 4xx.
// managed-inventory checks stay outside this type. The caller must not pass a
// managed-inventory UUID.
type Real struct {
	attempts atomic.Int64
	client   *wings.Client
}

// Dial performs one daemon HTTP call. A nil error means the round-trip
// completed. The returned error is a static wings error and does not contain
// the daemon token.
func (r *Real) Dial(ctx context.Context, req wings.Request) (wings.Result, error) {
	if r == nil || r.client == nil {
		return wings.Result{}, wings.ErrNotConfigured
	}
	res, err := r.client.Do(ctx, req)
	if err != nil {
		return wings.Result{}, err
	}
	r.attempts.Add(1)
	return res, nil
}

// Attempts is the number of completed Wings HTTP round-trips since process start.
func (r *Real) Attempts() int64 {
	if r == nil {
		return 0
	}
	return r.attempts.Load()
}
