package executor

import (
	"context"
	"strings"

	"github.com/FuzzySpace/GlassGamePanel/internal/wings"
)

// Runner selects the noop or real executor. Noop mode never dials and never
// increments. Real mode dials only when Dial is called.
type Runner struct {
	mode string
	noop *Noop
	real *Real
}

// NewRunner returns a noop runner unless mode is "real".
// client may be nil. A nil client on the real runner fails closed on Dial.
func NewRunner(mode string, client *wings.Client) *Runner {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "real" {
		mode = "noop"
	}
	return &Runner{mode: mode, noop: &Noop{}, real: &Real{client: client}}
}

// Mode is "noop" or "real".
func (r *Runner) Mode() string {
	if r == nil || r.mode != "real" {
		return "noop"
	}
	return "real"
}

// Attempts is the completed-dial counter for the active mode.
// Noop stays at zero unless Noop.Dispatch is called, which the API does not do.
func (r *Runner) Attempts() int64 {
	if r == nil {
		return 0
	}
	if r.mode == "real" {
		return r.real.Attempts()
	}
	return r.noop.Attempts()
}

// Dial calls the Wings daemon in real mode. Noop mode does not use client
// and returns without a round-trip.
func (r *Runner) Dial(ctx context.Context, req wings.Request) (wings.Result, error) {
	if r == nil || r.mode != "real" {
		return wings.Result{}, wings.ErrNotConfigured
	}
	return r.real.Dial(ctx, req)
}
