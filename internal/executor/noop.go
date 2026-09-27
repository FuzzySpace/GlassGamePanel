package executor

import (
	"fmt"
	"sync/atomic"
)

// ErrDisabled is returned if a caller attempts a Wings dispatch on the noop
// executor. The API does not call Noop.Dispatch. Real mode uses Runner.
var ErrDisabled = fmt.Errorf("wings dispatch disabled: TEST runtime noop executor")

// Noop is the default executor. It has no network client and does not dial Wings.
type Noop struct {
	attempts atomic.Int64
}

// Dispatch records an illegal Wings attempt and returns ErrDisabled.
// It does not open a connection. The allowlisted real path does not call this.
func (n *Noop) Dispatch(op, target string) error {
	n.attempts.Add(1)
	return fmt.Errorf("%w (op=%s target=%s)", ErrDisabled, op, target)
}

// Attempts is the number of Dispatch calls since process start.
func (n *Noop) Attempts() int64 {
	return n.attempts.Load()
}
