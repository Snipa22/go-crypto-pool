// Copyright and license: see repository LICENSE (MIT).
package leaflib

import "log"

// DebugLogger wraps a *log.Logger with an enabled flag, letting call
// sites unconditionally call Debugf without ever paying formatting
// cost when debug mode is off (Debugf checks the flag BEFORE doing
// any formatting work). This is the shared, single implementation
// used by all 4 cmd binaries (backend, leaf-solo, leaf-direct,
// leaf-proxy) for their -debug/*_DEBUG flag/env var -- see each
// binary's own main.go for how it is constructed and threaded down.
//
// internal/backend does not import internal/leaflib anywhere else
// today, and internal/leaflib has no dependency on internal/backend
// at all, so backend importing this one type creates no import
// cycle -- confirmed by `go build ./...` passing with backend's own
// Config structs (unlocker.Config/disburse.Config/
// networkpoller.Config) carrying a *DebugLogger field that mirrors
// their existing Logf-func-based logging seam.
//
// DebugLogger is deliberately NOT a global/package-level singleton:
// every caller constructs its own instance via NewDebugLogger and
// threads the resulting *DebugLogger through constructor injection
// (a struct field or setter), exactly like every other per-process
// *log.Logger already flowing through this codebase (see e.g.
// solo.NewServer's logger parameter). This means multiple leaf
// processes/tests running in the same test binary never share or
// cross-contaminate debug state -- each gets its own DebugLogger
// value, closed over its own *log.Logger writer.
type DebugLogger struct {
	logger  *log.Logger
	enabled bool
}

// NewDebugLogger constructs a DebugLogger that writes to logger only
// when enabled is true. logger may be nil if enabled is false (Debugf
// never dereferences it in that case) -- callers that always have a
// real logger available (the common case) should still pass one, but
// this is not required for a disabled instance.
func NewDebugLogger(logger *log.Logger, enabled bool) *DebugLogger {
	return &DebugLogger{logger: logger, enabled: enabled}
}

// Debugf logs only if d is non-nil and enabled -- both checked BEFORE
// any formatting work happens, so a disabled (or nil) DebugLogger's
// Debugf call costs a single branch, never a fmt.Sprintf-equivalent
// allocation/format pass. Safe to call on a nil *DebugLogger (a
// caller that never constructed one, e.g. an existing test harness
// that predates -debug, gets a no-op rather than a panic).
func (d *DebugLogger) Debugf(format string, args ...any) {
	if d == nil || !d.enabled {
		return
	}
	d.logger.Printf("[DEBUG] "+format, args...)
}

// Enabled reports whether d is non-nil and was constructed with
// enabled=true. Exists for call sites that want to skip constructing
// an expensive argument list entirely (beyond what Debugf's own
// lazy-formatting already avoids), e.g. a caller that would otherwise
// need to serialize a struct just to pass it as a %v argument.
func (d *DebugLogger) Enabled() bool {
	return d != nil && d.enabled
}
