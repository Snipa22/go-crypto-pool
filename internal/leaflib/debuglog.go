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

	// Level is the leveled-logging threshold consulted by Logf below
	// (DISPATCH_BRIEF.md "leaf-proxy ... log levels"; Alex's ask:
	// "error level 0 / 1 / 2 something like that to avoid useless
	// errors in foreground mode"). Semantics are owned by the
	// calling binary's own -log-level flag doc comment
	// (cmd/leaf-proxy/main.go), but the general shape is: 0 = quiet
	// (suppress routine, non-actionable, per-connection noise such
	// as a bad/buggy client's unparseable message or a port
	// scanner's garbage input), 1 = normal (today's un-leveled
	// output, the default), 2 = verbose (folds -debug's own output
	// in too). Exported, and deliberately a plain field rather than
	// a constructor parameter: only leaf-proxy's call sites consult
	// it today (via Logf), so it is set directly after construction
	// (mirroring how simple this type already is) rather than
	// growing NewDebugLogger's signature for every caller. Zero
	// value (0) is a safe, conservative default for any OTHER
	// caller that never sets it (backend/leaf-solo/leaf-direct) --
	// they never call Logf at all, so this field is simply inert for
	// them.
	Level int
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

// Logf logs via the underlying logger (no "[DEBUG]" prefix -- unlike
// Debugf, this is for ordinary leveled operational output, not a
// separate verbose-debug tag) only if d is non-nil AND d.Level >=
// level -- a cheap >= check before any formatting work, exactly like
// Debugf's own enabled check. Safe to call on a nil *DebugLogger (a
// caller that never constructed one gets a no-op, matching Debugf's
// nil-safety contract).
//
// This is leaf-proxy's -log-level mechanism (DISPATCH_BRIEF.md): call
// sites that fire routine, non-actionable, per-connection noise (e.g.
// a bad/buggy client's unparseable message) call Logf(1, ...) so that
// output disappears at -log-level=0 but is otherwise identical to
// today's un-leveled behavior at the default level (1) and above.
// This is deliberately a SMALL addition to the existing DebugLogger
// type rather than a new, parallel leveled-logger mechanism -- see
// this type's own doc comment.
func (d *DebugLogger) Logf(level int, format string, args ...any) {
	if d == nil || d.Level < level {
		return
	}
	d.logger.Printf(format, args...)
}
