// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestDebugLoggerDisabledWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	d := NewDebugLogger(logger, false)

	d.Debugf("share submitted job_id=%s nonce=%s", "abc", "def")

	if buf.Len() != 0 {
		t.Fatalf("expected no output when disabled, got %q", buf.String())
	}
	if d.Enabled() {
		t.Fatal("expected Enabled() to be false")
	}
}

func TestDebugLoggerEnabledWrites(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	d := NewDebugLogger(logger, true)

	d.Debugf("share submitted job_id=%s nonce=%s", "abc", "def")

	got := buf.String()
	if !strings.Contains(got, "[DEBUG]") {
		t.Fatalf("expected output to contain [DEBUG] tag, got %q", got)
	}
	if !strings.Contains(got, "job_id=abc") || !strings.Contains(got, "nonce=def") {
		t.Fatalf("expected formatted args in output, got %q", got)
	}
	if !d.Enabled() {
		t.Fatal("expected Enabled() to be true")
	}
}

func TestDebugLoggerNilIsSafeNoOp(t *testing.T) {
	var d *DebugLogger
	// Must not panic, must not write anywhere (there is nowhere to
	// write to -- d.logger is never dereferenced for a nil receiver).
	d.Debugf("this must not panic: %s", "arg")
	if d.Enabled() {
		t.Fatal("expected Enabled() to be false for a nil *DebugLogger")
	}
}

func TestDebugLoggerMultipleInstancesDoNotShareState(t *testing.T) {
	var bufA, bufB bytes.Buffer
	loggerA := log.New(&bufA, "", 0)
	loggerB := log.New(&bufB, "", 0)

	dA := NewDebugLogger(loggerA, true)
	dB := NewDebugLogger(loggerB, false)

	dA.Debugf("from A")
	dB.Debugf("from B")

	if !strings.Contains(bufA.String(), "from A") {
		t.Fatalf("expected bufA to contain \"from A\", got %q", bufA.String())
	}
	if bufB.Len() != 0 {
		t.Fatalf("expected bufB to be empty (dB disabled), got %q", bufB.String())
	}
}

// --- Logf (leaf-proxy's -log-level mechanism) -----------------------

// TestDebugLoggerLogf_SuppressedBelowLevel confirms Logf(level, ...)
// is a no-op when d.Level < level -- the exact mechanism leaf-proxy's
// -log-level=0 ("quiet") relies on to suppress routine per-connection
// noise logged via Logf(1, ...).
func TestDebugLoggerLogf_SuppressedBelowLevel(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	d := NewDebugLogger(logger, false)
	d.Level = 0

	d.Logf(1, "session %s sent unparseable message: %v", "abc", "boom")

	if buf.Len() != 0 {
		t.Fatalf("expected no output when Level(0) < level(1), got %q", buf.String())
	}
}

// TestDebugLoggerLogf_FiresAtOrAboveLevel confirms Logf(level, ...)
// fires when d.Level >= level, at exactly the default level (1,
// "normal") and above (2, "verbose") -- both must produce the exact
// same output for a line gated at level 1, matching the documented
// "byte-identical to today's un-leveled output" contract.
func TestDebugLoggerLogf_FiresAtOrAboveLevel(t *testing.T) {
	for _, level := range []int{1, 2} {
		var buf bytes.Buffer
		logger := log.New(&buf, "", 0)
		d := NewDebugLogger(logger, false)
		d.Level = level

		d.Logf(1, "session %s sent unparseable message: %v", "abc", "boom")

		got := buf.String()
		if !strings.Contains(got, "session abc sent unparseable message: boom") {
			t.Fatalf("Level=%d: expected formatted output, got %q", level, got)
		}
		// Logf never adds a "[DEBUG]" tag -- unlike Debugf, this is
		// ordinary leveled operational output, not verbose-debug
		// output.
		if strings.Contains(got, "[DEBUG]") {
			t.Fatalf("Level=%d: Logf output must not carry a [DEBUG] tag, got %q", level, got)
		}
	}
}

// TestDebugLoggerLogf_NilIsSafeNoOp mirrors
// TestDebugLoggerNilIsSafeNoOp for Logf.
func TestDebugLoggerLogf_NilIsSafeNoOp(t *testing.T) {
	var d *DebugLogger
	d.Logf(0, "this must not panic: %s", "arg")
}

// TestDebugLoggerLogf_ZeroValueLevelDefaultsToSuppressed confirms a
// DebugLogger constructed via NewDebugLogger (which never sets Level)
// has Level == 0 by default -- so a Logf(1, ...) call against a
// caller that never explicitly set Level is suppressed, not silently
// treated as "normal". This is the documented, safe default for
// every OTHER caller of DebugLogger (backend/leaf-solo/leaf-direct)
// that never sets Level at all and never calls Logf either -- this
// test exists purely to pin that zero-value contract down explicitly.
func TestDebugLoggerLogf_ZeroValueLevelDefaultsToSuppressed(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	d := NewDebugLogger(logger, false)

	d.Logf(1, "should not appear")

	if buf.Len() != 0 {
		t.Fatalf("expected no output for a DebugLogger whose Level was never set, got %q", buf.String())
	}
}
