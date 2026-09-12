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
