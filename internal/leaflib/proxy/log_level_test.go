// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestHandleLine_UnparseableMessage_SuppressedAtLogLevelZero and
// TestHandleLine_UnparseableMessage_LoggedAtLogLevelOne are the
// required section-2 verification tests (DISPATCH_BRIEF.md "Required
// verification before you report done", item 2): "feed handleLine
// unparseable JSON at level 0 vs level 1 and assert on logged output
// presence/absence".
//
// Both tests route handleLine's noise line through
// leaflib.DebugLogger.Logf(1, ...) (session.go) -- see that call
// site's own doc comment for why this exact line was chosen as the
// section's confirmed offender.

func TestHandleLine_UnparseableMessage_SuppressedAtLogLevelZero(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	var buf bytes.Buffer
	h.server.logger = log.New(&buf, "", 0)
	h.server.debugLogger = leaflib.NewDebugLogger(h.server.logger, false)
	h.server.debugLogger.Level = 0

	c, _ := h.connect()
	c.login(t, "log-level-test-addr")

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	sess.handleLine("this is not valid json{{{")

	if buf.Len() != 0 {
		t.Fatalf("expected NO log output at -log-level=0 for an unparseable message, got %q", buf.String())
	}
}

func TestHandleLine_UnparseableMessage_LoggedAtLogLevelOne(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	var buf bytes.Buffer
	h.server.logger = log.New(&buf, "", 0)
	h.server.debugLogger = leaflib.NewDebugLogger(h.server.logger, false)
	h.server.debugLogger.Level = 1

	c, _ := h.connect()
	c.login(t, "log-level-test-addr")
	buf.Reset() // discard any login-time logging noise unrelated to this assertion

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	sess.handleLine("this is not valid json{{{")

	got := buf.String()
	if !strings.Contains(got, "sent unparseable message") {
		t.Fatalf("expected log output at -log-level=1 (today's default, byte-identical-to-unleveled behavior) for an unparseable message, got %q", got)
	}
}

// TestHandleLine_UnparseableMessage_LoggedAtLogLevelTwo confirms the
// "verbose" level also still logs this line (it folds -debug's
// output in ADDITIONALLY, it never suppresses anything level 1
// already showed).
func TestHandleLine_UnparseableMessage_LoggedAtLogLevelTwo(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	var buf bytes.Buffer
	h.server.logger = log.New(&buf, "", 0)
	h.server.debugLogger = leaflib.NewDebugLogger(h.server.logger, true)
	h.server.debugLogger.Level = 2

	c, _ := h.connect()
	c.login(t, "log-level-test-addr")
	buf.Reset()

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}

	sess.handleLine("this is not valid json{{{")

	got := buf.String()
	if !strings.Contains(got, "sent unparseable message") {
		t.Fatalf("expected log output at -log-level=2 for an unparseable message, got %q", got)
	}
}

// --- oversized-login rejection (the OTHER line this section gates) --

func TestHandleLogin_OversizedLogin_SuppressedAtLogLevelZero(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	var buf bytes.Buffer
	h.server.logger = log.New(&buf, "", 0)
	h.server.debugLogger = leaflib.NewDebugLogger(h.server.logger, false)
	h.server.debugLogger.Level = 0

	oversized := strings.Repeat("a", maxProxyLoginLen+1)
	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: oversized, Pass: "rig1", Agent: "XMRig/6.21.0"})})

	var resp ErrorResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		t.Fatalf("unmarshal oversized-login rejection response: %v", err)
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatal("expected an oversized login string to be rejected with a non-empty error message, got none")
	}

	if buf.Len() != 0 {
		t.Fatalf("expected NO log output at -log-level=0 for an oversized login rejection, got %q", buf.String())
	}
}

func TestHandleLogin_OversizedLogin_LoggedAtLogLevelOne(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	var buf bytes.Buffer
	h.server.logger = log.New(&buf, "", 0)
	h.server.debugLogger = leaflib.NewDebugLogger(h.server.logger, false)
	h.server.debugLogger.Level = 1

	oversized := strings.Repeat("a", maxProxyLoginLen+1)
	c, _ := h.connect()
	c.send(Request{ID: 1, JsonRPC: "2.0", Method: "login", Params: mustMarshal(t, LoginRequest{Login: oversized, Pass: "rig1", Agent: "XMRig/6.21.0"})})

	var resp ErrorResponse
	if err := json.Unmarshal(c.recvRaw(), &resp); err != nil {
		t.Fatalf("unmarshal oversized-login rejection response: %v", err)
	}
	if resp.Error == nil || resp.Error.Message == "" {
		t.Fatal("expected an oversized login string to be rejected with a non-empty error message, got none")
	}

	got := buf.String()
	if !strings.Contains(got, "oversized login string") {
		t.Fatalf("expected log output at -log-level=1 for an oversized login rejection, got %q", got)
	}
}
