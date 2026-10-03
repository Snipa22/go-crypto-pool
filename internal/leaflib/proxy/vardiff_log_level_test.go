// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// syncBuffer is a mutex-guarded bytes.Buffer -- a plain bytes.Buffer
// is NOT safe here. retargetLogLevelHarness's connect() call spins up
// a REAL background handleConn goroutine (session_test.go's
// connectAtDifficultyWithPort) that keeps logging through this same
// buffer (session.go's -debug output, plus server.go's own
// "connection accepted"/"connection closed" Debugf calls) right up
// until that goroutine actually returns -- including AFTER each test
// below calls c.client.Close(), since the server-side goroutine's own
// deferred "connection closed" Debugf write races with whatever
// happens next on the test's main goroutine. drainJobPushes' done
// channel only observes the CLIENT side of the net.Pipe going away;
// it says nothing about whether the SERVER-side handleConn goroutine
// has finished executing its own deferred cleanup (which is exactly
// where that write comes from -- see server.go's handleConn, the
// "connection closed" Debugf inside its second defer). So the test's
// subsequent buf.String()/buf.Len() read has no synchronization with
// that write: a real, reproducible data race under `go test -race`
// (confirmed: `go test -race -run
// TestMaybeRetarget_RetargetLog_LoggedAtLogLevelTwo -count=20`
// without this fix fails nearly every run). Guarding every access
// with a mutex makes the concurrent Write/String/Len/Reset calls
// legitimately safe -- it does not change what gets logged, only
// makes reading it memory-safe while a background goroutine may
// still be writing to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Len()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

// TestMaybeRetarget_RetargetLog_SuppressedAtLogLevelZero/
// TestMaybeRetarget_RetargetLog_LoggedAtLogLevelOne/
// TestMaybeRetarget_RetargetLog_LoggedAtLogLevelTwo are
// DISPATCH_BRIEF_MIN_SHARE_FILTER.md section 2's required
// verification test ("A test proving the vardiff retarget log lines
// are suppressed at -log-level=0 and present at -log-level=1/2 --
// mirror whatever test pattern the earlier
// unparseable-message-at-level-0 test already uses in this package"),
// mirroring log_level_test.go's exact pattern.
//
// Drives a real retarget via sess.maybeRetarget() directly (same
// pattern forced_min_difficulty_test.go already uses): connectedAt is
// backdated well past RetargetInterval, and hashesAccumulated is left
// at its zero-value default, so leaflib.ComputeRetarget's decay
// branch (nd = curDiff*0.9) deterministically reports changed=true on
// the very first call -- no flakiness, no real vardiff ticker
// involved. A background goroutine drains the job push
// maybeRetarget's real pushJob call triggers so that write never
// blocks (mirrors forced_min_difficulty_test.go's identical drain
// goroutine exactly).

func retargetLogLevelHarness(t *testing.T, level int, debugEnabled bool) (*harness, *testClient, *Session, *syncBuffer) {
	t.Helper()
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Second, TargetTime: 15}, 0)

	buf := &syncBuffer{}
	h.server.logger = log.New(buf, "", 0)
	h.server.debugLogger = leaflib.NewDebugLogger(h.server.logger, debugEnabled)
	h.server.debugLogger.Level = level

	c, _ := h.connect()
	loginResp := c.login(t, "vardiff-log-level-test-addr")
	if loginResp.Result.Status != "OK" {
		t.Fatalf("login failed: %+v", loginResp)
	}

	sess := h.onlySession()
	if sess == nil {
		t.Fatal("expected a registered session after login")
	}
	// Backdate connectedAt well past RetargetInterval so the
	// connSeconds age gate in maybeRetarget never blocks this call,
	// and leave hashesAccumulated at 0 so ComputeRetarget's decay
	// branch deterministically reports changed=true.
	sess.connectedAt = time.Now().Add(-time.Hour)

	buf.Reset() // discard any login-time logging noise unrelated to this assertion

	return h, c, sess, buf
}

// drainJobPushes reads and discards every line c receives until c is
// closed -- lets maybeRetarget's real pushJob write complete without
// blocking, since this test drives maybeRetarget directly rather than
// through the wire (mirrors forced_min_difficulty_test.go's identical
// drain goroutine).
func drainJobPushes(c *testClient) (done chan struct{}) {
	done = make(chan struct{})
	go func() {
		defer close(done)
		for {
			_ = c.client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := c.reader.ReadBytes('\n'); err != nil {
				return
			}
		}
	}()
	return done
}

func TestMaybeRetarget_RetargetLog_SuppressedAtLogLevelZero(t *testing.T) {
	_, c, sess, buf := retargetLogLevelHarness(t, 0, false)
	done := drainJobPushes(c)

	sess.maybeRetarget()

	_ = c.client.Close()
	<-done

	if buf.Len() != 0 {
		t.Fatalf("expected NO log output at -log-level=0 for a vardiff retarget, got %q", buf.String())
	}
}

func TestMaybeRetarget_RetargetLog_LoggedAtLogLevelOne(t *testing.T) {
	_, c, sess, buf := retargetLogLevelHarness(t, 1, false)
	done := drainJobPushes(c)

	sess.maybeRetarget()

	_ = c.client.Close()
	<-done

	got := buf.String()
	if !strings.Contains(got, "vardiff retarget for session") {
		t.Fatalf("expected log output at -log-level=1 (today's default, byte-identical-to-unleveled behavior) for a vardiff retarget, got %q", got)
	}
}

// TestMaybeRetarget_RetargetLog_LoggedAtLogLevelTwo confirms the
// "verbose" level also still logs this line (it folds -debug's own
// output in ADDITIONALLY, it never suppresses anything level 1
// already showed) -- mirrors log_level_test.go's identical level-2
// test exactly.
func TestMaybeRetarget_RetargetLog_LoggedAtLogLevelTwo(t *testing.T) {
	_, c, sess, buf := retargetLogLevelHarness(t, 2, true)
	done := drainJobPushes(c)

	sess.maybeRetarget()

	_ = c.client.Close()
	<-done

	got := buf.String()
	if !strings.Contains(got, "vardiff retarget for session") {
		t.Fatalf("expected log output at -log-level=2 for a vardiff retarget, got %q", got)
	}
}
