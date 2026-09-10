// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/addressflags"
)

// TestSessionLogin_ForcedMinDifficulty_RaisesStartingDifficulty is the
// required Fix 7 test (DISPATCH_BRIEF.md 2026-09-10): an operator-set
// difficulty floor (addressflags.Flags.ForcedMinDifficulty) on a
// downstream session's login address must raise its STARTING
// difficulty when the port tier's own configured starting difficulty
// is below the floor -- mirrors solo.Session's identical handleLogin
// behavior exactly (see internal/leaflib/solo/session.go's handleLogin
// doc comment).
func TestSessionLogin_ForcedMinDifficulty_RaisesStartingDifficulty(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	const (
		addr          = "floored-address"
		portStartDiff = uint64(50)
		operatorFloor = uint64(1000)
	)
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {ForcedMinDifficulty: operatorFloor},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connectAtDifficulty(portStartDiff)
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to succeed for a floored (not banned) address, got status=%q", loginResp.Result.Status)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != operatorFloor {
		t.Fatalf("expected starting difficulty to be raised to the operator floor %d, got %d", operatorFloor, got)
	}
	if got := sess.forcedMinDifficulty.Load(); got != operatorFloor {
		t.Fatalf("expected forcedMinDifficulty to be captured as %d, got %d", operatorFloor, got)
	}
	if loginResp.Result.Job.JobID == "" {
		t.Errorf("expected the login response to still carry a real job")
	}
}

// TestSessionLogin_ForcedMinDifficulty_BelowPortStartingDifficulty_NoOp
// is the non-regression complement: a floor LOWER than the port
// tier's own starting difficulty must not lower it -- it is a FLOOR,
// not a fixed/target value.
func TestSessionLogin_ForcedMinDifficulty_BelowPortStartingDifficulty_NoOp(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	const (
		addr          = "low-floor-address"
		portStartDiff = uint64(5000)
		operatorFloor = uint64(100)
	)
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {ForcedMinDifficulty: operatorFloor},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connectAtDifficulty(portStartDiff)
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to succeed, got status=%q", loginResp.Result.Status)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != portStartDiff {
		t.Fatalf("expected the port's own starting difficulty %d to be unaffected by a lower floor, got %d", portStartDiff, got)
	}
	// The floor is still recorded (it constrains future retargets),
	// even though it didn't need to raise the starting value.
	if got := sess.forcedMinDifficulty.Load(); got != operatorFloor {
		t.Fatalf("expected forcedMinDifficulty to be captured as %d regardless, got %d", operatorFloor, got)
	}
}

// TestMaybeRetarget_NeverUndercutsForcedMinDifficulty is the required
// Fix 7 test proving a retarget never goes below an operator-set
// floor: this drives many real maybeRetarget ticks against a session
// whose accept-history (hashesAccumulated stays 0 throughout, mirroring
// an idle/slow miner) would otherwise keep dragging the retarget
// formula's 0.9x-per-tick decay all the way down toward
// cfg.MinDifficulty (1) -- but forcedMinDifficulty must clamp every
// single tick's result at (or above) the floor instead.
func TestMaybeRetarget_NeverUndercutsForcedMinDifficulty(t *testing.T) {
	// RetargetInterval is deliberately large (matches every other
	// test's convention for disabling the BACKGROUND vardiff
	// goroutine, runVardiffLoop) -- this test drives maybeRetarget
	// directly, itself, from the test goroutine; a short interval
	// would also let the real background runVardiffLoop goroutine
	// (started by handleConn) fire concurrently and race this test's
	// own direct sess.connectedAt mutation below (a real, confirmed
	// `go test -race` failure otherwise: connectedAt is a plain
	// time.Time, not synchronized, and is only safe to write here
	// because the background loop's own gate never fires within the
	// lifetime of this test).
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour, TargetTime: 30}, 0)

	const (
		addr          = "floored-retarget-address"
		startDiff     = uint64(200)
		operatorFloor = uint64(100)
	)
	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {ForcedMinDifficulty: operatorFloor},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connectAtDifficulty(startDiff)
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to succeed, got status=%q", loginResp.Result.Status)
	}

	sess := h.onlySession()
	if got := sess.forcedMinDifficulty.Load(); got != operatorFloor {
		t.Fatalf("expected forcedMinDifficulty to be captured as %d, got %d", operatorFloor, got)
	}

	// Push connectedAt far into the past so every maybeRetarget call
	// below sees a connSeconds well past RetargetInterval, and leave
	// hashesAccumulated at its zero-value default (no shares
	// accepted) so ComputeRetarget's decay branch (nd =
	// curDiff*0.9) drives the difficulty steadily downward across
	// repeated ticks -- exactly the scenario that would eventually
	// undercut the floor without this fix.
	sess.connectedAt = time.Now().Add(-1 * time.Hour)

	// Drain the job pushes maybeRetarget triggers on every real
	// change so the read loop doesn't need to (this test drives
	// maybeRetarget directly, not through the wire).
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c.client.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, err := c.reader.ReadBytes('\n'); err != nil {
				return
			}
		}
	}()

	for i := 0; i < 30; i++ {
		sess.maybeRetarget()
		if got := sess.currentDifficulty.Load(); got < operatorFloor {
			t.Fatalf("retarget tick %d: currentDifficulty=%d undercut the operator floor %d", i, got, operatorFloor)
		}
	}
	if got := sess.currentDifficulty.Load(); got != operatorFloor {
		t.Errorf("expected repeated decaying retargets to eventually settle exactly at the floor %d, got %d", operatorFloor, got)
	}

	c.client.Close()
	<-done
}
