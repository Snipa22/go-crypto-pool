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

// --- DISPATCH_BRIEF.md 2026-09-13 (Alex): cap starting/min difficulty
// to the pool's own target_diff -------------------------------------
//
// The tests below cover session.go's handleLogin's new one-time,
// login-only cap: none of the three difficulty floors (port tier's
// own starting_difficulty, the global cfg.min_difficulty, and the
// per-address operator ForcedMinDifficulty) may leave a session
// starting ABOVE whatever the upstream pool's own current
// WorkerTemplate.TargetDiff (Job.UpstreamShareDiff's provenance) is
// actually asking for right now.

// poolTemplateWithTargetDiff builds a WorkerTemplate identical to
// newHarness's own default fixture, except for TargetDiff -- letting
// each test below install whatever pool target_diff it needs via
// h.source.setTemplate(...) before logging in.
func poolTemplateWithTargetDiff(targetDiff uint64) *WorkerTemplate {
	return &WorkerTemplate{
		Blob:              fakeBlob(76, 50),
		ReservedOffset:    50,
		ClientNonceOffset: -1,
		PoolOffset:        -1,
		SeedHash:          []byte("test-seed-hash-32-bytes-exactly!"),
		Height:            123,
		JobID:             "upstream-job-1",
		TargetDiff:        targetDiff,
		Difficulty:        1000,
	}
}

// TestSessionLogin_PoolTargetDiffCapsPortStartingDifficulty is Alex's
// exact reported example: pool target_diff (50_000) LOWER than the
// port's starting_difficulty (300_000, no operator floor) -> the
// session must start at 50_000, not 300_000.
func TestSessionLogin_PoolTargetDiffCapsPortStartingDifficulty(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	const (
		addr           = "pool-cap-address-1"
		portStartDiff  = uint64(300_000)
		poolTargetDiff = uint64(50_000)
	)
	h.source.setTemplate(poolTemplateWithTargetDiff(poolTargetDiff))

	c, _ := h.connectAtDifficulty(portStartDiff)
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to succeed, got status=%q", loginResp.Result.Status)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != poolTargetDiff {
		t.Fatalf("expected starting difficulty to be capped down to the pool's target_diff %d, got %d", poolTargetDiff, got)
	}
}

// TestSessionLogin_PoolTargetDiffCapsForcedMinDifficultyFloor covers
// the "cap ALL THREE floors" scope decision explicitly: the pool's
// target_diff (50_000) must win even over an operator's
// ForcedMinDifficulty floor (1_000_000) -- the session still starts
// at 50_000. forcedMinDifficulty itself must still be captured as the
// operator's RAW, uncapped value (1_000_000): that field feeds
// maybeRetarget's own ongoing floor logic, which this change does not
// touch (see vardiff.go's TestMaybeRetarget_NeverUndercutsForcedMinDifficulty,
// unaffected by this change and re-verified below).
func TestSessionLogin_PoolTargetDiffCapsForcedMinDifficultyFloor(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)

	const (
		addr           = "pool-cap-address-2"
		portStartDiff  = uint64(1000)
		operatorFloor  = uint64(1_000_000)
		poolTargetDiff = uint64(50_000)
	)
	h.source.setTemplate(poolTemplateWithTargetDiff(poolTargetDiff))

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
	if got := sess.currentDifficulty.Load(); got != poolTargetDiff {
		t.Fatalf("expected the pool's target_diff %d to win even over the operator's forced floor %d, got %d", poolTargetDiff, operatorFloor, got)
	}
	if got := sess.forcedMinDifficulty.Load(); got != operatorFloor {
		t.Fatalf("expected forcedMinDifficulty to still record the operator's RAW, uncapped floor %d, got %d", operatorFloor, got)
	}
}

// --- DISPATCH_BRIEF.md 2026-09-13 (Alex): make the pool-diff cap
// toggleable (default ON) -------------------------------------------
//
// The tests below cover Server.poolDiffCapEnabled/
// SetPoolDiffCapEnabled -- the new toggle gating the entire cap block
// tested above. newHarness's NewServer defaults poolDiffCapEnabled to
// true (the implicit/default case, flag never set), which is already
// exercised by TestSessionLogin_PoolTargetDiffCapsPortStartingDifficulty
// above; the tests below cover the explicit-true and explicit-false
// cases.

// TestSessionLogin_PoolDiffCapDisabled_PortStartingDifficultyNotCapped
// is the required "flag disabled" test: Alex's exact reported example
// (300k port floor, 50k pool target_diff) must now start at 300k, NOT
// capped to 50k, proving the flag genuinely gates the cap block --
// this is the exact byte-identical pre-46a6e2c max()-of-floors
// behavior.
func TestSessionLogin_PoolDiffCapDisabled_PortStartingDifficultyNotCapped(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.SetPoolDiffCapEnabled(false)

	const (
		addr           = "pool-cap-toggle-disabled-address"
		portStartDiff  = uint64(300_000)
		poolTargetDiff = uint64(50_000)
	)
	h.source.setTemplate(poolTemplateWithTargetDiff(poolTargetDiff))

	c, _ := h.connectAtDifficulty(portStartDiff)
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to succeed, got status=%q", loginResp.Result.Status)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != portStartDiff {
		t.Fatalf("expected starting difficulty to remain at the port's own %d (cap disabled), got %d", portStartDiff, got)
	}
}

// TestSessionLogin_PoolDiffCapEnabledExplicit_StillCapsPortStartingDifficulty
// is the required "flag enabled, explicit true" test: re-runs Alex's
// exact scenario with SetPoolDiffCapEnabled(true) wired explicitly
// (rather than relying on NewServer's own default), proving the
// existing capped behavior from commit 46a6e2c still holds when the
// toggle is explicitly turned on.
func TestSessionLogin_PoolDiffCapEnabledExplicit_StillCapsPortStartingDifficulty(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	h.server.SetPoolDiffCapEnabled(true)

	const (
		addr           = "pool-cap-toggle-enabled-address"
		portStartDiff  = uint64(300_000)
		poolTargetDiff = uint64(50_000)
	)
	h.source.setTemplate(poolTemplateWithTargetDiff(poolTargetDiff))

	c, _ := h.connectAtDifficulty(portStartDiff)
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to succeed, got status=%q", loginResp.Result.Status)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != poolTargetDiff {
		t.Fatalf("expected starting difficulty to be capped down to the pool's target_diff %d (cap explicitly enabled), got %d", poolTargetDiff, got)
	}
}

// TestSessionLogin_PoolTargetDiffHigherThanFloors_NoRegression is the
// required non-regression check: when the pool's own target_diff is
// HIGHER than every configured/forced floor, the existing
// floor-stacking behavior (max of port starting_difficulty,
// cfg.min_difficulty, and the operator's ForcedMinDifficulty) is
// preserved untouched -- no cap applied.
func TestSessionLogin_PoolTargetDiffHigherThanFloors_NoRegression(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour, MinDifficulty: 10_000}, 0)

	const (
		addr           = "pool-cap-address-3"
		portStartDiff  = uint64(300_000)
		operatorFloor  = uint64(50_000)
		poolTargetDiff = uint64(5_000_000)
	)
	h.source.setTemplate(poolTemplateWithTargetDiff(poolTargetDiff))

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
	// max(portStartDiff=300_000, cfg.MinDifficulty=10_000, operatorFloor=50_000) == 300_000.
	if got := sess.currentDifficulty.Load(); got != portStartDiff {
		t.Fatalf("expected the existing max()-of-floors starting difficulty %d to be unaffected by a HIGHER pool target_diff, got %d", portStartDiff, got)
	}
}

// TestSessionLogin_NoPoolTemplateYet_FallsBackToUncappedFloors covers
// "no template/target_diff available yet at login" -> falls back to
// today's uncapped max()-of-floors behavior, no cap applied, no
// panic/error. Exercised via TargetDiff == 0 on an otherwise-live
// template (a genuinely nil CurrentTemplate() would also fail
// currentJob's OWN separate "no job template available yet" path in
// handleLogin, which is unrelated to this cap and not what this test
// is pinning down -- see
// TestJobManager_CurrentTargetDiffForRoute_NoTemplate in job_test.go
// for the nil-template case against the accessor directly).
func TestSessionLogin_NoPoolTemplateYet_FallsBackToUncappedFloors(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour, MinDifficulty: 10_000}, 0)

	const (
		addr          = "pool-cap-address-4"
		portStartDiff = uint64(300_000)
		operatorFloor = uint64(50_000)
	)
	h.source.setTemplate(poolTemplateWithTargetDiff(0)) // pool dialect that never published target_diff

	src := &fakeAddressFlagsSource{flags: map[string]addressflags.Flags{
		addr: {ForcedMinDifficulty: operatorFloor},
	}}
	cache := addressflags.NewCache(src, 0, nil)
	cache.Start(context.Background())
	h.server.EnableAddressFlags(cache)

	c, _ := h.connectAtDifficulty(portStartDiff)
	loginResp := c.login(t, addr)
	if loginResp.Result.Status != "OK" {
		t.Fatalf("expected login to succeed with no panic/error, got status=%q", loginResp.Result.Status)
	}

	sess := h.onlySession()
	if got := sess.currentDifficulty.Load(); got != portStartDiff {
		t.Fatalf("expected the uncapped max()-of-floors starting difficulty %d (no pool target_diff known), got %d", portStartDiff, got)
	}
}

// TestMaybeRetarget_NeverUndercutsForcedMinDifficulty_StillUnaffected
// re-confirms (per the brief's required test 5) that this login-time-
// only cap change leaves vardiff.go's maybeRetarget completely
// unchanged for an ALREADY-STARTED session: even though the pool's
// own target_diff here is far BELOW the operator's forced floor at
// login time (so this session's STARTING difficulty is itself capped
// down), subsequent maybeRetarget ticks must still never undercut the
// operator's raw, uncapped ForcedMinDifficulty floor -- proving the
// cap genuinely never reaches maybeRetarget at all.
func TestMaybeRetarget_NeverUndercutsForcedMinDifficulty_StillUnaffected(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour, TargetTime: 30}, 0)

	const (
		addr           = "pool-cap-retarget-address"
		startDiff      = uint64(1000)
		operatorFloor  = uint64(500)
		poolTargetDiff = uint64(50) // far below the operator floor -- caps this session's START only
	)
	h.source.setTemplate(poolTemplateWithTargetDiff(poolTargetDiff))

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
	if got := sess.currentDifficulty.Load(); got != poolTargetDiff {
		t.Fatalf("expected the session to START at the pool-capped difficulty %d, got %d", poolTargetDiff, got)
	}
	if got := sess.forcedMinDifficulty.Load(); got != operatorFloor {
		t.Fatalf("expected forcedMinDifficulty to still record the operator's RAW floor %d, got %d", operatorFloor, got)
	}

	sess.connectedAt = time.Now().Add(-1 * time.Hour)

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
			t.Fatalf("retarget tick %d: currentDifficulty=%d undercut the operator floor %d -- the login-time pool cap must never reach maybeRetarget", i, got, operatorFloor)
		}
	}
	if got := sess.currentDifficulty.Load(); got != operatorFloor {
		t.Errorf("expected repeated decaying retargets to climb back up to and settle exactly at the operator floor %d, got %d", operatorFloor, got)
	}

	c.client.Close()
	<-done
}
