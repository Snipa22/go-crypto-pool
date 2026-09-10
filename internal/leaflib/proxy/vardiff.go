// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// runVardiffLoop/maybeRetarget are leaf-proxy's downstream-session
// counterpart to internal/leaflib/solo/vardiff.go's identically-named
// methods — REUSING the exact same shared algorithm
// (leaflib.ComputeRetarget, extracted from solo specifically so this
// package could reuse it — see leaflib/vardiff.go's doc comment)
// rather than re-implementing the retarget math. Scoped to this
// session's own connection lifetime context exactly like solo's
// version (no shared/global scheduler — bug class 5 from leaflib.go's
// doc comment, avoided here the same way).
func (s *Session) runVardiffLoop(ctx context.Context) {
	interval := s.server.vardiff.RetargetInterval
	if interval <= 0 {
		interval = leaflib.DefaultVardiffConfig().RetargetInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.maybeRetarget()
		}
	}
}

func (s *Session) maybeRetarget() {
	cfg := s.server.vardiff
	connSeconds := int(time.Since(s.connectedAt).Seconds())
	if connSeconds < int(cfg.RetargetInterval.Seconds()) {
		return
	}

	curDiff := s.currentDifficulty.Load()
	hashes := s.hashesAccumulated.Load()

	// Fix 7 (DISPATCH_BRIEF.md 2026-09-10): an operator-forced
	// minimum difficulty (see session.go's handleLogin and
	// internal/leaflib/addressflags's package doc comment) must
	// never be undercut by a vardiff retarget for the lifetime of
	// this connection -- mirrors solo.Session.maybeRetarget's
	// identical floor-raising logic exactly. 0 (the overwhelmingly
	// common case) is a complete no-op.
	minDiff := cfg.MinDifficulty
	if floor := s.forcedMinDifficulty.Load(); floor > minDiff {
		minDiff = floor
	}

	newDiff, changed := leaflib.ComputeRetarget(curDiff, hashes, connSeconds, cfg.TargetTime, minDiff, cfg.MaxDifficulty)
	if !changed {
		return
	}

	s.currentDifficulty.Store(newDiff)

	// Routed through currentJob (session.go) rather than
	// s.server.jobs.NextJob directly -- see currentJob's own doc
	// comment. In practice this call will almost always mint a
	// genuinely fresh job anyway, since leaflib.ComputeRetarget only
	// reports changed=true when the difficulty genuinely changed
	// (matching XNP's own !miner.newDiff gate: a real retarget always
	// forces a new job) -- but going through currentJob here too
	// keeps a single, consistent code path across every production
	// job-issuance call site, at no cost.
	job, err := s.currentJob(newDiff)
	if err != nil {
		s.server.logger.Printf("proxy: vardiff retarget for session %s failed to build a new job: %v", s.sessionID, err)
		return
	}
	s.server.logger.Printf("proxy: vardiff retarget for session %s: %d -> %d (hashes=%d, connSeconds=%d)", s.sessionID, curDiff, newDiff, hashes, connSeconds)
	s.pushJob(job)
}
