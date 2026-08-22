// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// runVardiffLoop mirrors solo.Session's own runVardiffLoop exactly,
// reusing internal/leaflib.VardiffConfig/ComputeRetarget (the shared
// package extracted specifically so leaf-proxy and leaf-direct can
// both reuse the exact same retarget algorithm without duplicating
// it) via s.server.vardiff (a solo.VardiffConfig, itself a type alias
// for leaflib.VardiffConfig — see solo/vardiff.go).
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

// maybeRetarget mirrors solo.Session's own maybeRetarget exactly.
func (s *Session) maybeRetarget() {
	cfg := s.server.vardiff
	connSeconds := int(time.Since(s.connectedAt).Seconds())
	if connSeconds < int(cfg.RetargetInterval.Seconds()) {
		return
	}

	curDiff := s.currentDifficulty.Load()
	hashes := s.hashesAccumulated.Load()

	newDiff, changed := leaflib.ComputeRetarget(curDiff, hashes, connSeconds, cfg.TargetTime, cfg.MinDifficulty, cfg.MaxDifficulty)
	if !changed {
		return
	}

	s.currentDifficulty.Store(newDiff)

	job, err := s.server.jobManager.RestampDifficulty(context.Background(), s.xn, newDiff)
	if err != nil {
		s.server.logger.Printf("direct: vardiff retarget for session %s (xn %s) failed to restamp job: %v", s.sessionID, s.xn, err)
		return
	}
	s.server.logger.Printf("direct: vardiff retarget for session %s (xn %s): %d -> %d (hashes=%d, connSeconds=%d)", s.sessionID, s.xn, curDiff, newDiff, hashes, connSeconds)
	s.pushJob(job)
}
