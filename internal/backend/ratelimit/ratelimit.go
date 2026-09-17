// Package ratelimit implements a per-source-IP token-bucket rate
// limiter, and an http.Handler-wrapping middleware built on top of
// it, for this backend's public, unauthenticated, read-only HTTP
// routes (see internal/backend/statsapi, internal/backend/networkapi,
// internal/backend/legacyconfig, and cmd/backend's wiring of all
// three behind Middleware).
//
// There is no prior rate-limiting code anywhere else in this
// codebase to mirror (golang.org/x/time/rate was only an indirect,
// unused go.mod dependency before this package) -- this is a
// deliberately small, from-scratch design:
//
//   - One golang.org/x/time/rate.Limiter per distinct source IP,
//     lazily created on first request from that IP.
//   - Bounded memory: idle per-IP limiters are periodically swept by
//     Cleanup/RunJanitor, so a flood of distinct source IPs (e.g. a
//     spoofed/rotating-IP DoS attempt) cannot grow this package's own
//     internal map without bound forever -- exactly the kind of
//     footgun a rate limiter must not itself introduce while fixing a
//     DoS finding.
//   - A limiter constructed with a non-positive requests-per-second
//     value is simply disabled: Allow always returns true, and no
//     per-IP map entries are ever created, so a deployment that turns
//     this off pays no memory/CPU cost for it either.
//
// Middleware determines the request's source IP the same way
// http.Request.RemoteAddr is universally consulted elsewhere for a
// "who is this connection from" question -- see clientIP's own doc
// comment for why this package does not consult X-Forwarded-For.
package ratelimit

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a per-source-IP token-bucket rate limiter. The zero
// value is not usable -- construct one with New.
type Limiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor

	limit rate.Limit
	burst int

	// disabled is set by New when constructed with a non-positive
	// requests-per-second value -- see this package's doc comment.
	// Allow short-circuits to true and never touches visitors, so a
	// disabled Limiter carries no memory-growth footgun at all.
	disabled bool
}

// visitor is one source IP's token bucket, plus the last time it was
// seen -- used by Cleanup to evict entries that have gone idle long
// enough that they are no longer worth keeping around.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// New constructs a Limiter allowing perSecond requests/second
// sustained, per distinct source IP, with the given token-bucket
// burst size. perSecond <= 0 disables rate limiting entirely (Allow
// always returns true) -- this is the documented, intentional escape
// hatch for -stats-api-rate-limit-per-second/
// GCPOOL_STATS_API_RATE_LIMIT_PER_SECOND <= 0 in cmd/backend.
func New(perSecond float64, burst int) *Limiter {
	l := &Limiter{visitors: make(map[string]*visitor)}
	if perSecond <= 0 {
		l.disabled = true
		return l
	}
	l.limit = rate.Limit(perSecond)
	l.burst = burst
	return l
}

// Enabled reports whether this Limiter actually enforces a limit (see
// New's doc comment on perSecond <= 0).
func (l *Limiter) Enabled() bool {
	return l != nil && !l.disabled
}

// Allow reports whether the caller identified by key (typically a
// source IP -- see clientIP) may proceed right now, consuming one
// token from that key's bucket if so. A disabled Limiter (see New)
// always returns true without allocating any per-key state.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.disabled {
		return true
	}

	l.mu.Lock()
	v, ok := l.visitors[key]
	if !ok {
		v = &visitor{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.visitors[key] = v
	}
	v.lastSeen = time.Now()
	lim := v.limiter
	l.mu.Unlock()

	return lim.Allow()
}

// Cleanup evicts every per-key visitor entry that has not been seen
// in at least maxAge, bounding this Limiter's memory footprint. Safe
// to call concurrently with Allow. A no-op on a disabled Limiter
// (which never has any entries to evict).
func (l *Limiter) Cleanup(maxAge time.Duration) {
	if l == nil || l.disabled {
		return
	}
	cutoff := time.Now().Add(-maxAge)

	l.mu.Lock()
	defer l.mu.Unlock()
	for key, v := range l.visitors {
		if v.lastSeen.Before(cutoff) {
			delete(l.visitors, key)
		}
	}
}

// RunJanitor calls Cleanup(maxAge) every interval until ctx is done.
// Intended to be started as its own goroutine (mirroring every other
// poll-loop's `go x.RunLoop(ctx)` convention in cmd/backend/main.go's
// run()). A no-op that returns immediately on a disabled Limiter.
func (l *Limiter) RunJanitor(ctx context.Context, interval, maxAge time.Duration) {
	if l == nil || l.disabled {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.Cleanup(maxAge)
		}
	}
}

// clientIP resolves the rate-limiting key for r: the request's source
// IP, with the port stripped from http.Request.RemoteAddr.
//
// This intentionally does NOT consult X-Forwarded-For (or any other
// client-supplied header): trusting a header the client itself sent
// for a rate-limit KEY would let any client bypass its own limit for
// free by simply sending a different value per request, which is
// worse than not being X-Forwarded-For-aware at all. If this backend
// is ever deployed behind a reverse proxy whose X-Forwarded-For value
// must be trusted for the real client IP, that should be an explicit,
// separately-configured decision (e.g. a trusted-proxy CIDR allowlist
// gating when the header is honored), not silently assumed here.
//
// This is a small, local adaptation of the SplitHostPort-based
// convention internal/leaflib/metrics.RemoteIPOf already establishes
// for a net.Addr -- http.Request.RemoteAddr is already a plain
// "host:port" string (not a net.Addr), so adapting that helper would
// add an indirection for no benefit; the logic itself (SplitHostPort,
// fall back to the raw string if it doesn't parse as host:port) is
// identical.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// tooManyRequestsBody is the small JSON body Middleware writes
// alongside HTTP 429 -- a real, informative body rather than either a
// silent drop or a bare status code with no explanation.
type tooManyRequestsBody struct {
	Error string `json:"error"`
}

// Middleware wraps next with limiter's per-source-IP rate limiting. A
// request whose source IP has exceeded its rate gets a real HTTP 429
// Too Many Requests response with a short JSON body, and next is NOT
// called for it. A nil or disabled limiter (see New) always calls
// next.
func Middleware(next http.Handler, limiter *Limiter) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(clientIP(r)) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(tooManyRequestsBody{Error: "rate limit exceeded, slow down"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
