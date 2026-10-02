// Copyright and license: see repository LICENSE (MIT).

// Package proxy (this file): HTTP Basic Auth gate for leaf-proxy's
// metrics/stats HTTP surface (DISPATCH_BRIEF.md "leaf-proxy ...
// password-protected metrics like xnp style"). Alex's own framing,
// quoted verbatim: "metrics with password protection like xnp style
// - This would be the entire metrics endpoint, including the status
// panel, should default to off".
//
// Design: OFF BY DEFAULT, opt-in once a password is configured. When
// -metrics-password/LEAF_PROXY_METRICS_PASSWORD is empty (the
// default), WrapMetricsAuth returns its handler argument completely
// unwrapped -- a literal no-op, zero behavior change, zero added
// latency, for every deployment that doesn't set a password. ONLY
// when a non-empty password is configured does this wrap EVERY
// handler registered on the caller's metricsMux (not just
// /metrics -- /, /api/miners, and /api/miners/history too, since
// they all share the same mux) in an HTTP Basic Auth check requiring
// that exact username/password.
//
// This is a public-facing HTTP port (cmd/leaf-proxy's
// -metrics-listen-address can be bound to a wildcard/public address,
// not just loopback), so the credential comparison uses
// subtle.ConstantTimeCompare on both username and password -- never
// a plain "==" string comparison -- to avoid a timing side-channel,
// mirroring this codebase's existing defensive treatment of
// untrusted input (see session.go's addressflags ban-check callers).
// A failed or missing auth attempt gets a standard 401 response with
// a WWW-Authenticate: Basic header -- ordinary Go net/http idiom, no
// custom auth scheme invented.
package proxy

import (
	"crypto/subtle"
	"net/http"
)

// WrapMetricsAuth returns next unchanged when password == "" (the
// default -- "off" per Alex's own ask). Otherwise it returns a new
// http.Handler that requires HTTP Basic Auth with EXACTLY username/
// password before delegating to next; a missing or mismatched
// credential gets 401 with a WWW-Authenticate: Basic header, and next
// is never invoked for that request.
//
// Intended caller: cmd/leaf-proxy/main.go, wrapping the fully-built
// metricsMux (after every route -- /metrics, /, /api/miners,
// /api/miners/history -- has already been registered on it) exactly
// once, immediately before constructing the *http.Server that serves
// it.
func WrapMetricsAuth(next http.Handler, username, password string) http.Handler {
	if password == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, ok := r.BasicAuth()
		if !ok || !constantTimeStringsEqual(gotUser, username) || !constantTimeStringsEqual(gotPass, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="leaf-proxy metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// constantTimeStringsEqual compares a and b in constant time via
// subtle.ConstantTimeCompare -- NOT "==", which short-circuits on the
// first mismatched byte and would leak a timing signal about how many
// leading bytes of an attacker-supplied credential happened to match
// the real one. subtle.ConstantTimeCompare itself requires equal-
// length inputs to even consider comparing (it returns 0 immediately
// otherwise, which is still safe: that early return happens BEFORE
// any byte-by-byte work and leaks only the (already-public, fixed)
// expected length, not which bytes matched).
func constantTimeStringsEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
