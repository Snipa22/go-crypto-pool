package ratelimit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newRequest(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/balance?payment_address=addr-1", nil)
	req.RemoteAddr = remoteAddr
	return req
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remoteAddr string
		want       string
	}{
		{remoteAddr: "203.0.113.5:54321", want: "203.0.113.5"},
		{remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
		{remoteAddr: "not-a-host-port", want: "not-a-host-port"},
	}
	for _, tc := range cases {
		t.Run(tc.remoteAddr, func(t *testing.T) {
			req := newRequest(tc.remoteAddr)
			if got := clientIP(req); got != tc.want {
				t.Errorf("clientIP(%q) = %q, want %q", tc.remoteAddr, got, tc.want)
			}
		})
	}
}

func TestLimiter_UnderRateAllows(t *testing.T) {
	l := New(10, 10)
	for i := 0; i < 10; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("Allow() = false on request %d, want true (within burst)", i)
		}
	}
}

func TestLimiter_OverRateDenies(t *testing.T) {
	l := New(1, 1)
	if !l.Allow("1.2.3.4") {
		t.Fatal("first Allow() = false, want true (burst=1 should allow the first request)")
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("second immediate Allow() = true, want false (rate=1/s, burst exhausted)")
	}
}

func TestLimiter_PerKeyIndependent(t *testing.T) {
	l := New(1, 1)
	if !l.Allow("1.2.3.4") {
		t.Fatal("Allow(1.2.3.4) = false, want true")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("Allow(5.6.7.8) = false, want true -- different source IP must have its own bucket")
	}
	// 1.2.3.4 should now be exhausted, independent of 5.6.7.8.
	if l.Allow("1.2.3.4") {
		t.Fatal("second Allow(1.2.3.4) = true, want false")
	}
}

func TestLimiter_BurstAllowsInitialBucketOfRequests(t *testing.T) {
	l := New(1, 5)
	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("Allow() = false on request %d (within burst=5), want true", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("6th Allow() = true, want false (burst of 5 exhausted)")
	}
}

func TestLimiter_DisabledWhenNonPositiveRate(t *testing.T) {
	for _, rate := range []float64{0, -1, -100} {
		l := New(rate, 10)
		if l.Enabled() {
			t.Errorf("New(%v, 10).Enabled() = true, want false", rate)
		}
		for i := 0; i < 1000; i++ {
			if !l.Allow("1.2.3.4") {
				t.Fatalf("Allow() = false on request %d for disabled limiter (rate=%v), want always true", i, rate)
			}
		}
	}
}

func TestLimiter_NilLimiterAlwaysAllows(t *testing.T) {
	var l *Limiter
	if l.Enabled() {
		t.Error("nil Limiter Enabled() = true, want false")
	}
	if !l.Allow("1.2.3.4") {
		t.Error("nil Limiter Allow() = false, want true")
	}
}

func TestLimiter_Cleanup_EvictsStaleEntries(t *testing.T) {
	l := New(10, 10)
	l.Allow("1.2.3.4")
	l.Allow("5.6.7.8")

	l.mu.Lock()
	n := len(l.visitors)
	l.mu.Unlock()
	if n != 2 {
		t.Fatalf("expected 2 visitor entries before cleanup, got %d", n)
	}

	// Force 1.2.3.4's lastSeen far enough in the past that Cleanup
	// evicts it, but leave 5.6.7.8 fresh.
	l.mu.Lock()
	l.visitors["1.2.3.4"].lastSeen = time.Now().Add(-time.Hour)
	l.mu.Unlock()

	l.Cleanup(time.Minute)

	l.mu.Lock()
	_, stillHas1234 := l.visitors["1.2.3.4"]
	_, stillHas5678 := l.visitors["5.6.7.8"]
	n = len(l.visitors)
	l.mu.Unlock()

	if stillHas1234 {
		t.Error("Cleanup did not evict the stale 1.2.3.4 entry")
	}
	if !stillHas5678 {
		t.Error("Cleanup evicted the fresh 5.6.7.8 entry, want it kept")
	}
	if n != 1 {
		t.Errorf("expected 1 visitor entry after cleanup, got %d", n)
	}
}

func TestLimiter_Cleanup_NoopWhenDisabled(t *testing.T) {
	l := New(0, 10)
	l.Cleanup(time.Second) // must not panic on a disabled limiter's nil-ish state
}

func TestLimiter_RunJanitor_StopsOnContextDone(t *testing.T) {
	l := New(10, 10)
	l.Allow("1.2.3.4")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.RunJanitor(ctx, time.Millisecond, time.Nanosecond)
		close(done)
	}()

	// Give the janitor a couple of ticks to actually run Cleanup at
	// least once, evicting the entry seeded above (maxAge is
	// effectively zero).
	time.Sleep(20 * time.Millisecond)
	l.mu.Lock()
	n := len(l.visitors)
	l.mu.Unlock()
	if n != 0 {
		t.Errorf("expected RunJanitor to have evicted the stale entry, got %d remaining", n)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("RunJanitor did not return after ctx cancellation")
	}
}

func TestMiddleware_UnderRatePassesThrough(t *testing.T) {
	l := New(10, 10)
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	rr := httptest.NewRecorder()
	Middleware(next, l).ServeHTTP(rr, newRequest("1.2.3.4:1111"))

	if !called {
		t.Error("next was not called for a request under the rate limit")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestMiddleware_OverRateReturns429AndDoesNotCallNext(t *testing.T) {
	l := New(1, 1)
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	mw := Middleware(next, l)

	rr1 := httptest.NewRecorder()
	mw.ServeHTTP(rr1, newRequest("9.9.9.9:1111"))
	if rr1.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", rr1.Code)
	}

	rr2 := httptest.NewRecorder()
	mw.ServeHTTP(rr2, newRequest("9.9.9.9:2222"))
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429; body=%s", rr2.Code, rr2.Body.String())
	}
	if called != 1 {
		t.Errorf("next was called %d times, want exactly 1 (not called for the rate-limited request)", called)
	}
	if ct := rr2.Header().Get("Content-Type"); ct == "" {
		t.Error("429 response missing Content-Type header")
	}
	if rr2.Body.Len() == 0 {
		t.Error("429 response has an empty body, want a real error body (not a silent drop)")
	}
}

func TestMiddleware_DisabledLimiterAlwaysPassesThrough(t *testing.T) {
	l := New(0, 10) // 0 disables rate limiting entirely
	called := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	mw := Middleware(next, l)

	for i := 0; i < 50; i++ {
		rr := httptest.NewRecorder()
		mw.ServeHTTP(rr, newRequest("1.2.3.4:1111"))
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200 (limiter disabled)", i, rr.Code)
		}
	}
	if called != 50 {
		t.Errorf("next was called %d times, want 50 (every request should pass through)", called)
	}
}

func TestMiddleware_DifferentIPsHaveIndependentLimits(t *testing.T) {
	l := New(1, 1)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mw := Middleware(next, l)

	rrA := httptest.NewRecorder()
	mw.ServeHTTP(rrA, newRequest("1.1.1.1:1"))
	if rrA.Code != http.StatusOK {
		t.Fatalf("IP A first request status = %d, want 200", rrA.Code)
	}

	rrB := httptest.NewRecorder()
	mw.ServeHTTP(rrB, newRequest("2.2.2.2:1"))
	if rrB.Code != http.StatusOK {
		t.Fatalf("IP B first request status = %d, want 200 (independent bucket from IP A)", rrB.Code)
	}
}
