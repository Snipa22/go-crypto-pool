// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"context"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// These tests exercise RandomXValidator against an httptest server that
// implements go-xmr-lib's real RXVerifier HTTP protocol (POST /seed to
// prime a seed, per hashValidation/randomx.go's NewSeed/Hash) -- they do
// NOT exercise real RandomX hashing (no such implementation exists in this
// process; see randomx.go's top-of-file honest-status doc comment). This
// is exactly the gap that same doc comment calls out: before this
// validator is trusted in production it needs an end-to-end pass against
// a real randomx-service daemon, which is not available in this sandbox.

func randomXShare(blob, seed []byte, resultHex string, blockDiff int64) *poolpb.Share {
	return &poolpb.Share{
		BlockDiff: blockDiff,
		RawProof: &poolpb.Share_RandomxProof{
			RandomxProof: &poolpb.RandomXProof{
				Blob:      blob,
				SeedHash:  seed,
				ResultHex: resultHex,
			},
		},
	}
}

func TestRandomXValidator_Validate_MockService(t *testing.T) {
	realHash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	mux := http.NewServeMux()
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		// NewSeed: expects 204 on success.
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/hash", func(w http.ResponseWriter, r *http.Request) {
		// Hash(): real go-xmr-lib v0.2.5+ issues POST /hash (fixed from an
		// earlier v0.2.4 bug where it hit /seed with a malformed request --
		// see the go-xmr-lib PR #8/#9 fix and randomx.go's own top-of-file
		// doc comment for the full history; go-crypto-pool's go.mod pins
		// the fixed v0.2.5).
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(hex.EncodeToString(realHash)))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewRandomXValidator(srv.URL)
	ctx := context.Background()

	t.Run("claimed hash matches real service response", func(t *testing.T) {
		valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), hex.EncodeToString(realHash), 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !valid {
			t.Errorf("expected valid=true when claimed hash matches service response")
		}
	})

	t.Run("claimed hash does not match real service response", func(t *testing.T) {
		valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "0000000000000000", 0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false for a claimed hash that doesn't match")
		}
	})

	t.Run("malformed claimed hex is rejected, not an infra error", func(t *testing.T) {
		valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "not-hex!!", 0))
		if err != nil {
			t.Fatalf("expected no error for malformed hex (should be a rejected share, not an infra failure), got: %v", err)
		}
		if valid {
			t.Errorf("expected valid=false for malformed claimed hex")
		}
	})

	t.Run("nil share", func(t *testing.T) {
		_, err := v.Validate(ctx, nil)
		if err == nil {
			t.Errorf("expected error for nil share")
		}
	})

	t.Run("wrong proof type", func(t *testing.T) {
		wrong := &poolpb.Share{RawProof: &poolpb.Share_C29Proof{C29Proof: &poolpb.C29Proof{}}}
		_, err := v.Validate(ctx, wrong)
		if err != ErrWrongProofType {
			t.Errorf("expected ErrWrongProofType, got %v", err)
		}
	})
}

func TestRandomXValidator_Validate_ServiceUnreachable(t *testing.T) {
	// A validator pointed at a genuinely unreachable service must return a
	// real (non-nil) error -- NOT silently accept or reject the share.
	// This is the "honest failure mode" the top-of-file doc comment on
	// randomx.go describes, and it's the single most important behavior
	// to regression-test here: a silent wrong answer in either direction
	// has real financial consequences in a payout system.
	v := NewRandomXValidator("http://127.0.0.1:1") // reserved, nothing listens here
	ctx := context.Background()

	valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "deadbeef", 0))
	if err == nil {
		t.Fatalf("expected a real error when the randomx-service is unreachable, got valid=%v, err=nil", valid)
	}
	if valid {
		t.Errorf("expected valid=false alongside the error (never silently accept on infra failure)")
	}
}

// failNThenSucceed builds an httptest handler for /hash that fails
// (closes the connection, giving the client a transport-level error) on
// the first failCount requests, then serves realHash successfully on
// every request after that. It also serves /seed unconditionally (some
// paths through RXVerifier may prime a seed).
func failNThenSucceedHandler(failCount int32, realHash []byte, calls *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/seed" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		n := atomic.AddInt32(calls, 1)
		if n <= failCount {
			// Hijack and close the raw connection to force a genuine
			// transport-level error on the client side (not just a
			// non-2xx status), simulating the daemon being briefly
			// unavailable/restarting.
			hj, ok := w.(http.Hijacker)
			if !ok {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(hex.EncodeToString(realHash)))
	}
}

func TestRandomXValidator_Validate_RetriesTransientFailureThenSucceeds(t *testing.T) {
	realHash := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}
	var calls int32

	mux := http.NewServeMux()
	// Fail the first rxHashMaxAttempts-1 requests, succeed on the last
	// attempt within the retry budget -- proves the retry actually
	// happens and recovers.
	mux.HandleFunc("/hash", failNThenSucceedHandler(int32(rxHashMaxAttempts-1), realHash, &calls))
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewRandomXValidator(srv.URL)
	ctx := context.Background()

	valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), hex.EncodeToString(realHash), 0))
	if err != nil {
		t.Fatalf("expected retry to recover from transient failures with no error, got: %v", err)
	}
	if !valid {
		t.Errorf("expected valid=true once the retried call succeeds")
	}
	if got := atomic.LoadInt32(&calls); got != int32(rxHashMaxAttempts) {
		t.Errorf("expected exactly %d /hash requests (failures + the succeeding retry), got %d", rxHashMaxAttempts, got)
	}
}

func TestRandomXValidator_ValidateBlobSeedResult_RetriesTransientFailureThenSucceeds(t *testing.T) {
	realHash := []byte{0xca, 0xfe, 0xba, 0xbe}
	var calls int32

	mux := http.NewServeMux()
	mux.HandleFunc("/hash", failNThenSucceedHandler(int32(rxHashMaxAttempts-1), realHash, &calls))
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewRandomXValidator(srv.URL)
	ctx := context.Background()

	valid, err := v.ValidateBlobSeedResult(ctx, []byte("blob"), []byte("seed"), hex.EncodeToString(realHash))
	if err != nil {
		t.Fatalf("expected retry to recover from transient failures with no error, got: %v", err)
	}
	if !valid {
		t.Errorf("expected valid=true once the retried call succeeds")
	}
	if got := atomic.LoadInt32(&calls); got != int32(rxHashMaxAttempts) {
		t.Errorf("expected exactly %d /hash requests, got %d", rxHashMaxAttempts, got)
	}
}

func TestRandomXValidator_Validate_RetryBudgetIsBounded(t *testing.T) {
	// Every attempt fails -- proves the retry budget is bounded (not
	// infinite) and that the final, real error is still surfaced once
	// the budget is exhausted.
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/hash", failNThenSucceedHandler(1<<30, nil, &calls))
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewRandomXValidator(srv.URL)
	ctx := context.Background()

	valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "deadbeef", 0))
	if err == nil {
		t.Fatalf("expected a real error once the retry budget is exhausted, got valid=%v, err=nil", valid)
	}
	if valid {
		t.Errorf("expected valid=false alongside the error")
	}
	if got := atomic.LoadInt32(&calls); got != int32(rxHashMaxAttempts) {
		t.Errorf("expected exactly %d /hash requests (bounded retry budget), got %d", rxHashMaxAttempts, got)
	}
}

func TestRandomXValidator_HashWithRetry_StopsOnCancelledContext(t *testing.T) {
	// A context that's already done must stop retrying (and, in this
	// case, must never even make it to a first HTTP call once it
	// re-checks ctx between attempts) rather than burning the retry
	// budget against a caller that has already given up.
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/hash", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/seed", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v := NewRandomXValidator(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done before Validate is even called

	valid, err := v.Validate(ctx, randomXShare([]byte("blob"), []byte("seed"), "deadbeef", 0))
	if err == nil {
		t.Fatalf("expected a context error, got valid=%v, err=nil", valid)
	}
	if !errorsIsContextErr(err) {
		t.Errorf("expected the returned error to be (or wrap) a context error, got: %v", err)
	}

	// Give any stray goroutine a moment, then confirm no HTTP call was
	// made at all -- the ctx.Err() check before the loop in Validate
	// already short-circuits before hashWithRetry is even entered.
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("expected zero /hash requests once ctx is already done before the call, got %d", got)
	}
}

func errorsIsContextErr(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded ||
		(err != nil && (containsErr(err, context.Canceled) || containsErr(err, context.DeadlineExceeded)))
}

func containsErr(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
