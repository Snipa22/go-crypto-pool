// Copyright and license: see repository LICENSE (MIT).
package validator

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestRandomXValidator_Validate_RealDaemon closes the exact gap this
// package's own honest-status doc comment (randomx.go) calls out: prior
// tests only exercised RandomXValidator against an httptest MOCK of
// go-xmr-lib's RXVerifier protocol, never against a genuine, real
// randomx-service daemon computing real RandomX hashes. This test is
// opportunistically gated on a real daemon being reachable at
// 127.0.0.1:39093 (skip, not fail, when unreachable -- same pattern as
// this repo's GCPOOL_TEST_DSN-gated Postgres integration tests).
//
// Uses the exact real reference vector from go-randomx's own test suite
// (git.gammaspectra.live/P2Pool/go-randomx@v1.0.0's randomx_test.go) and
// from randomx-service's own doc/API.md worked example -- both
// independently confirmed (2026-08-21) against a real, live
// tevador/randomx-service v1.0.2 instance to produce the exact same
// hash: seed "test key 000", input "This is a test" ->
// 639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f.
func TestRandomXValidator_Validate_RealDaemon(t *testing.T) {
	const serviceURL = "http://127.0.0.1:39093"

	conn, err := net.DialTimeout("tcp", "127.0.0.1:39093", 500*time.Millisecond)
	if err != nil {
		t.Skipf("no randomx-service reachable at %s, skipping real-daemon test: %v", serviceURL, err)
	}
	_ = conn.Close()

	seed := []byte("test key 000")
	input := []byte("This is a test")
	const wantHex = "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"

	v := NewRandomXValidator(serviceURL)

	// Seed the real daemon directly via a raw HTTP call first (mirrors
	// what a real leaf's job-management layer would do once per new
	// block template's seed hash) -- RandomXValidator.Validate itself
	// only calls Hash, it doesn't reseed, so the daemon needs the
	// right seed active before Validate runs.
	req, err := http.NewRequest(http.MethodPost, serviceURL+"/seed", bytes.NewReader(seed))
	if err != nil {
		t.Fatalf("build seed request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x.randomx+bin")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("real /seed call to randomx-service failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("real /seed call: status = %d, want 204", resp.StatusCode)
	}

	share := randomXShare(input, seed, wantHex, 1)
	valid, err := v.Validate(context.Background(), share)
	if err != nil {
		t.Fatalf("Validate against real randomx-service: %v", err)
	}
	if !valid {
		t.Fatal("expected the real, correct RandomX hash to validate successfully against the live daemon")
	}

	// Sanity-check the negative case too: a wrong claimed hash must be
	// rejected, not just any hash accepted blindly.
	wrongShare := randomXShare(input, seed, hex.EncodeToString(make([]byte, 32)), 1)
	valid, err = v.Validate(context.Background(), wrongShare)
	if err != nil {
		t.Fatalf("Validate (wrong hash) against real randomx-service: %v", err)
	}
	if valid {
		t.Fatal("expected a wrong claimed hash to be rejected by the real daemon, not accepted")
	}
}
