// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWrapMetricsAuth_EmptyPasswordIsANoOp confirms the documented
// "off by default" behavior: with password == "", WrapMetricsAuth
// returns next COMPLETELY unwrapped -- a request with no credentials
// at all still reaches next and gets its normal response.
func TestWrapMetricsAuth_EmptyPasswordIsANoOp(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	wrapped := WrapMetricsAuth(inner, "proxy", "")

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (empty password must be a complete no-op)", resp.StatusCode)
	}
}

// TestWrapMetricsAuth_MissingCredentialsRejected confirms a request
// with NO Authorization header at all gets 401 + WWW-Authenticate
// once a non-empty password is configured.
func TestWrapMetricsAuth_MissingCredentialsRejected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must never be invoked for an unauthenticated request")
	})
	wrapped := WrapMetricsAuth(inner, "proxy", "secret")

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Error("expected a WWW-Authenticate header on a 401 response, got none")
	}
}

// TestWrapMetricsAuth_WrongCredentialsRejected confirms a request
// with the WRONG username or password (but a well-formed Basic Auth
// header) still gets 401, never reaching next.
func TestWrapMetricsAuth_WrongCredentialsRejected(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler must never be invoked for a mismatched credential")
	})
	wrapped := WrapMetricsAuth(inner, "proxy", "secret")

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	for _, tc := range []struct {
		name, user, pass string
	}{
		{"wrong username", "not-proxy", "secret"},
		{"wrong password", "proxy", "not-secret"},
		{"both wrong", "nope", "nope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.SetBasicAuth(tc.user, tc.pass)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

// TestWrapMetricsAuth_CorrectCredentialsAccepted confirms the exact
// correct username/password combination reaches next and gets its
// normal response.
func TestWrapMetricsAuth_CorrectCredentialsAccepted(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	wrapped := WrapMetricsAuth(inner, "proxy", "secret")

	srv := httptest.NewServer(wrapped)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.SetBasicAuth("proxy", "secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

// TestConstantTimeStringsEqual is a small direct unit test of the
// comparison helper itself.
func TestConstantTimeStringsEqual(t *testing.T) {
	if !constantTimeStringsEqual("abc", "abc") {
		t.Error("expected equal strings to compare equal")
	}
	if constantTimeStringsEqual("abc", "abd") {
		t.Error("expected different strings (same length) to compare unequal")
	}
	if constantTimeStringsEqual("abc", "abcd") {
		t.Error("expected different-length strings to compare unequal")
	}
	if constantTimeStringsEqual("", "abc") {
		t.Error("expected empty vs non-empty to compare unequal")
	}
}
