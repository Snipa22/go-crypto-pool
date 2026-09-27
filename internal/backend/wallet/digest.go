package wallet

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// digestTransport is a real, minimal RFC 2617 HTTP Digest
// authentication http.RoundTripper. monero-wallet-rpc, when started
// with --rpc-login user:pass (the standard, documented way to secure
// it), answers every unauthenticated request with a real 401 plus a
// WWW-Authenticate: Digest challenge — it does NOT support HTTP Basic
// auth. Go's standard net/http has no built-in digest-auth support,
// so this is a real (if intentionally minimal — MD5/auth qop only,
// no auth-int, no SHA-256 variant) implementation rather than a
// vendored dependency, since pulling in a whole digest-auth library
// for one RPC client is disproportionate.
//
// Only used when MoneroWalletRPC is constructed with non-empty
// User/Password (see NewMoneroWalletRPC) — a deployment running
// monero-wallet-rpc with no --rpc-login at all (unauthenticated,
// bound to localhost only, its own documented "trusted network"
// story) never touches this type.
type digestTransport struct {
	username string
	password string
	base     http.RoundTripper

	mu    sync.Mutex
	nc    uint32 // nonce count, incremented per authenticated request
	cache *digestChallenge
}

// digestChallenge is a parsed WWW-Authenticate: Digest header.
type digestChallenge struct {
	realm  string
	nonce  string
	opaque string
	qop    string
	algo   string
}

func parseDigestChallenge(header string) (*digestChallenge, error) {
	const prefix = "Digest "
	if !strings.HasPrefix(header, prefix) {
		return nil, fmt.Errorf("wallet: digest auth: WWW-Authenticate header is not a Digest challenge: %q", header)
	}
	fields := splitDigestFields(strings.TrimPrefix(header, prefix))
	c := &digestChallenge{
		realm:  fields["realm"],
		nonce:  fields["nonce"],
		opaque: fields["opaque"],
		qop:    fields["qop"],
		algo:   fields["algorithm"],
	}
	if c.realm == "" || c.nonce == "" {
		return nil, fmt.Errorf("wallet: digest auth: challenge missing realm/nonce: %q", header)
	}
	return c, nil
}

// splitDigestFields parses a comma-separated "key=value" / "key=\"value\""
// list, the exact real shape of a Digest challenge/credentials header.
func splitDigestFields(s string) map[string]string {
	out := map[string]string{}
	for _, part := range splitDigestTopLevel(s) {
		part = strings.TrimSpace(part)
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		val := strings.TrimSpace(part[eq+1:])
		val = strings.Trim(val, `"`)
		out[key] = val
	}
	return out
}

// splitDigestTopLevel splits on commas that are not inside a quoted
// string (qop can be a quoted list like qop="auth,auth-int", which a
// naive strings.Split(",") would incorrectly break apart).
func splitDigestTopLevel(s string) []string {
	var parts []string
	inQuotes := false
	start := 0
	for i, r := range s {
		switch r {
		case '"':
			inQuotes = !inQuotes
		case ',':
			if !inQuotes {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// authorizationHeader builds the real Authorization: Digest header
// value for one request, given an already-obtained challenge.
// RFC 2617's exact response formula for qop=auth:
//
//	HA1 = MD5(username:realm:password)
//	HA2 = MD5(method:digestURI)
//	response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
func (t *digestTransport) authorizationHeader(c *digestChallenge, method, uri string) (string, error) {
	cnonce, err := randomHex(8)
	if err != nil {
		return "", fmt.Errorf("wallet: digest auth: generating cnonce: %w", err)
	}
	t.mu.Lock()
	t.nc++
	nc := t.nc
	t.mu.Unlock()
	ncStr := fmt.Sprintf("%08x", nc)

	ha1 := md5Hex(t.username + ":" + c.realm + ":" + t.password)
	ha2 := md5Hex(method + ":" + uri)

	qop := c.qop
	if qop == "" {
		// Some monero-wallet-rpc builds omit qop entirely (the
		// older, qop-less RFC 2069 form) — handled as a real,
		// distinct code path rather than assuming qop=auth always.
		response := md5Hex(ha1 + ":" + c.nonce + ":" + ha2)
		return fmt.Sprintf(
			`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
			t.username, c.realm, c.nonce, uri, response,
		), nil
	}

	response := md5Hex(ha1 + ":" + c.nonce + ":" + ncStr + ":" + cnonce + ":" + qop + ":" + ha2)
	header := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", cnonce="%s", nc=%s, qop=%s, response="%s"`,
		t.username, c.realm, c.nonce, uri, cnonce, ncStr, qop, response,
	)
	if c.opaque != "" {
		header += fmt.Sprintf(`, opaque="%s"`, c.opaque)
	}
	return header, nil
}

// RoundTrip implements http.RoundTripper. It buffers req.Body (the
// JSON-RPC request bodies this client sends are always small) so the
// same request can be replayed with real Authorization credentials
// once the server's real 401 challenge has been parsed.
func (t *digestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}

	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("wallet: digest auth: buffering request body: %w", err)
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Attempt with a cached challenge first, if one exists (avoids a
	// real extra round trip on every single request once the wallet
	// has already been authenticated once this session — matches
	// what a real browser/digest-aware HTTP client does).
	t.mu.Lock()
	cached := t.cache
	t.mu.Unlock()
	if cached != nil {
		hdr, err := t.authorizationHeader(cached, req.Method, req.URL.RequestURI())
		if err == nil {
			req.Header.Set("Authorization", hdr)
		}
	}

	resp, err := base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// Real 401: parse the real challenge and retry exactly once.
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	resp.Body.Close()
	challenge, perr := parseDigestChallenge(wwwAuth)
	if perr != nil {
		return nil, fmt.Errorf("wallet: digest auth: %w (and no cached challenge succeeded)", perr)
	}
	t.mu.Lock()
	t.cache = challenge
	t.mu.Unlock()

	hdr, err := t.authorizationHeader(challenge, req.Method, req.URL.RequestURI())
	if err != nil {
		return nil, err
	}

	retryReq := req.Clone(req.Context())
	if bodyBytes != nil {
		retryReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		retryReq.ContentLength = int64(len(bodyBytes))
	}
	retryReq.Header.Set("Authorization", hdr)

	return base.RoundTrip(retryReq)
}
