// Copyright and license: see repository LICENSE (MIT).
package leaflib

import "strings"

// IsHTTPRequestProbe reports whether line looks like a literal HTTP
// request line (e.g. "CONNECT example.com:443 HTTP/1.1" or
// "GET / HTTP/1.1"), rather than a stratum JSON-RPC message.
//
// THE PROBLEM THIS FIXES: leaf-proxy and leaf-direct can both be
// configured to listen on ports 80/443 (common for mining traffic
// disguised as HTTPS to get through restrictive firewalls). Port
// scanners, open-proxy probes, and plain misdirected HTTP clients
// routinely send a literal HTTP request line to any open port on
// 80/443 -- this is a completely different protocol hitting the
// stratum listener by accident/probing, not a malformed stratum
// message.
//
// EVOLUTION OF THIS CHECK: originally added CONNECT-only, per Alex's
// own ask: "when someone connects, they /may/ try to send a HTTP
// connect message, because we run on 80/443, if they do so, we need
// to close their connection as soon as we receive it and drop them
// from tracking." Generalized to the full standard HTTP method set
// after real production log evidence (session 8bcf5048aa6ed,
// leaf-proxy) showed a real client sending a plain HTTP GET request
// instead, which the CONNECT-only check did not catch -- the
// connection stayed open and the EXISTING "sent unparseable message,
// dropping" path logged a SEPARATE line for every single header:
//
//	leaf-proxy: ... invalid character 'G' looking for beginning of value   <- "GET / HTTP/1.1"
//	leaf-proxy: ... invalid character 'H' looking for beginning of value   <- "Host: ..."
//	leaf-proxy: ... invalid character 'U' looking for beginning of value   <- "User-Agent: ..."
//	leaf-proxy: ... invalid character 'A' looking for beginning of value   <- "Accept: ..."
//	leaf-proxy: ... invalid character 'C' looking for beginning of value   <- "Connection: ..."
//
// Alex's own framing: "This is what's happening right now, so we
// might need to handle a bit more cleanup in general."
//
// Detection is deliberately a FIRST-TOKEN check, not a substring
// search: line is trimmed of leading whitespace, then its first
// whitespace-delimited token is compared case-insensitively against
// the standard HTTP method tokens (GET, HEAD, POST, PUT, DELETE,
// OPTIONS, PATCH, TRACE, CONNECT) -- real probes/misdirected clients
// aren't guaranteed to send exact-case method tokens. A line that
// merely contains one of these words somewhere else (e.g. inside a
// stratum JSON payload) must NOT match.
//
// A real HTTP request line also has a recognizable shape beyond just
// the method (METHOD SP request-target SP HTTP-version, e.g.
// "GET / HTTP/1.1"), but for a stratum server that will never
// legitimately receive any of these tokens as the first word of a
// JSON-RPC line, a first-token-is-one-of-these-exact-methods check is
// already unambiguous and sufficient -- this deliberately does not
// implement a full HTTP request-line grammar parser.
func IsHTTPRequestProbe(line string) bool {
	trimmed := strings.TrimLeft(line, " \t\r\n")
	if trimmed == "" {
		return false
	}
	end := strings.IndexAny(trimmed, " \t")
	var firstToken string
	if end == -1 {
		firstToken = trimmed
	} else {
		firstToken = trimmed[:end]
	}
	switch strings.ToUpper(firstToken) {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT":
		return true
	default:
		return false
	}
}
