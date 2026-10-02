// Copyright and license: see repository LICENSE (MIT).
package leaflib

import "strings"

// IsHTTPConnectProbe reports whether line looks like a literal HTTP
// CONNECT request line (e.g. "CONNECT example.com:443 HTTP/1.1"),
// rather than a stratum JSON-RPC message.
//
// THE PROBLEM THIS FIXES: leaf-proxy and leaf-direct can both be
// configured to listen on ports 80/443 (common for mining traffic
// disguised as HTTPS to get through restrictive firewalls). Port
// scanners and open-proxy probes routinely send a literal HTTP
// CONNECT request line to any open port on 80/443 hoping to find an
// open HTTP proxy to tunnel through -- this is a completely different
// protocol hitting the stratum listener by accident/probing, not a
// malformed stratum message. Alex's own ask: "when someone connects,
// they /may/ try to send a HTTP connect message, because we run on
// 80/443, if they do so, we need to close their connection as soon as
// we receive it and drop them from tracking."
//
// Detection is deliberately a FIRST-TOKEN check, not a substring
// search: line is trimmed of leading whitespace, then its first
// whitespace-delimited token is compared case-insensitively against
// "CONNECT" (real probes aren't guaranteed to send exact-case
// CONNECT). A line that merely contains "connect" somewhere else
// (e.g. inside a stratum JSON payload) must NOT match.
//
// Deliberately narrow in scope, matching Alex's own wording ("HTTP
// connect message"): this does NOT also try to catch GET/POST/other
// stray HTTP verbs that might hit these ports -- that could be a
// reasonable future generalization if other stray HTTP methods turn
// out to be a real problem too, but it is not implemented here.
func IsHTTPConnectProbe(line string) bool {
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
	return strings.EqualFold(firstToken, "CONNECT")
}
