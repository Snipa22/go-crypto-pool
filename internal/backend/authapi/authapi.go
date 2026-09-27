// Package authapi implements the SXMR-legacy backend's
// authentication/account-settings HTTP endpoints, ported from the
// legacy Node.js nodejs-pool-upgrade `lib/api.js` (see brief-auth.md
// for the exact ground-truth field names/behavior this mirrors).
//
// This is a genuinely separate package/Handler from every other
// internal/backend/* HTTP surface (internal/backend/api's leaf ->
// backend ingestion trust boundary, internal/backend/statsapi/
// networkapi's read-only aggregate queries, internal/backend/
// addressmap's XMR->Tari mapping) for the same reason those are all
// kept apart from each other: a bug in credential/JWT handling must
// never be able to touch share/block ingestion, and this surface can
// be deployed/rate-limited independently of any of them.
//
// Endpoints:
//
//   - POST /authenticate
//     Body: {"username": "...", "password": "..."}. Verifies the
//     password against `users.pass` (an HMAC-SHA256 hex digest -- see
//     hashPassword) and, on success, returns a fresh 24h JWT with
//     claims {"id": <user id>, "admin": <bool>}.
//
//   - GET /authed/tokenRefresh (JWT-gated)
//     Re-issues a fresh 24h token with the same {id, admin} claims.
//
//   - GET /authed/ (JWT-gated)
//     Returns the authenticated user's {payout_threshold,
//     email_enabled}.
//
//   - POST /authed/changePassword (JWT-gated)
//     Body: {"password": "..."}. Re-hashes and updates users.pass.
//
//   - POST /authed/toggleEmail (JWT-gated)
//     Flips users.enable_email for the authenticated user.
//
//   - POST /authed/changePayoutThreshold (JWT-gated)
//     Body: {"threshold": <number>}. Updates users.payout_threshold.
//
//   - POST /user/forcePayment (NOT JWT-gated -- public, keyed by
//     username/address)
//     Body: {"username": "<address>[.<payment_id>]", "algo":
//     "...", "network": "..."}. Flags the matching `balance` row's
//     new force_payout column (see db.Repository.SetForcePayout's
//     doc comment for why this replaces legacy's Redis
//     `earlyPayout` queue push -- there is no Redis in this stack).
//
//   - POST /user/updateThreshold (NOT JWT-gated)
//     Body: {"username": "...", "threshold": <number>}. Updates the
//     EXISTING `users` row's payout_threshold for that username --
//     UPDATE-only, never creates a row (an unauthenticated caller who
//     merely knows/guesses a username must not be able to conjure a
//     new `users` row into existence).
//
//   - GET /user/{address} (NOT JWT-gated)
//     Returns {payout_threshold, email_enabled} for that username,
//     or zero-value defaults (not an error) if no such user exists.
//
//   - POST /user/toggleEmail (NOT JWT-gated)
//     Body: {"address": "..."}. Flips users.enable_email if a row
//     exists; a no-op (still success) if it doesn't.
//
// # Deliberate deviations from legacy (see brief-auth.md)
//
//  1. Legacy fell back to comparing `email == password` when
//     `users.pass IS NULL` (a credential-recovery quirk). This is
//     NOT replicated: a NULL pass here always fails authentication.
//     This is an intentional, sane simplification, not an oversight.
//
//  2. Legacy hashed passwords with HMAC-SHA256 keyed by a distinct
//     "server secret key" whose provenance (a separate config value)
//     is not specified anywhere in the ground-truth brief this
//     package was built from, and no such env var was requested for
//     it. This package reuses Config.JWTSecret (the same secret used
//     to sign/verify JWTs, see hashPassword's doc comment) as that
//     HMAC key too, rather than inventing a second, undocumented
//     secret env var. This is stated here explicitly as a deviation
//     worth revisiting if a deployment ever wants the two secrets to
//     rotate independently.
//
//  3. This package uses github.com/golang-jwt/jwt/v5 -- verified via
//     `go mod graph` to already be the actively-maintained fork
//     resolved into this module's build list (pulled in transitively
//     by github.com/prometheus/client_golang and
//     github.com/prometheus/common), MIT-licensed, with active recent
//     upstream commits. It is the current de facto Go ecosystem
//     standard for JWT handling (the original dgrijalva/jwt-go is
//     archived/unmaintained; golang-jwt is its official successor
//     org).
package authapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// maxBodyBytes bounds how much of any request body this package will
// read -- every real payload here (credentials, a threshold number, a
// short address string) is tiny; there is no legitimate reason for it
// to approach this size.
const maxBodyBytes = 1 << 16 // 64 KiB

// maxMinerStringLen caps every miner-supplied, address/username-shaped
// string field these handlers accept before it reaches a Repository
// call that persists it to an unbounded `TEXT` column (users.username
// via UpdateUserThreshold, in particular -- see db/users.go). Mirrors
// internal/backend/api's identically-named/valued constant and
// PROD_HARDENING_REVIEW.md finding #17's own reasoning: 256 bytes is
// generous for anything actually shaped like a real address or
// "<address>.<payment_id>" username, far short of maxBodyBytes.
const maxMinerStringLen = 256

// tokenTTL is how long a freshly signed or refreshed JWT is valid for
// -- matches legacy's own 24h expiry exactly (see brief-auth.md).
const tokenTTL = 24 * time.Hour

// User mirrors db.User field-for-field (see that package's doc
// comment) -- kept as this package's own type for the same
// dependency-direction reason every other internal/backend/*
// package's Record type mirrors its own db type instead of importing
// internal/backend/db directly.
type User struct {
	ID              int64
	Username        string
	Email           string
	Pass            *string
	Admin           bool
	EnableEmail     bool
	PayoutThreshold int64
}

// ErrUserNotFound is the sentinel a Repository implementation must
// return from GetUserByUsername/GetUserByID when no matching row
// exists. Handler translates this into either a 401 (POST
// /authenticate) or a "zero-value defaults" 200 (GET /user/{address}),
// depending on the endpoint -- see each handler's own comment.
var ErrUserNotFound = errors.New("authapi: no such user")

// ErrBalanceNotFound is the sentinel a Repository implementation must
// return from SetForcePayout when no payable balance row matches.
// Handler translates this into POST /user/forcePayment's legacy 400
// response.
var ErrBalanceNotFound = errors.New("authapi: no matching balance row")

// Repository is the narrow persistence surface this package's
// handlers depend on. *db.Repository satisfies this via the adapter
// wired up in cmd/backend; tests inject a fake.
type Repository interface {
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserByID(ctx context.Context, id int64) (User, error)
	UpdateUserPassword(ctx context.Context, id int64, passHash string) error
	ToggleUserEnableEmail(ctx context.Context, id int64) error
	ToggleUserEnableEmailByUsername(ctx context.Context, username string) error
	UpdateUserPayoutThreshold(ctx context.Context, id int64, threshold int64) error

	// UpdateUserThreshold implements the public POST
	// /user/updateThreshold path: it must be UPDATE-only and must
	// NEVER create a new `users` row. Implementations must return
	// this package's own ErrUserNotFound sentinel (not db's) when
	// username matches no row, so Handler can translate that into
	// the endpoint's legacy-parity 400 response.
	UpdateUserThreshold(ctx context.Context, username string, threshold int64) error
	SetForcePayout(ctx context.Context, algo, network, paymentAddress string, paymentID *string) error
}

// Config configures a Handler.
type Config struct {
	// JWTSecret is the HMAC-SHA256 key used both to sign/verify every
	// JWT this package issues AND (see this package's doc comment,
	// deviation #2) to hash passwords for the `users.pass` column.
	// Required -- NewHandler returns an error if this is empty, so
	// that a deployment which forgets to set GCPOOL_JWT_SECRET fails
	// fast at startup rather than silently issuing/accepting
	// unverifiable tokens.
	JWTSecret string

	// Network, if set to something other than NETWORK_UNSPECIFIED,
	// is this backend's own configured network -- used as
	// POST /user/forcePayment's default `network` when the request
	// body omits it (mirrors statsapi.Config.Network's role, per
	// brief-auth.md's explicit instruction to do so).
	Network poolpb.Network

	// Metrics, if non-nil, is the metrics.Metrics instance this
	// Handler's handlers increment (auth_attempts_total,
	// force_payout_writes_total). If nil, metrics are simply not
	// recorded. See PROD_HARDENING_REVIEW.md finding #19: per the
	// audit, POST /authenticate and POST /user/forcePayment were
	// previously entirely metric-invisible -- /authenticate
	// attempt/failure counts are the standard credential-stuffing/
	// brute-force signal, and every force-payout write moves real
	// money ahead of a miner's normal payout schedule, so it is
	// worth its own always-on counter regardless of outcome.
	Metrics *metrics.Metrics
}

// Handler implements this package's HTTP endpoints.
type Handler struct {
	repo Repository
	cfg  Config
}

// NewHandler constructs a Handler backed by repo. Returns an error if
// cfg.JWTSecret is empty -- see Config.JWTSecret's doc comment.
func NewHandler(repo Repository, cfg Config) (*Handler, error) {
	if strings.TrimSpace(cfg.JWTSecret) == "" {
		return nil, errors.New("authapi: Config.JWTSecret is required")
	}
	return &Handler{repo: repo, cfg: cfg}, nil
}

// Mux builds a fresh *http.ServeMux with this Handler's routes
// registered. Most callers should use RegisterRoutes against a
// shared mux instead (see cmd/backend) -- this exists mainly for this
// package's own tests and any caller that genuinely wants this
// Handler stand-alone.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return mux
}

// RegisterRoutes registers this Handler's routes onto mux. Safe to
// call on a mux that already has other, disjoint routes registered
// -- this package never registers anything outside /authenticate,
// /authed/, and /user/.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /authenticate", h.handleAuthenticate)

	mux.HandleFunc("GET /authed/tokenRefresh", h.requireAuth(h.handleTokenRefresh))
	mux.HandleFunc("GET /authed/", h.requireAuth(h.handleAuthedRoot))
	mux.HandleFunc("POST /authed/changePassword", h.requireAuth(h.handleChangePassword))
	mux.HandleFunc("POST /authed/toggleEmail", h.requireAuth(h.handleToggleEmail))
	mux.HandleFunc("POST /authed/changePayoutThreshold", h.requireAuth(h.handleChangePayoutThreshold))

	mux.HandleFunc("POST /user/forcePayment", h.handleForcePayment)
	mux.HandleFunc("POST /user/updateThreshold", h.handleUpdateThreshold)
	mux.HandleFunc("GET /user/{address}", h.handleGetUser)
	mux.HandleFunc("POST /user/toggleEmail", h.handleToggleEmailPublic)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// observeAuthAttempt increments Config.Metrics' auth_attempts_total
// for one POST /authenticate attempt, a no-op if no Metrics is
// configured. result is one of metrics.AuthResultSuccess/Failure. See
// PROD_HARDENING_REVIEW.md finding #19.
func (h *Handler) observeAuthAttempt(result string) {
	if h.cfg.Metrics == nil {
		return
	}
	h.cfg.Metrics.AuthAttemptsTotal.WithLabelValues(result).Inc()
}

// observeForcePayoutWrite increments Config.Metrics'
// force_payout_writes_total for one POST /user/forcePayment attempt,
// a no-op if no Metrics is configured. result is one of
// metrics.ForcePayoutResultSuccess/Failure. Per the audit
// (PROD_HARDENING_REVIEW.md finding #19), every force-payout write
// moves real money ahead of a miner's normal payout schedule and is
// worth its own always-on counter regardless of outcome.
func (h *Handler) observeForcePayoutWrite(algo, network, result string) {
	if h.cfg.Metrics == nil {
		return
	}
	h.cfg.Metrics.ForcePayoutWritesTotal.WithLabelValues(algo, network, result).Inc()
}

// hashPassword computes the hex-encoded HMAC-SHA256 digest of
// password keyed by h.cfg.JWTSecret -- see this package's doc
// comment (deviation #2) for why this reuses the JWT secret rather
// than a second, separately-configured hashing key.
func (h *Handler) hashPassword(password string) string {
	mac := hmac.New(sha256.New, []byte(h.cfg.JWTSecret))
	mac.Write([]byte(password))
	return hex.EncodeToString(mac.Sum(nil))
}

// claims is this package's JWT claim set: {"id": <user id>, "admin":
// <bool>} plus the standard exp/iat registered claims -- matches
// legacy's exact claim shape (see brief-auth.md).
type claims struct {
	ID    int64 `json:"id"`
	Admin bool  `json:"admin"`
	jwt.RegisteredClaims
}

// signToken issues a fresh JWT for (id, admin), valid for tokenTTL
// (24h, matching legacy).
func (h *Handler) signToken(id int64, admin bool) (string, error) {
	now := time.Now()
	c := claims{
		ID:    id,
		Admin: admin,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	signed, err := tok.SignedString([]byte(h.cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("authapi: signing token: %w", err)
	}
	return signed, nil
}

// parseToken verifies raw's signature/expiry against h.cfg.JWTSecret
// and returns its claims, or an error if raw is malformed, unsigned
// with an unexpected algorithm, expired, or otherwise invalid.
func (h *Handler) parseToken(raw string) (*claims, error) {
	c := &claims{}
	_, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(h.cfg.JWTSecret), nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

// claimsContextKey is the unexported context.Context key requireAuth
// stashes a validated *claims under.
type claimsContextKey struct{}

func claimsFromContext(ctx context.Context) (*claims, bool) {
	c, ok := ctx.Value(claimsContextKey{}).(*claims)
	return c, ok
}

// tokenBody is the shape extractToken tries to decode a request body
// as, to find a body-supplied `token` field -- the highest-priority
// token source per this package's doc comment/brief-auth.md.
type tokenBody struct {
	Token string `json:"token"`
}

// extractToken implements this package's JWT-middleware token
// extraction priority order (see brief-auth.md): request body field
// `token`, then query param `token`, then header `X-Access-Token`.
// It reads and returns the full (bounded) request body alongside the
// token, so requireAuth can restore r.Body for the wrapped handler to
// decode its own JSON fields from the same bytes (e.g.
// handleChangePassword's {"password": "..."} body, which coexists
// with -- or is entirely separate from -- any body-supplied token).
// tooLarge reports whether the body exceeded maxBodyBytes.
func extractToken(r *http.Request) (token string, bodyBytes []byte, tooLarge bool) {
	if r.Body != nil {
		limited := io.LimitReader(r.Body, maxBodyBytes+1)
		b, _ := io.ReadAll(limited)
		if len(b) > maxBodyBytes {
			return "", nil, true
		}
		bodyBytes = b
		if len(b) > 0 {
			var tb tokenBody
			// A non-JSON or unrelated-shape body is not an error at
			// this layer -- it simply means no body-supplied token,
			// falling through to the query/header sources below.
			_ = json.Unmarshal(b, &tb)
			token = tb.Token
		}
	}
	if token == "" {
		token = r.URL.Query().Get("token")
	}
	if token == "" {
		token = r.Header.Get("X-Access-Token")
	}
	return token, bodyBytes, false
}

// requireAuth wraps next with this package's JWT-gating contract (see
// brief-auth.md): a missing token is a 403 with
// {"success": false, "msg": "No token provided."}; an invalid/expired
// token is (deliberately, matching legacy) a 200 with
// {"success": false, "msg": "Failed to authenticate token."} rather
// than a 401/403 -- existing SXMR UI clients expect exactly this
// quirk. A validated token's claims are attached to the request
// context for next to read via claimsFromContext.
func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, bodyBytes, tooLarge := extractToken(r)
		if tooLarge {
			writeJSONErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		if token == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{"success": false, "msg": "No token provided."})
			return
		}
		c, err := h.parseToken(token)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"success": false, "msg": "Failed to authenticate token."})
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		ctx := context.WithValue(r.Context(), claimsContextKey{}, c)
		next(w, r.WithContext(ctx))
	}
}

// networkDBString mirrors internal/backend/api/statsapi's own
// private helper of the same name/purpose -- poolpb.Network to this
// schema's exact "MAINNET"/"TESTNET" column string.
func networkDBString(n poolpb.Network) string {
	switch n {
	case poolpb.Network_NETWORK_MAINNET:
		return "MAINNET"
	case poolpb.Network_NETWORK_TESTNET:
		return "TESTNET"
	default:
		return ""
	}
}

// splitUsername implements legacy's exact username-encoding
// convention for POST /user/forcePayment: "<address>[.<payment_id>]".
// A username with no '.' has no payment_id (nil, not an empty
// string, mirroring db.Repository's own nil-means-unset convention).
func splitUsername(username string) (address string, paymentID *string) {
	if idx := strings.IndexByte(username, '.'); idx >= 0 {
		addr := username[:idx]
		pid := username[idx+1:]
		return addr, &pid
	}
	return username, nil
}

// authenticateRequest is the JSON body POST /authenticate expects.
type authenticateRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	var req authenticateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "malformed JSON body"})
		return
	}
	if req.Username == "" || req.Password == "" {
		h.observeAuthAttempt(metrics.AuthResultFailure)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "msg": "Invalid username/password"})
		return
	}
	if len(req.Username) > maxMinerStringLen {
		h.observeAuthAttempt(metrics.AuthResultFailure)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "msg": "Invalid username/password"})
		return
	}

	user, err := h.repo.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		// Both "no such user" and any underlying repository error
		// collapse to the same generic invalid-credentials response
		// -- mirroring legacy's own behavior of never distinguishing
		// "wrong username" from "wrong password" to a caller.
		h.observeAuthAttempt(metrics.AuthResultFailure)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "msg": "Invalid username/password"})
		return
	}
	if user.Pass == nil {
		// Deliberate deviation from legacy: NOT falling back to an
		// email == password comparison here -- see this package's
		// doc comment, deviation #1.
		h.observeAuthAttempt(metrics.AuthResultFailure)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "msg": "Invalid username/password"})
		return
	}

	want := h.hashPassword(req.Password)
	if !hmac.Equal([]byte(*user.Pass), []byte(want)) {
		h.observeAuthAttempt(metrics.AuthResultFailure)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"success": false, "msg": "Invalid username/password"})
		return
	}
	h.observeAuthAttempt(metrics.AuthResultSuccess)

	token, err := h.signToken(user.ID, user.Admin)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "msg": "token generation failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "msg": token})
}

func (h *Handler) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		writeJSONErr(w, http.StatusInternalServerError, "missing auth claims")
		return
	}
	token, err := h.signToken(c.ID, c.Admin)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "token generation failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"msg": token})
}

// authedInfo is the JSON shape GET /authed/'s `msg` field takes.
type authedInfo struct {
	PayoutThreshold int64 `json:"payout_threshold"`
	EmailEnabled    bool  `json:"email_enabled"`
}

func (h *Handler) handleAuthedRoot(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		writeJSONErr(w, http.StatusInternalServerError, "missing auth claims")
		return
	}
	user, err := h.repo.GetUserByID(r.Context(), c.ID)
	if err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"msg": authedInfo{PayoutThreshold: user.PayoutThreshold, EmailEnabled: user.EnableEmail},
	})
}

type changePasswordRequest struct {
	Password string `json:"password"`
}

func (h *Handler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		writeJSONErr(w, http.StatusInternalServerError, "missing auth claims")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	if req.Password == "" {
		writeJSONErr(w, http.StatusBadRequest, "password is required")
		return
	}

	hash := h.hashPassword(req.Password)
	if err := h.repo.UpdateUserPassword(r.Context(), c.ID, hash); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"msg": "Password updated"})
}

func (h *Handler) handleToggleEmail(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		writeJSONErr(w, http.StatusInternalServerError, "missing auth claims")
		return
	}
	if err := h.repo.ToggleUserEnableEmail(r.Context(), c.ID); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"msg": "Email toggled"})
}

// changePayoutThresholdRequest.Threshold is float64 (not int64)
// because legacy's lib/api.js read this field with parseFloat and so
// never rejected a decimal value here -- encoding/json, unlike
// parseFloat, hard-errors trying to unmarshal a JSON number with a
// fractional part into an int64 field. payout_threshold is itself an
// atomic-unit bigint column (see brief-auth.md), i.e. inherently
// integral, so any fractional value received is rounded (not
// truncated) to the nearest atomic unit before being persisted --
// this matches ordinary decimal-rounding expectations for a
// caller-supplied numeric amount and avoids silently shaving value
// off a threshold on truncation.
type changePayoutThresholdRequest struct {
	Threshold float64 `json:"threshold"`
}

func (h *Handler) handleChangePayoutThreshold(w http.ResponseWriter, r *http.Request) {
	c, ok := claimsFromContext(r.Context())
	if !ok {
		writeJSONErr(w, http.StatusInternalServerError, "missing auth claims")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req changePayoutThresholdRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	threshold := int64(math.Round(req.Threshold))

	if err := h.repo.UpdateUserPayoutThreshold(r.Context(), c.ID, threshold); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"msg": fmt.Sprintf("Threshold updated, set to: %d", threshold)})
}

// forcePaymentRequest is the JSON body POST /user/forcePayment
// expects. Algo/Network are optional -- see handleForcePayment.
type forcePaymentRequest struct {
	Username string `json:"username"`
	Algo     string `json:"algo"`
	Network  string `json:"network"`
}

// defaultForcePaymentAlgo mirrors legacy's own default (see
// brief-auth.md): a bare username with no algo specified is assumed
// to be a Monero (RXM) address, since forcePayment predates this
// backend's multi-coin/Tari support.
const defaultForcePaymentAlgo = "RXM"

func (h *Handler) handleForcePayment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req forcePaymentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "malformed JSON body"})
		return
	}
	if req.Username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "username is required"})
		return
	}
	if len(req.Username) > maxMinerStringLen || len(req.Algo) > maxMinerStringLen || len(req.Network) > maxMinerStringLen {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "field exceeds maximum length"})
		return
	}

	address, paymentID := splitUsername(req.Username)

	algo := req.Algo
	if algo == "" {
		algo = defaultForcePaymentAlgo
	}

	network := req.Network
	if network == "" {
		network = networkDBString(h.cfg.Network)
	}
	if network == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "network is required (this backend has no default configured network)"})
		return
	}

	if err := h.repo.SetForcePayout(r.Context(), algo, network, address, paymentID); err != nil {
		h.observeForcePayoutWrite(algo, network, metrics.ForcePayoutResultFailure)
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "Error in pushing update, username not found"})
		return
	}
	h.observeForcePayoutWrite(algo, network, metrics.ForcePayoutResultSuccess)
	writeJSON(w, http.StatusOK, map[string]string{"msg": "Payout scheduled"})
}

// updateThresholdRequest.Threshold is float64 for the same reason as
// changePayoutThresholdRequest.Threshold above: legacy's parseFloat
// never rejected a decimal here, and this handler rounds to the
// nearest atomic unit before persisting (see that type's doc comment
// for the full rationale).
type updateThresholdRequest struct {
	Username  string  `json:"username"`
	Threshold float64 `json:"threshold"`
}

func (h *Handler) handleUpdateThreshold(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req updateThresholdRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	if req.Username == "" {
		writeJSONErr(w, http.StatusBadRequest, "username is required")
		return
	}
	if len(req.Username) > maxMinerStringLen {
		writeJSONErr(w, http.StatusBadRequest, "username exceeds maximum length")
		return
	}
	threshold := int64(math.Round(req.Threshold))

	// NOTE (explicit gap, per brief-auth.md): this backend has no
	// single reusable, coin-agnostic "ValidateAddress" function --
	// internal/backend/addressmap's validateXMRAddress/
	// validateTariAddress are coin-SPECIFIC and neither is a good fit
	// for this endpoint's genuinely coin-agnostic `username` field
	// (unlike POST /user/forcePayment, which does have separate
	// algo/network fields it could branch on, this endpoint's legacy
	// shape does not). Rather than inventing new address-decode
	// logic, address-format validation is deliberately skipped here.

	if err := h.repo.UpdateUserThreshold(r.Context(), req.Username, threshold); err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "msg": "Error updating threshold, username not found"})
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"msg": fmt.Sprintf("Threshold updated, set to: %d", threshold)})
}

func (h *Handler) handleGetUser(w http.ResponseWriter, r *http.Request) {
	address := r.PathValue("address")
	if address == "" {
		writeJSONErr(w, http.StatusBadRequest, "address is required")
		return
	}
	if len(address) > maxMinerStringLen {
		writeJSONErr(w, http.StatusBadRequest, "address exceeds maximum length")
		return
	}

	user, err := h.repo.GetUserByUsername(r.Context(), address)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusOK, map[string]any{
				"msg": authedInfo{PayoutThreshold: 0, EmailEnabled: false},
			})
			return
		}
		writeJSONErr(w, http.StatusInternalServerError, "query failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"msg": authedInfo{PayoutThreshold: user.PayoutThreshold, EmailEnabled: user.EnableEmail},
	})
}

type toggleEmailPublicRequest struct {
	Address string `json:"address"`
}

func (h *Handler) handleToggleEmailPublic(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req toggleEmailPublicRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "malformed JSON body")
		return
	}
	if req.Address == "" {
		writeJSONErr(w, http.StatusBadRequest, "address is required")
		return
	}
	if len(req.Address) > maxMinerStringLen {
		writeJSONErr(w, http.StatusBadRequest, "address exceeds maximum length")
		return
	}

	if err := h.repo.ToggleUserEnableEmailByUsername(r.Context(), req.Address); err != nil {
		writeJSONErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"msg": "Email toggled"})
}
