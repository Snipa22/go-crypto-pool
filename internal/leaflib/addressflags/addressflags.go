// Package addressflags is the LEAF-SIDE half of go-crypto-pool's
// manual ban / forced-minimum-difficulty system. The backend's
// internal/backend/db/addressflags.go package is the durable,
// operator-facing storage + CLI for these two REAL, confirmed-manual
// controls (an operator runs `backend address ban`/`force-difficulty`
// in response to a real abuse report or a real need to floor a
// miner's difficulty -- there is no automated detection anywhere).
// This package is where that operator decision actually takes
// effect: at LOGIN time on a leaf, not by the backend rejecting an
// already-submitted share after the fact.
//
// Enforcing this at the backend (the previous, now-reverted approach
// -- see this repo's git history) is the wrong layer: it lets a
// banned/floored miner complete login, receive real jobs, and consume
// real leaf resources (a stratum connection, a JobManager slot, a
// vardiff goroutine) before the backend ever gets a chance to say no.
// Enforcing it here means a banned address's login is rejected
// outright (session.go's handleLogin, both solo and direct), and a
// floored address's difficulty never drops below its operator-set
// minimum for the lifetime of that connection (both at login and on
// every subsequent vardiff retarget -- see Cache.Get's callers in
// solo/session.go, solo/vardiff.go, direct/session.go, direct's own
// vardiff handling).
//
// Two real Source implementations exist, matching the two leaf modes'
// genuinely different relationship with a backend:
//
//   - leaf-direct always has a real backend connection (that is its
//     whole reason for existing -- see cmd/leaf-direct's doc
//     comment), so HTTPSource polls the backend's own real, read-only
//     GET /api/v1/leaf/address-flags endpoint (see
//     internal/backend/leafflagsapi) and caches the result.
//   - leaf-solo has NO backend connection anywhere in the binary (see
//     cmd/leaf-solo's doc comment: "there is no share-forwarding to a
//     backend anywhere in this binary"), so it cannot poll one for
//     this either. FileSource instead polls a local, operator-
//     maintained JSON file on disk -- the same "a human decided this,
//     off-platform, and encoded that decision somewhere this process
//     can read it" shape as the backend CLI, just backed by a file
//     instead of a database row, because a standalone solo leaf has
//     no database to ask.
//
// Both feed the same Cache, so session.go's enforcement logic in
// solo/direct is identical regardless of which Source is behind it --
// neither package needs to know or care where the flags actually came
// from.
package addressflags

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// Flags is one payment address's real, manual ban/forced-minimum-
// difficulty state -- the leaf-side projection of
// db.AddressFlag, stripped down to only the two fields enforcement
// actually needs (no audit metadata; that stays backend-side only,
// see addressflagsapi's doc comment on why the leaf-facing endpoint
// is deliberately narrow).
type Flags struct {
	Banned bool
	// ForcedMinDifficulty is 0 when no operator-forced floor applies
	// to this address (the overwhelmingly common case). A non-zero
	// value is the real minimum share difficulty this address's
	// session must never be started or retargeted below.
	ForcedMinDifficulty uint64
}

// Source fetches the current, complete set of actively-flagged
// addresses (banned OR floored -- mirrors db.Repository.
// ListAddressFlags' own "active flags only" scope exactly). Returning
// the full set each call (rather than an incremental diff) keeps both
// real implementations below simple and keeps Cache's own refresh
// logic source-agnostic.
type Source interface {
	Fetch(ctx context.Context) (map[string]Flags, error)
}

// Cache is a thread-safe, periodically-refreshed, fail-open-on-
// transient-error snapshot of every currently-flagged address. "Fail
// open on transient error" here means: if a poll fails (backend
// briefly unreachable, file briefly unreadable mid-write, etc.), the
// PREVIOUS successful snapshot keeps serving Get calls rather than the
// cache going empty -- this is the ONE deliberate exception to the
// backend's own "a lookup error must never be treated as not flagged"
// rule (addressflags.go's checkAddressFlags doc comment), and it is
// deliberate: an already-banned miner staying banned through a brief
// poll hiccup is the safe failure mode; a miner getting UNBANNED for a
// few seconds because their leaf's poll happened to race a backend
// restart is not. A cache that has NEVER completed a single successful
// poll starts fully empty (nothing flagged) -- see NewCache -- since
// there is no previous snapshot to fall back to and refusing every
// login until the very first poll succeeds would make Source
// unavailability equivalent to ballooning every login into a hard
// dependency on it, which defeats leaf-solo's whole
// no-backend-dependency design point.
type Cache struct {
	source   Source
	interval time.Duration
	logger   *log.Logger

	mu   sync.RWMutex
	data map[string]Flags
}

// NewCache constructs a Cache. interval <= 0 falls back to
// DefaultPollInterval. A nil logger falls back to log.Default().
func NewCache(source Source, interval time.Duration, logger *log.Logger) *Cache {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Cache{source: source, interval: interval, logger: logger, data: make(map[string]Flags)}
}

// DefaultPollInterval is used when a caller passes interval <= 0 to
// NewCache. 30s balances "an operator's ban/floor action takes effect
// on this leaf reasonably quickly" against "do not hammer the backend
// or restat a local file every second across every connected leaf
// process".
const DefaultPollInterval = 30 * time.Second

// Get returns paymentAddress's current Flags (the zero value,
// Flags{Banned: false, ForcedMinDifficulty: 0}, for the overwhelming
// majority of addresses that have never been flagged -- mirrors
// db.Repository.GetAddressFlag's own "not found is normal" contract).
// Safe for concurrent use with Start's background refresh.
func (c *Cache) Get(paymentAddress string) Flags {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.data[paymentAddress]
}

// Start runs an immediate synchronous poll (so the very first login
// after process startup already benefits from whatever was flagged
// before this process started, rather than needing to wait a full
// interval), then continues polling every c.interval in a background
// goroutine until ctx is cancelled. Safe to call at most once per
// Cache; callers (cmd/leaf-solo, cmd/leaf-direct) call this once at
// startup, after constructing the Cache and before serving any miner
// connections.
func (c *Cache) Start(ctx context.Context) {
	c.pollOnce(ctx)
	go func() {
		ticker := time.NewTicker(c.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.pollOnce(ctx)
			}
		}
	}()
}

func (c *Cache) pollOnce(ctx context.Context) {
	pollCtx, cancel := context.WithTimeout(ctx, c.interval)
	defer cancel()
	data, err := c.source.Fetch(pollCtx)
	if err != nil {
		// Fail open on the PREVIOUS snapshot -- see Cache's doc
		// comment. Logged, never silently swallowed: an operator
		// watching leaf logs needs to know their ban/floor source is
		// unreachable, even though enforcement of already-known
		// flags is unaffected.
		c.logger.Printf("addressflags: poll failed, keeping previous snapshot (%d entries): %v", c.len(), err)
		return
	}
	c.mu.Lock()
	c.data = data
	c.mu.Unlock()
}

func (c *Cache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}

// --- HTTPSource: leaf-direct's real backend-polling Source ---

// HTTPSource polls a real backend's GET /api/v1/leaf/address-flags
// endpoint (internal/backend/leafflagsapi) — leaf-direct's Source,
// since leaf-direct always has a configured backend base URL already
// (LEAF_DIRECT_BACKEND_BASE_URL — see cmd/leaf-direct/main.go).
type HTTPSource struct {
	baseURL string
	client  *http.Client
	// authHeaderName/authHeaderValue mirror the same optional
	// shared-secret auth this leaf already sends on every share/
	// block forward (transport.HTTPProtobufTransportConfig) — the
	// address-flags endpoint is read-only and unauthenticated on
	// the backend side today (see leafflagsapi's doc comment), but
	// sending the same header costs nothing and keeps this leaf
	// consistent if that ever changes.
	authHeaderName  string
	authHeaderValue string
}

// NewHTTPSource constructs an HTTPSource against baseURL (e.g.
// "http://backend:8080", no trailing slash required). authHeaderName/
// authHeaderValue may both be empty to send no auth header at all.
func NewHTTPSource(baseURL, authHeaderName, authHeaderValue string) *HTTPSource {
	return &HTTPSource{
		baseURL:         trimTrailingSlash(baseURL),
		client:          &http.Client{},
		authHeaderName:  authHeaderName,
		authHeaderValue: authHeaderValue,
	}
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// leafFlagsResponse mirrors internal/backend/leafflagsapi's real JSON
// response shape exactly.
type leafFlagsResponse struct {
	Flags []leafFlagRow `json:"flags"`
}

type leafFlagRow struct {
	PaymentAddress      string `json:"payment_address"`
	Banned              bool   `json:"banned"`
	ForcedMinDifficulty int64  `json:"forced_min_difficulty,omitempty"`
}

// Fetch implements Source against the real backend endpoint.
func (s *HTTPSource) Fetch(ctx context.Context) (map[string]Flags, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.baseURL+"/api/v1/leaf/address-flags", nil)
	if err != nil {
		return nil, fmt.Errorf("addressflags: building request: %w", err)
	}
	if s.authHeaderName != "" {
		req.Header.Set(s.authHeaderName, s.authHeaderValue)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("addressflags: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("addressflags: reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("addressflags: backend returned status %d: %s", resp.StatusCode, string(body))
	}

	var parsed leafFlagsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("addressflags: decoding response: %w", err)
	}

	out := make(map[string]Flags, len(parsed.Flags))
	for _, row := range parsed.Flags {
		if row.PaymentAddress == "" {
			continue
		}
		var floor uint64
		if row.ForcedMinDifficulty > 0 {
			floor = uint64(row.ForcedMinDifficulty)
		}
		out[row.PaymentAddress] = Flags{Banned: row.Banned, ForcedMinDifficulty: floor}
	}
	return out, nil
}

// --- FileSource: leaf-solo's real local-file Source ---

// FileSource polls a local, operator-maintained JSON file on disk —
// leaf-solo's Source, since leaf-solo has no backend connection at
// all to poll instead (see this package's doc comment). The file is
// re-read from scratch on every poll (no diffing, no mtime check —
// this is a small, infrequently-changing, operator-sized file, not
// something worth optimizing), so an operator can hand-edit it (or
// have some other out-of-band tool regenerate it) and have the change
// take effect within one poll interval with zero leaf-solo restart.
//
// File format is a plain JSON array:
//
//	[
//	  {"payment_address": "abc123...", "banned": true, "reason": "abuse report #42"},
//	  {"payment_address": "def456...", "forced_min_difficulty": 1000000, "reason": "known low-power rig, avoid share-flood"}
//	]
//
// "reason" is accepted and ignored (a human-readability aid for
// whoever maintains the file by hand; leaf-solo enforces, it does not
// audit-log — that half of the design lives in the backend's
// address_flags table for leaf-direct's operators, and leaf-solo
// operators are expected to keep their own record of why an entry is
// in this file, e.g. in the same VCS/config-management history that
// manages the file itself).
type FileSource struct {
	path string
}

// NewFileSource constructs a FileSource reading path.
func NewFileSource(path string) *FileSource {
	return &FileSource{path: path}
}

type fileFlagRow struct {
	PaymentAddress      string `json:"payment_address"`
	Banned              bool   `json:"banned"`
	ForcedMinDifficulty int64  `json:"forced_min_difficulty,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

// Fetch implements Source by re-reading and parsing s.path in full.
// A missing file is treated as "nothing flagged" (not an error) so a
// leaf-solo deployment that has never needed this feature can simply
// never create the file at all and never see a poll-failure log line
// for it; every OTHER read/parse error (permission denied, malformed
// JSON, a real disk error) is returned as a real error so Cache's
// fail-open-on-previous-snapshot behavior applies to it correctly.
func (s *FileSource) Fetch(_ context.Context) (map[string]Flags, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]Flags{}, nil
		}
		return nil, fmt.Errorf("addressflags: reading %s: %w", s.path, err)
	}

	var rows []fileFlagRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		return nil, fmt.Errorf("addressflags: parsing %s: %w", s.path, err)
	}

	out := make(map[string]Flags, len(rows))
	for _, row := range rows {
		if row.PaymentAddress == "" {
			continue
		}
		var floor uint64
		if row.ForcedMinDifficulty > 0 {
			floor = uint64(row.ForcedMinDifficulty)
		}
		out[row.PaymentAddress] = Flags{Banned: row.Banned, ForcedMinDifficulty: floor}
	}
	return out, nil
}
