// Copyright and license: see repository LICENSE (MIT).
//
// checkin.go implements the real legacy nodejs-pool-sxmr /poolCheckin
// heartbeat, modeled on the REAL production source of a sibling clone
// of `nodejs-pool` fetched for this task:
//
//   - `lib/pool.js` (cluster master), `setInterval(..., 10000)`:
//     every 10 seconds, POSTs
//     `{current_time: +new Date(), pool_id: <pool_id>, block_id: <tip
//     height>, ports: {<port>: <miner_count>}}` as JSON to
//     `global.jsonClient`'s base URL (global.config.config_api) +
//     "poolCheckin", with header `x-pool-auth: <api_auth_token>` set
//     once at client construction. `current_time` is JS `+new Date()`
//     -- real Unix MILLISECONDS.
//   - `lib/remoteShare.js`'s `app.post('/poolApi/poolCheckin', ...)`
//     handler: this route uses `bodyParser.json()` (unlike /leafApi's
//     raw-protobuf WSData handling -- see legacytransport.go's package
//     doc comment), and checks the `x-pool-auth` header against
//     `global.config.api_auth_token` -- a SEPARATE secret from the
//     WSData.key checked on /leafApi (confirmed real, distinct config
//     fields on every leaf host's own nodejs-pool-tari-internal/
//     config.json). On success: `UPDATE pools SET last_checkin=...,
//     active=true, blockIDTime=now(), blockID=... WHERE id=<pool_id>`,
//     then for each port in the submitted `ports` map: `UPDATE ports
//     SET lastSeen=now(), miners=<count> WHERE pool_id=<pool_id> AND
//     network_port=<port>`.
//
// Without this heartbeat, pool-core's own routing/health-check logic
// (which depends on `pools.active`/`ports.lastSeen` staleness) silently
// drains miner traffic away from an otherwise fully healthy leaf within
// ~10-20 minutes -- a real, already-observed production incident
// (2026-09-23), previously mitigated by a throwaway Python sidecar
// script that this implementation replaces and lets be decommissioned.
package legacytransport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// DefaultCheckinInterval matches the real legacy cadence exactly (see
// lib/pool.js's `setInterval(..., 10000)`).
const DefaultCheckinInterval = 10 * time.Second

// checkinAPIPath is the real, fixed nodejs-pool-sxmr endpoint path --
// see lib/remoteShare.js's `app.post('/poolApi/poolCheckin', ...)`
// registration, reached via global.config.config_api (the operator-
// configured base URL) + this fixed suffix.
const checkinAPIPath = "poolCheckin"

// CheckinConfig configures a Checkin heartbeat.
type CheckinConfig struct {
	// APIURL is the legacy backend's real `config_api` base URL, e.g.
	// "http://203.0.113.10:32322/poolApi/" in production -- see
	// package doc comment. Checkin appends checkinAPIPath
	// ("poolCheckin") itself, so a trailing slash on APIURL is
	// tolerated either way (trimmed before joining).
	APIURL string

	// AuthToken is the real `api_auth_token` secret, sent as the
	// `x-pool-auth` HTTP header on every request. This is DELIBERATELY
	// a separate secret from LegacyTransport.Config.AuthKey (the
	// WSData.key checked on /leafApi) -- see package doc comment for
	// why these are two distinct real secrets on the real backend.
	// Never logged.
	AuthToken string

	// PoolID is the same legacy pool-server-source identifier already
	// used for share/block forwarding (LegacyTransport.Config.
	// LegacyPoolID) -- confirmed from remoteShare.js's poolCheckin
	// handler, which does a plain `WHERE id = pool_id` against the
	// same `pools` table/numbering space share/block forwarding uses.
	PoolID int32

	// Interval overrides DefaultCheckinInterval. Zero/negative falls
	// back to the default.
	Interval time.Duration

	// HTTPClient allows injecting a custom *http.Client (e.g. for test
	// doubles). If nil, a client with a conservative default Timeout
	// is constructed.
	HTTPClient *http.Client

	// Logger receives a warning line on every failed checkin POST
	// (never fatal -- see Run's doc comment). If nil, log.Default() is
	// used.
	Logger *log.Logger
}

// TipHeightSource is the minimal interface Checkin needs to learn the
// current chain-tip height for the heartbeat's `block_id` field.
// *solo.JobManager's own LatestHeight method satisfies this directly --
// Checkin deliberately does not run its own separate tip poller.
type TipHeightSource interface {
	LatestHeight() uint64
}

// PortMinerCounter is the minimal interface Checkin needs to learn the
// current per-port connected-miner counts for the heartbeat's `ports`
// field. cmd/leaf-direct supplies a small adapter built from its own
// *leaflib.ConnectionManager.Snapshot() + each listener's real bound
// port (see that binary's own checkin wiring) -- this package
// deliberately has no opinion on "ports" as a concept, matching
// LegacyTransport's own coin/port-agnostic design.
type PortMinerCounter interface {
	PortMinerCounts() map[int]int
}

// checkinBody is the exact real JSON shape lib/pool.js POSTs (see
// package doc comment) -- field names/casing match the real legacy
// sender byte-for-byte since the legacy handler decodes real JSON keys,
// not protobuf.
type checkinBody struct {
	CurrentTime int64       `json:"current_time"`
	PoolID      int32       `json:"pool_id"`
	BlockID     uint64      `json:"block_id"`
	Ports       map[int]int `json:"ports"`
}

// Checkin runs the real legacy /poolCheckin heartbeat on a fixed
// interval. It is legacy-mode-only: constructing and Run-ing one has no
// effect on, and shares no state with, the normal (non-legacy)
// HTTPProtobufTransport share/block forwarding path.
type Checkin struct {
	apiURL    string
	authToken string
	poolID    int32
	interval  time.Duration
	client    *http.Client
	logger    *log.Logger
}

// NewCheckin constructs a Checkin from cfg. Returns an error if APIURL
// or AuthToken is empty, or PoolID is not positive -- mirrors New's
// (legacytransport.go) own required-field validation convention
// exactly.
func NewCheckin(cfg CheckinConfig) (*Checkin, error) {
	if cfg.APIURL == "" {
		return nil, fmt.Errorf("legacytransport: NewCheckin: APIURL must not be empty")
	}
	if cfg.AuthToken == "" {
		return nil, fmt.Errorf("legacytransport: NewCheckin: AuthToken must not be empty")
	}
	if cfg.PoolID <= 0 {
		return nil, fmt.Errorf("legacytransport: NewCheckin: PoolID must be positive, got %d", cfg.PoolID)
	}

	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultCheckinInterval
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: interval}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	return &Checkin{
		apiURL:    trimTrailingSlash(cfg.APIURL) + "/",
		authToken: cfg.AuthToken,
		poolID:    cfg.PoolID,
		interval:  interval,
		client:    client,
		logger:    logger,
	}, nil
}

// Run blocks, POSTing a checkin on every tick until ctx is cancelled.
// Best-effort, non-blocking, never-fail semantics matching every other
// legacy-mode feature in this codebase: a failed checkin POST logs a
// warning and retries on the next tick -- it never panics, never
// crashes the calling leaf, and never blocks longer than one HTTP call
// (bounded by the same interval as the client's own request timeout).
// Callers are expected to invoke this via `go`.
func (c *Checkin) Run(ctx context.Context, tip TipHeightSource, ports PortMinerCounter) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.postOnce(ctx, tip, ports); err != nil {
				c.logger.Printf("legacytransport: checkin: %v", err)
			}
		}
	}
}

// postOnce sends exactly one checkin POST. Exported test-shape via the
// package-internal test file; callers should generally use Run.
func (c *Checkin) postOnce(ctx context.Context, tip TipHeightSource, ports PortMinerCounter) error {
	body := checkinBody{
		CurrentTime: time.Now().UnixMilli(),
		PoolID:      c.poolID,
		BlockID:     tip.LatestHeight(),
		Ports:       ports.PortMinerCounts(),
	}
	if body.Ports == nil {
		body.Ports = map[int]int{}
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal checkin body: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, c.interval)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.apiURL+checkinAPIPath, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build checkin request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-pool-auth", c.authToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("submit checkin: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("submit checkin: backend returned status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}
