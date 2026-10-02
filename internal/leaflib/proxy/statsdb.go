// Copyright and license: see repository LICENSE (MIT).

// Package proxy (this file): leaf-proxy's optional 24h miner-history
// retention (DISPATCH_BRIEF.md "leaf-proxy ... 24h stats retention").
// Alex's own framing, quoted verbatim: "24h stats retention - Likely
// a local loop and/or a small SQLite DB - Used for basic miner
// tracking". That is the EXACT, and only, scope of this file: a
// small local loop plus a small SQLite DB, for basic per-address
// miner tracking over the trailing 24 hours. It is deliberately NOT
// a general-purpose time-series store -- no aggregation, no
// downsampling, no pagination, no multi-address queries. A future
// reader who needs more than "give me this one address's samples
// from the last 24h" should treat that as a new feature, not an
// extension of this one.
//
// Storage: modernc.org/sqlite, a pure-Go (no cgo) SQLite driver --
// consistent with this repo's existing pure-Go-over-cgo preference
// (see internal/leaflib/validator/randomx_puregolang.go's own doc
// comment on exactly that tradeoff for RandomX). Disabled entirely
// (StatsDB is never constructed, no background loop ever starts)
// unless -stats-db-path/LEAF_PROXY_STATS_DB_PATH is non-empty --
// matches this codebase's consistent "empty path = feature off"
// convention (address-flags-file, tls-cert-persist-path).
//
// Schema: one table, miner_samples(ts INTEGER, address TEXT, port
// TEXT, difficulty INTEGER, hashrate_hz REAL, share_count INTEGER),
// with an index on (address, ts) for the per-address history query
// this file's whole point is to serve. Every sample tick
// (RunSampleLoop below) both inserts the current snapshot AND prunes
// rows older than 24h in the SAME tick -- a real prune, not a
// separate, easily-forgotten cron job.
package proxy

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	_ "modernc.org/sqlite" // pure-Go sqlite driver, registers itself as "sqlite"
)

// MinerSample is one point-in-time, per-address row in miner_samples
// -- both what RunSampleLoop inserts (one per currently-connected,
// logged-in session, via Server.SampleForStatsDB) and what History
// returns.
type MinerSample struct {
	Timestamp  time.Time
	Address    string
	Port       string
	Difficulty uint64
	HashrateHz float64
	ShareCount uint64
}

// StatsDB owns the SQLite connection backing this feature. Construct
// via OpenStatsDB; nil is never a valid, usable *StatsDB (unlike this
// package's nil-safe metrics/debugLogger conventions) -- callers
// (cmd/leaf-proxy/main.go) only ever construct one at all when
// -stats-db-path is non-empty, and simply never reference it
// otherwise.
type StatsDB struct {
	db     *sql.DB
	logger *log.Logger
}

// OpenStatsDB opens (creating if absent) the SQLite file at path,
// and ensures the miner_samples table and its (address, ts) index
// exist. logger defaults to log.Default() if nil.
func OpenStatsDB(path string, logger *log.Logger) (*StatsDB, error) {
	if logger == nil {
		logger = log.Default()
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("statsdb: opening %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("statsdb: pinging %s: %w", path, err)
	}
	const schema = `
CREATE TABLE IF NOT EXISTS miner_samples (
	ts INTEGER NOT NULL,
	address TEXT NOT NULL,
	port TEXT NOT NULL,
	difficulty INTEGER NOT NULL,
	hashrate_hz REAL NOT NULL,
	share_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_miner_samples_address_ts ON miner_samples (address, ts);
`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("statsdb: creating schema in %s: %w", path, err)
	}
	return &StatsDB{db: db, logger: logger}, nil
}

// Close closes the underlying SQLite connection.
func (sdb *StatsDB) Close() error {
	return sdb.db.Close()
}

// InsertSamples inserts one row per sample, all in a single
// transaction. A nil/empty samples is a no-op (no empty transaction
// is opened).
func (sdb *StatsDB) InsertSamples(ctx context.Context, samples []MinerSample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := sdb.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("statsdb: begin insert tx: %w", err)
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO miner_samples (ts, address, port, difficulty, hashrate_hz, share_count) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("statsdb: prepare insert: %w", err)
	}
	defer stmt.Close()
	for _, s := range samples {
		if _, err := stmt.ExecContext(ctx, s.Timestamp.Unix(), s.Address, s.Port, s.Difficulty, s.HashrateHz, s.ShareCount); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("statsdb: inserting sample for address %q: %w", s.Address, err)
		}
	}
	return tx.Commit()
}

// PruneOlderThan deletes every row with ts < cutoff.Unix(), returning
// the number of rows actually removed. Called every sample tick (see
// RunSampleLoop) with cutoff == now-24h -- a real prune every tick,
// not a separate, easily-forgotten cron job.
func (sdb *StatsDB) PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := sdb.db.ExecContext(ctx, `DELETE FROM miner_samples WHERE ts < ?`, cutoff.Unix())
	if err != nil {
		return 0, fmt.Errorf("statsdb: pruning rows older than %s: %w", cutoff, err)
	}
	return res.RowsAffected()
}

// History returns every sample for address from the trailing 24h,
// sorted oldest-to-newest. An address with no samples at all returns
// an empty (non-nil) slice, not an error.
func (sdb *StatsDB) History(ctx context.Context, address string) ([]MinerSample, error) {
	cutoff := time.Now().Add(-24 * time.Hour).Unix()
	rows, err := sdb.db.QueryContext(ctx,
		`SELECT ts, address, port, difficulty, hashrate_hz, share_count FROM miner_samples WHERE address = ? AND ts >= ? ORDER BY ts ASC`,
		address, cutoff)
	if err != nil {
		return nil, fmt.Errorf("statsdb: querying history for address %q: %w", address, err)
	}
	defer rows.Close()

	out := make([]MinerSample, 0)
	for rows.Next() {
		var ts int64
		var s MinerSample
		if err := rows.Scan(&ts, &s.Address, &s.Port, &s.Difficulty, &s.HashrateHz, &s.ShareCount); err != nil {
			return nil, fmt.Errorf("statsdb: scanning history row for address %q: %w", address, err)
		}
		s.Timestamp = time.Unix(ts, 0).UTC()
		out = append(out, s)
	}
	return out, rows.Err()
}

// RunSampleLoop runs forever (until ctx is cancelled): every
// interval, it calls snapshot(now) to get the current per-session
// samples, inserts them, and prunes every row older than 24h -- in
// that same tick, so retention never silently falls behind. Intended
// caller: cmd/leaf-proxy/main.go, as its own background goroutine
// (mirroring the hashrate-report ticker's and metrics HTTP server's
// own ctx-cancellation wiring), passing server.SampleForStatsDB as
// snapshot. Logs (via sdb.logger, unconditionally -- these are rare,
// real I/O failures against this leaf's own local SQLite file, not
// per-connection noise) and continues on a single tick's insert/prune
// error rather than exiting the loop entirely.
func (sdb *StatsDB) RunSampleLoop(ctx context.Context, interval time.Duration, snapshot func(time.Time) []MinerSample) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			samples := snapshot(now)
			if err := sdb.InsertSamples(ctx, samples); err != nil {
				sdb.logger.Printf("proxy: statsdb: failed to insert samples: %v", err)
			}
			if _, err := sdb.PruneOlderThan(ctx, now.Add(-24*time.Hour)); err != nil {
				sdb.logger.Printf("proxy: statsdb: failed to prune samples older than 24h: %v", err)
			}
		}
	}
}

// SampleForStatsDB returns one MinerSample per currently-connected,
// logged-in (non-empty address) downstream session, stamped with ts
// -- the real, live snapshot source RunSampleLoop's own snapshot
// callback is wired to (cmd/leaf-proxy/main.go), built from the SAME
// Stats() call StatsHTMLHandler/MinersJSONHandler already use (no new
// stats-collection mechanism).
func (s *Server) SampleForStatsDB(ts time.Time) []MinerSample {
	st := s.Stats()
	out := make([]MinerSample, 0, len(st.Sessions))
	for _, sess := range st.Sessions {
		if sess.Address == "" {
			continue
		}
		out = append(out, MinerSample{
			Timestamp:  ts,
			Address:    sess.Address,
			Port:       sess.Port,
			Difficulty: sess.CurrentDifficulty,
			HashrateHz: sess.EstimatedHashrate,
			ShareCount: sess.ShareCount,
		})
	}
	return out
}

// minerHistoryEntry is one element of MinersHistoryHandler's JSON
// array response -- deliberately a separate, narrower shape from
// MinerSample (no raw address field: the query parameter that
// selected it already told the caller which address this is).
type minerHistoryEntry struct {
	Timestamp  string  `json:"timestamp"`
	Port       string  `json:"port"`
	Difficulty uint64  `json:"difficulty"`
	HashrateHz float64 `json:"hashrate_hz"`
	ShareCount uint64  `json:"share_count"`
}

// MinersHistoryHandler serves GET /api/miners/history?address=<addr>:
// the last 24h of db's retained samples for that address, sorted
// oldest-to-newest, as a JSON array. address is REQUIRED -- omitting
// it is a 400, not "return everything" (DISPATCH_BRIEF.md: "this is
// 'basic miner tracking' per Alex's own framing, not a full analytics
// backend -- a simple per-address query is sufficient scope, don't
// build pagination/aggregation beyond this"). Intended registration:
// the SAME metricsMux /metrics and / are registered on, only when
// -stats-db-path is non-empty (cmd/leaf-proxy/main.go) -- section 1's
// optional HTTP Basic Auth gate, once a password is configured,
// covers this route too.
func MinersHistoryHandler(db *StatsDB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		address := r.URL.Query().Get("address")
		if address == "" {
			http.Error(w, "address query parameter is required", http.StatusBadRequest)
			return
		}
		samples, err := db.History(r.Context(), address)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to query history: %v", err), http.StatusInternalServerError)
			return
		}
		out := make([]minerHistoryEntry, 0, len(samples))
		for _, s := range samples {
			out = append(out, minerHistoryEntry{
				Timestamp:  s.Timestamp.Format(time.RFC3339),
				Port:       s.Port,
				Difficulty: s.Difficulty,
				HashrateHz: s.HashrateHz,
				ShareCount: s.ShareCount,
			})
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(out); err != nil {
			http.Error(w, fmt.Sprintf("failed to encode history JSON: %v", err), http.StatusInternalServerError)
		}
	})
}
