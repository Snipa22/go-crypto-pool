// Package networkpoller implements the backend's real, live REAL-
// NETWORK-STATE poll loop (subsystem gap audit items 2+4): unlike
// internal/backend/networkapi.NetworkStatsSince, which only ever
// derives its numbers from THIS pool's own `shares`/`blocks` tables
// (i.e. "how hard is this pool's own miner set working"), this
// package periodically queries the REAL upstream node/daemon this
// pool mines against -- a real Tari base node over GRPC for RXT/C29/
// SHA3X, a real monerod over JSON-RPC for RXM -- and records that
// chain's OWN actual height/difficulty/estimated-hashrate into
// internal/backend/db's `network_state` table (see that table's
// migration doc comment for the full rationale).
//
// This mirrors internal/backend/unlocker's poll-loop shape closely
// (Config/RunOnce/RunLoop, one real RPC/GRPC call per configured
// algo per pass, errors logged+counted rather than crashing the
// loop) since the two packages solve structurally identical problems
// -- periodically asking a real external chain a question and
// writing the answer back to Postgres -- just against a different
// question (chain-state snapshot vs. one block's maturity).
package networkpoller

import (
	"context"
	"fmt"
	"log"
	"time"
)

// State is one real, live chain-state snapshot a Source has fetched
// for one algo/network. Fields mirror db.NetworkState field-for-field
// (see that package's doc comment) -- kept as this package's own
// type, rather than importing internal/backend/db directly, for the
// same dependency-direction reason internal/backend/unlocker.Block
// exists (see that package's doc comment): cmd/backend is the only
// place this package and internal/backend/db need to meet.
type State struct {
	// Height is the real chain's own current tip height, as reported
	// live by the queried node/daemon at fetch time.
	Height int64

	// Difficulty is the real chain's own current difficulty, as
	// reported live by the queried node/daemon. nil when the
	// queried protocol call for this algo does not cleanly resolve
	// a single per-algo difficulty (see TariNetworkSource's doc
	// comment) rather than a fabricated/guessed value.
	Difficulty *float64

	// EstimatedHashrateHS is the real chain-wide estimated network
	// hashrate in H/s, as reported live by (or derived live from)
	// the queried node/daemon's own response.
	EstimatedHashrateHS *float64

	// BestBlockHash is the real chain's current tip block hash, best
	// effort / for diagnostics only.
	BestBlockHash string
}

// Source fetches one real, live State for one configured algo/
// network target. Each production implementation (TariNetworkSource,
// MoneroNetworkSource) owns its own real RPC/GRPC wire protocol
// entirely -- this interface's only job is to let Poller's poll loop
// stay coin-agnostic, exactly mirroring chain.ChainVerifier's role
// for internal/backend/unlocker.
type Source interface {
	// FetchNetworkState performs one real query against the upstream
	// node/daemon this Source is configured against and returns its
	// current chain state. A non-nil error means a genuine
	// operational failure (RPC/network/decode error) -- Poller logs
	// and counts it, leaving that algo's network_state row
	// untouched (stale) until the next successful pass, rather than
	// ever writing a zeroed/guessed State.
	FetchNetworkState(ctx context.Context) (State, error)
}

// Target pairs one algo's real Source with the network label its
// State should be recorded under.
type Target struct {
	Algo    string
	Network string
	Source  Source
}

// Repository is the narrow persistence surface Poller depends on.
// *db.Repository satisfies this interface as-is (UpsertNetworkState,
// db/network.go) via cmd/backend's adapter, exactly mirroring
// unlocker.Repository's role.
type Repository interface {
	UpsertNetworkState(ctx context.Context, algo, network string, state RepoState) error
}

// RepoState is the exact shape Repository.UpsertNetworkState accepts
// -- deliberately identical in field set to db.NetworkState, so
// cmd/backend's adapter is a pure 1:1 field copy (see that adapter's
// own doc comment).
type RepoState struct {
	Height              int64
	Difficulty          *float64
	EstimatedHashrateHS *float64
	BestBlockHash       string
	Source              string
	PolledAt            time.Time
}

// Metrics is the narrow instrumentation surface Poller optionally
// reports to -- satisfied by *metrics.Metrics via cmd/backend's
// wiring, kept as its own tiny interface here (rather than importing
// internal/backend/metrics directly) so this package's tests never
// need a real Prometheus registry.
type Metrics interface {
	ObserveNetworkPoll(algo, network, result string, duration time.Duration)
}

// Config configures a Poller.
type Config struct {
	// Targets is every algo/network this poller should query each
	// pass. An empty slice is accepted (RunOnce/RunLoop simply do
	// nothing) -- "no real chain sources configured" is a legitimate
	// deployment state (e.g. neither GCPOOL_TARI_GRPC_ADDR nor
	// GCPOOL_MONERO_RPC_ADDR set), not a caller error.
	Targets []Target

	// PollInterval is how often RunLoop re-queries every configured
	// Target. Required to be > 0 for RunLoop (RunOnce ignores it
	// entirely -- it always runs exactly one pass).
	PollInterval time.Duration

	// Logf receives one line per notable event. Defaults to
	// log.Printf if nil.
	Logf func(format string, args ...any)

	// Metrics, if non-nil, is reported to once per Target per pass.
	Metrics Metrics
}

// Poller runs Config's poll loop against a Repository.
type Poller struct {
	repo Repository
	cfg  Config
	logf func(format string, args ...any)
}

// New constructs a Poller.
func New(repo Repository, cfg Config) *Poller {
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	return &Poller{repo: repo, cfg: cfg, logf: logf}
}

// PassResult summarizes the outcome of one RunOnce call, primarily
// for tests and operational logging.
type PassResult struct {
	Fetched int
	Errors  int
}

const (
	resultOK    = "ok"
	resultError = "error"
)

// RunOnce performs exactly one poll pass: for every configured
// Target, fetches its real, live network state and, on success,
// upserts it into the Repository. A fetch or upsert failure for one
// Target is logged and counted but never aborts the remaining
// Targets in this pass -- one unreachable node/daemon must not stall
// every other configured algo's network_state freshness.
func (p *Poller) RunOnce(ctx context.Context) PassResult {
	var total PassResult
	for _, t := range p.cfg.Targets {
		start := time.Now()
		result := resultOK

		state, err := t.Source.FetchNetworkState(ctx)
		if err != nil {
			result = resultError
			total.Errors++
			p.logf("networkpoller: %s/%s: fetching real network state: %v", t.Algo, t.Network, err)
		} else if err := p.repo.UpsertNetworkState(ctx, t.Algo, t.Network, RepoState{
			Height:              state.Height,
			Difficulty:          state.Difficulty,
			EstimatedHashrateHS: state.EstimatedHashrateHS,
			BestBlockHash:       state.BestBlockHash,
			Source:              sourceLabel(t),
			PolledAt:            start,
		}); err != nil {
			result = resultError
			total.Errors++
			p.logf("networkpoller: %s/%s: recording real network state: %v", t.Algo, t.Network, err)
		} else {
			total.Fetched++
		}

		if p.cfg.Metrics != nil {
			p.cfg.Metrics.ObserveNetworkPoll(t.Algo, t.Network, result, time.Since(start))
		}
	}
	return total
}

// sourceLabel derives network_state.source's diagnostic string from
// t.Source's dynamic type -- purely for operational readability in
// the DB row, never parsed by any reader (see that column's
// migration doc comment).
func sourceLabel(t Target) string {
	switch t.Source.(type) {
	case *TariNetworkSource:
		return "tari_grpc"
	case *MoneroNetworkSource:
		return "monero_rpc"
	default:
		return fmt.Sprintf("%T", t.Source)
	}
}

// RunLoop calls RunOnce every cfg.PollInterval until ctx is canceled.
// It never returns an error itself -- RunOnce already swallows and
// logs per-target failures, mirroring unlocker.Unlocker.RunLoop.
func (p *Poller) RunLoop(ctx context.Context) {
	if p.cfg.PollInterval <= 0 {
		p.logf("networkpoller: PollInterval <= 0, RunLoop exiting without polling")
		return
	}
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()

	// Run one pass immediately on startup rather than waiting a full
	// PollInterval for the first real network_state row to appear --
	// mirrors cmd/backend's own runWalletStatsPoller's pollOnce()
	// -then-loop shape.
	p.RunOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.RunOnce(ctx)
		}
	}
}
