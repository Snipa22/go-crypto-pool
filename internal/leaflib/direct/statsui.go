// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	directmetrics "github.com/Snipa22/go-crypto-pool/internal/leaflib/direct/metrics"
)

// SessionStat is one connected session's real, point-in-time
// diagnostic snapshot, used by both Stats() and the stats HTML page
// — mirrors internal/leaflib/solo/server.go's SessionStat shape
// exactly (leaf-direct tracks the same per-session share/block
// bookkeeping as leaf-solo; BlockCount here means a genuine found
// block, same as solo, NOT leaf-proxy's "forwarded upstream" sense).
type SessionStat struct {
	SessionID string
	Address   string
	Worker    string
	// Agent is the real miner software/version string the miner
	// self-reported at login (solo.LoginRequest.Agent) — mirrors
	// solo/server.go's SessionStat.Agent exactly.
	Agent             string
	RemoteAddr        string
	ConnectedAt       time.Time
	CurrentDifficulty uint64
	ShareCount        uint64
	BlockCount        uint64
	// EstimatedHashrate mirrors solo/server.go's own
	// SessionStat.EstimatedHashrate exactly (see
	// leaflib.EstimateHashrateHz's doc comment for the formula).
	EstimatedHashrate float64
}

// AddressCount is one entry in Stats.MinersByAddress: a mining/payout
// address (or metrics.OtherAddressLabel for the overflow bucket) and
// the number of currently-connected sessions logged in under it —
// mirrors internal/leaflib/solo/server.go's AddressCount exactly.
type AddressCount struct {
	Address string
	Count   int
}

// Stats is a point-in-time diagnostic snapshot across all currently-
// connected sessions, backing both Stats() callers (logging, tests)
// and the stats HTML page — mirrors internal/leaflib/solo/server.go's
// and internal/leaflib/proxy/server.go's Stats shape exactly, plus
// leaf-direct's own additional backend-transport health fields (its
// analogue of leaf-proxy's UpstreamConnected/UpstreamReconnects: there
// is no persistent backend connection object to type-assert against,
// since transport.ShareTransport is a stateless per-call interface,
// so these instead reflect the last known real outcome of
// forwardShare/forwardBlock — see server.go's recordTransportError/
// recordTransportSuccess).
type Stats struct {
	ActiveSessions   int
	TotalShares      uint64
	TotalBlocks      uint64
	UniqueRemoteIPs  int
	MinersByAddress  []AddressCount // capped/sorted desc by count, overflow aggregated into metrics.OtherAddressLabel
	MinDifficulty    uint64
	MaxDifficulty    uint64
	MedianDifficulty uint64
	Sessions         []SessionStat // per-session snapshot list, sorted by ConnectedAt

	// TotalEstimatedHashrate is the sum of EstimatedHashrate across
	// all sessions in this snapshot (hashes/second) — see
	// SessionStat.EstimatedHashrate's doc comment for the underlying
	// per-session formula.
	TotalEstimatedHashrate float64

	// BackendHealthy is true when the last known real
	// forwardShare/forwardBlock call to the backend succeeded (or no
	// call has been made yet — "no known failure" is the honest
	// default state for a freshly-started leaf-direct instance).
	BackendHealthy bool
	// BackendErrorsTotal is the real, cumulative count of transport
	// failures (share+block combined) since process start.
	BackendErrorsTotal uint64
	// BackendLastErrorKind is "share" or "block", whichever the most
	// recent recorded transport outcome (success or failure)
	// concerned — empty if no backend call has completed yet.
	BackendLastErrorKind string
	// BackendLastCheckedAt is the timestamp of the most recent
	// recorded transport outcome (success or failure) — zero if no
	// backend call has completed yet.
	BackendLastCheckedAt time.Time
}

// Stats returns a diagnostic snapshot across all currently-connected
// sessions: real per-session data (address, worker, remote address,
// current vardiff difficulty, share/block counts), real per-address
// connection counts (subject to the same cardinality cap as the
// leaf_direct_miners_by_address metric — see
// directmetrics.CapAddressCounts), the real count of distinct remote
// IPs currently connected, the real min/max/median of currently-
// connected sessions' vardiff difficulty, and the real backend-
// transport health state (see the Stats type's doc comment) — mirrors
// internal/leaflib/solo/server.go's Stats() exactly, plus the
// backend-transport-health fields solo mode has no analogue for.
func (s *Server) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st := Stats{ActiveSessions: len(s.sessions)}
	ipSet := make(map[string]struct{}, len(s.sessions))
	addrCounts := make(map[string]int)
	diffs := make([]uint64, 0, len(s.sessions))
	st.Sessions = make([]SessionStat, 0, len(s.sessions))

	for _, sess := range s.sessions {
		st.TotalShares += sess.shareCount.Load()
		st.TotalBlocks += sess.blockCount.Load()

		addr, _ := sess.address.Load().(string)
		worker, _ := sess.worker.Load().(string)
		agent, _ := sess.agent.Load().(string)
		remoteIP := directmetrics.RemoteIPOf(sess.mc.RemoteAddr())
		diff := sess.currentDifficulty.Load()

		if remoteIP != "" {
			ipSet[remoteIP] = struct{}{}
		}
		if addr != "" {
			addrCounts[addr]++
		}
		diffs = append(diffs, diff)

		remoteAddr := ""
		if sess.mc.RemoteAddr() != nil {
			remoteAddr = sess.mc.RemoteAddr().String()
		}
		hashrate := leaflib.EstimateHashrateHz(sess.hashesAccumulated.Load(), sess.connectedAt)
		st.Sessions = append(st.Sessions, SessionStat{
			SessionID:         sess.sessionID,
			Address:           addr,
			Worker:            worker,
			Agent:             agent,
			RemoteAddr:        remoteAddr,
			ConnectedAt:       sess.connectedAt,
			CurrentDifficulty: diff,
			ShareCount:        sess.shareCount.Load(),
			BlockCount:        sess.blockCount.Load(),
			EstimatedHashrate: hashrate,
		})
		st.TotalEstimatedHashrate += hashrate
	}

	st.UniqueRemoteIPs = len(ipSet)

	kept, other := directmetrics.CapAddressCounts(addrCounts, s.maxAddressLabels)
	st.MinersByAddress = sortedAddressCounts(kept, other)

	st.MinDifficulty, st.MaxDifficulty, st.MedianDifficulty = minMaxMedian(diffs)

	sortSessionsByConnectedAt(st.Sessions)

	st.BackendHealthy = s.transportOKSoFar.Load()
	st.BackendErrorsTotal = s.transportErrorTotal.Load()
	if kind, ok := s.lastTransportKind.Load().(string); ok {
		st.BackendLastErrorKind = kind
	}
	if at, ok := s.lastTransportAt.Load().(time.Time); ok {
		st.BackendLastCheckedAt = at
	}

	return st
}

// sortedAddressCounts renders kept+other into the deterministic,
// count-desc-then-address-asc order the stats HTML page and any
// future consumer expect, with the "other" overflow bucket (if any)
// always last — mirrors internal/leaflib/solo/server.go's
// sortedAddressCounts exactly.
func sortedAddressCounts(kept map[string]int, other int) []AddressCount {
	out := make([]AddressCount, 0, len(kept)+1)
	for addr, count := range kept {
		out = append(out, AddressCount{Address: addr, Count: count})
	}
	sortAddressCounts(out)
	if other > 0 {
		out = append(out, AddressCount{Address: directmetrics.OtherAddressLabel, Count: other})
	}
	return out
}

func sortAddressCounts(counts []AddressCount) {
	for i := 1; i < len(counts); i++ {
		for j := i; j > 0; j-- {
			a, b := counts[j-1], counts[j]
			if a.Count > b.Count || (a.Count == b.Count && a.Address <= b.Address) {
				break
			}
			counts[j-1], counts[j] = counts[j], counts[j-1]
		}
	}
}

// sortSessionsByConnectedAt sorts sessions ascending by ConnectedAt —
// mirrors internal/leaflib/proxy/server.go's sortSessionsByConnectedAt
// exactly.
func sortSessionsByConnectedAt(sessions []SessionStat) {
	for i := 1; i < len(sessions); i++ {
		for j := i; j > 0; j-- {
			if !sessions[j-1].ConnectedAt.After(sessions[j].ConnectedAt) {
				break
			}
			sessions[j-1], sessions[j] = sessions[j], sessions[j-1]
		}
	}
}

// minMaxMedian computes real min/max/median over vals without
// mutating the caller's slice (it copies before sorting). Returns
// zeros for an empty input — mirrors internal/leaflib/solo/server.go's
// minMaxMedian exactly.
func minMaxMedian(vals []uint64) (min, max, median uint64) {
	if len(vals) == 0 {
		return 0, 0, 0
	}
	sorted := make([]uint64, len(vals))
	copy(sorted, vals)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j-1] > sorted[j]; j-- {
			sorted[j-1], sorted[j] = sorted[j], sorted[j-1]
		}
	}
	min = sorted[0]
	max = sorted[len(sorted)-1]
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		median = sorted[mid]
	} else {
		median = (sorted[mid-1] + sorted[mid]) / 2
	}
	return min, max, median
}

// statsPageTemplate is the basic, single-page stats UI for
// leaf-direct — mirrors internal/leaflib/solo/statsui.go's and
// internal/leaflib/proxy/statsui.go's statsPageTemplate exactly (same
// "no JS framework, no client-side polling" scope), plus a
// backend-transport-health block analogous to leaf-proxy's
// upstream-connection-health block (leaf-direct forwards every
// validated share/block to a real backend instead of a single
// upstream pool connection, so the health signal shown here is "is
// the last known real backend call succeeding" rather than "is a
// persistent socket connected").
var statsPageTemplate = template.Must(template.New("direct-stats").Funcs(template.FuncMap{
	"formatTime": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.Format(time.RFC3339)
	},
	"connDuration": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return time.Since(t).Round(time.Second).String()
	},
	"formatHashrate": formatHashrate,
}).Parse(statsPageHTML))

const statsPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>leaf-direct stats</title>
<style>
  body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }
  h1 { margin-bottom: 0.25rem; }
  .generated { color: #666; font-size: 0.85rem; margin-bottom: 1.5rem; }
  .cards { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.5rem; min-width: 160px; }
  .card .value { font-size: 1.8rem; font-weight: 600; }
  .card .label { color: #666; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }
  .card.up .value { color: #1a7a1a; }
  .card.down .value { color: #b00020; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; background: #fff; }
  th, td { border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }
  th { background: #f0f0f0; }
  tr:nth-child(even) { background: #fbfbfb; }
  .empty { color: #999; font-style: italic; }
  .other { color: #999; }
  h2 { margin-top: 2rem; }
</style>
</head>
<body>
  <h1>leaf-direct stats</h1>
  <div class="generated">generated {{.GeneratedAt}}</div>

  <div class="cards">
    <div class="card {{if .Stats.BackendHealthy}}up{{else}}down{{end}}"><div class="value">{{if .Stats.BackendHealthy}}UP{{else}}DOWN{{end}}</div><div class="label">Backend transport</div></div>
    <div class="card"><div class="value">{{.Stats.BackendErrorsTotal}}</div><div class="label">Backend transport errors</div></div>
    <div class="card"><div class="value">{{.Stats.ActiveSessions}}</div><div class="label">Active connections</div></div>
    <div class="card"><div class="value">{{.Stats.UniqueRemoteIPs}}</div><div class="label">Unique remote IPs</div></div>
    <div class="card"><div class="value">{{.Stats.TotalShares}}</div><div class="label">Total shares (connected sessions)</div></div>
    <div class="card"><div class="value">{{.Stats.TotalBlocks}}</div><div class="label">Total blocks (connected sessions)</div></div>
    <div class="card"><div class="value">{{.Stats.MinDifficulty}} / {{.Stats.MedianDifficulty}} / {{.Stats.MaxDifficulty}}</div><div class="label">Vardiff min / median / max</div></div>
    <div class="card"><div class="value">{{formatHashrate .Stats.TotalEstimatedHashrate}}</div><div class="label">Global hashrate</div></div>
  </div>

  <h2>Backend transport health</h2>
  <table>
    <tr><th>Last known outcome</th><th>Cumulative errors</th><th>Last error/success kind</th><th>Last checked</th></tr>
    <tr>
      <td>{{if .Stats.BackendHealthy}}OK{{else}}FAILING{{end}}</td>
      <td>{{.Stats.BackendErrorsTotal}}</td>
      <td>{{if .Stats.BackendLastErrorKind}}{{.Stats.BackendLastErrorKind}}{{else}}<span class="empty">(no backend calls yet)</span>{{end}}</td>
      <td>{{if .Stats.BackendLastCheckedAt.IsZero}}<span class="empty">never</span>{{else}}{{formatTime .Stats.BackendLastCheckedAt}}{{end}}</td>
    </tr>
  </table>

  <h2>Miners by address{{if .AddressCapped}} (capped to {{.MaxAddressLabels}}, overflow in "other"){{end}}</h2>
  {{if .Stats.MinersByAddress}}
  <table>
    <tr><th>Address</th><th>Connected sessions</th></tr>
    {{range .Stats.MinersByAddress}}
    <tr{{if eq .Address "other"}} class="other"{{end}}><td>{{.Address}}</td><td>{{.Count}}</td></tr>
    {{end}}
  </table>
  {{else}}
  <p class="empty">No logged-in sessions yet.</p>
  {{end}}

  <h2>Connected sessions</h2>
  {{if .Stats.Sessions}}
  <table>
    <tr><th>Session ID</th><th>Address</th><th>Worker</th><th>Agent</th>{{if not $.HideRemoteAddress}}<th>Remote address</th>{{end}}<th>Connected</th><th>Uptime</th><th>Difficulty</th><th>Est. hashrate</th><th>Shares</th><th>Blocks</th></tr>
    {{range .Stats.Sessions}}
    <tr>
      <td>{{.SessionID}}</td>
      <td>{{if .Address}}{{.Address}}{{else}}<span class="empty">(not logged in)</span>{{end}}</td>
      <td>{{.Worker}}</td>
      <td>{{if .Agent}}{{.Agent}}{{else}}<span class="empty">(unknown)</span>{{end}}</td>
      {{if not $.HideRemoteAddress}}<td>{{.RemoteAddr}}</td>{{end}}
      <td>{{formatTime .ConnectedAt}}</td>
      <td>{{connDuration .ConnectedAt}}</td>
      <td>{{.CurrentDifficulty}}</td>
      <td>{{formatHashrate .EstimatedHashrate}}</td>
      <td>{{.ShareCount}}</td>
      <td>{{.BlockCount}}</td>
    </tr>
    {{end}}
  </table>
  {{else}}
  <p class="empty">No active connections.</p>
  {{end}}
</body>
</html>
`

// statsPageData is the template's root data value.
type statsPageData struct {
	GeneratedAt      string
	Stats            Stats
	MaxAddressLabels int
	AddressCapped    bool
	// HideRemoteAddress mirrors internal/leaflib/solo/statsui.go's
	// identical field exactly — see that doc comment.
	HideRemoteAddress bool
}

// formatHashrate mirrors solo/statsui.go's own formatHashrate exactly.
func formatHashrate(hz float64) string {
	if hz <= 0 {
		return "0 H/s"
	}
	units := []string{"H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s"}
	i := 0
	for hz >= 1000 && i < len(units)-1 {
		hz /= 1000
		i++
	}
	return fmt.Sprintf("%.2f %s", hz, units[i])
}

// StatsHTMLHandler serves the basic stats UI page described above,
// rendered fresh from Stats() on every request — no caching, no
// client-side JS, mirrors internal/leaflib/solo/statsui.go's and
// internal/leaflib/proxy/statsui.go's StatsHTMLHandler exactly.
func (s *Server) StatsHTMLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := s.Stats()
		data := statsPageData{
			GeneratedAt:       time.Now().UTC().Format(time.RFC3339),
			Stats:             st,
			MaxAddressLabels:  s.maxAddressLabels,
			AddressCapped:     len(st.MinersByAddress) > 0 && st.MinersByAddress[len(st.MinersByAddress)-1].Address == "other",
			HideRemoteAddress: s.hideRemoteAddress.Load(),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := statsPageTemplate.Execute(w, data); err != nil {
			http.Error(w, fmt.Sprintf("failed to render stats page: %v", err), http.StatusInternalServerError)
		}
	})
}
