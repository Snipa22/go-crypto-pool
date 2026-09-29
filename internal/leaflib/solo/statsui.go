// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"fmt"
	"html/template"
	"net/http"
	"time"
)

// DefaultStatsPageMaxSessions is the default -stats-page-max-sessions/
// LEAF_SOLO_STATS_PAGE_MAX_SESSIONS cap on how many SessionStat rows
// the stats HTML page's "Connected sessions" table renders by
// default -- picked as a reasonable midpoint of Alex's requested
// 100-200 range (real production scale made the previous uncapped
// one-row-per-session table "way too much to see" as a default
// view). Does NOT affect Stats() itself, and does NOT affect
// Stats.ActiveSessions (the separate, already-correct, uncapped
// total count) -- see capSessionsForDisplay's own doc comment.
const DefaultStatsPageMaxSessions = 150

// capSessionsForDisplay truncates sessions (already sorted ascending
// by ConnectedAt, per Stats()'s own sortSessionsByConnectedAt call --
// oldest-connected session first) to at most max entries for
// rendering on the stats HTML page ONLY -- called exclusively from
// StatsHTMLHandler, right before building statsPageData. Stats()
// itself is deliberately left completely unchanged/uncapped: it is
// also used by tests and potentially other internal callers that may
// legitimately want the full list, so the cap must never leak into
// that method's own contract.
//
// max <= 0 means "no cap, render everything" (the explicit escape
// hatch for anyone who wants the old, uncapped behavior), mirroring
// this codebase's existing zero-disables convention.
//
// When max > 0 and there are more sessions than max, the FIRST max
// entries of the existing ascending-ConnectedAt order are kept --
// i.e. the longest-connected ("oldest") sessions are shown, not the
// most-recently-connected ones. This keeps the existing, already-
// documented sort order exactly as-is rather than inventing a new
// one.
func capSessionsForDisplay(sessions []SessionStat, max int) (shown []SessionStat, truncated bool) {
	if max <= 0 || len(sessions) <= max {
		return sessions, false
	}
	return sessions[:max], true
}

// statsPageTemplate is the basic, single-page stats UI requested: no
// JS framework, no client-side polling — a plain server-rendered
// html/template page showing active connection count, per-address
// miner counts (respecting the same cardinality cap as
// leaf_miners_by_address), recent share/block counts, and the current
// vardiff difficulty distribution (min/max/median). Deliberately not a
// dashboard: a single readable page, matching the maintainer's own
// "basic" framing.
var statsPageTemplate = template.Must(template.New("solo-stats").Funcs(template.FuncMap{
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
<title>leaf-solo stats</title>
<style>
  body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }
  h1 { margin-bottom: 0.25rem; }
  .generated { color: #666; font-size: 0.85rem; margin-bottom: 1.5rem; }
  .cards { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .card { background: #fff; border: 1px solid #ddd; border-radius: 6px; padding: 1rem 1.5rem; min-width: 160px; }
  .card .value { font-size: 1.8rem; font-weight: 600; }
  .card .label { color: #666; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }
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
  <h1>leaf-solo stats</h1>
  <div class="generated">generated {{.GeneratedAt}}</div>

  <div class="cards">
    <div class="card"><div class="value">{{.Stats.ActiveSessions}}</div><div class="label">Active connections</div></div>
    <div class="card"><div class="value">{{.Stats.UniqueRemoteIPs}}</div><div class="label">Unique remote IPs</div></div>
    <div class="card"><div class="value">{{.Stats.TotalShares}}</div><div class="label">Total shares (connected sessions)</div></div>
    <div class="card"><div class="value">{{.Stats.TotalBlocks}}</div><div class="label">Total blocks (connected sessions)</div></div>
    <div class="card"><div class="value">{{.Stats.MinDifficulty}} / {{.Stats.MedianDifficulty}} / {{.Stats.MaxDifficulty}}</div><div class="label">Vardiff min / median / max</div></div>
    <div class="card"><div class="value">{{formatHashrate .Stats.TotalEstimatedHashrate}}</div><div class="label">Global hashrate</div></div>
  </div>

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

  <h2>Connected sessions{{if .SessionsCapped}} (showing {{len .ShownSessions}} of {{.Stats.ActiveSessions}}, capped to {{.StatsPageMaxSessions}}){{end}}</h2>
  {{if .ShownSessions}}
  <table>
    <tr><th>Session ID</th><th>Address</th><th>Worker</th><th>Agent</th>{{if not $.HideRemoteAddress}}<th>Remote address</th>{{end}}<th>Connected</th><th>Uptime</th><th>Difficulty</th><th>Est. hashrate</th><th>Shares</th><th>Blocks</th><th>Relogins</th></tr>
    {{range .ShownSessions}}
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
      <td>{{.Relogins}}</td>
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
	// HideRemoteAddress, when true, omits the "Remote address"
	// column (both header and per-session value) from the rendered
	// stats page entirely -- set from Server.hideRemoteAddress (see
	// SetHideRemoteAddress) so public-facing deployments can avoid
	// exposing remote miner IPs on a page anyone can load. Rendering
	// nothing at all is deliberately preferred over rendering an
	// empty value: a header with no data looks like a bug, not a
	// privacy control.
	HideRemoteAddress bool

	// ShownSessions is the (possibly truncated) subset of
	// Stats.Sessions actually rendered in the "Connected sessions"
	// table -- see capSessionsForDisplay's doc comment. Deliberately
	// a separate field from Stats.Sessions rather than mutating it:
	// Stats is the exact, unmodified return value of Stats().
	ShownSessions []SessionStat
	// StatsPageMaxSessions is the configured -stats-page-max-sessions
	// cap (mirrors MaxAddressLabels's naming/role for the address
	// cap above).
	StatsPageMaxSessions int
	// SessionsCapped is true only when Stats.Sessions actually had
	// to be truncated to produce ShownSessions -- mirrors
	// AddressCapped's own "false when not actually capped" contract
	// exactly.
	SessionsCapped bool
}

// formatHashrate renders a hashes/second estimate (see
// leaflib.EstimateHashrateHz's doc comment for the underlying
// formula) as a short, human-readable string with the standard
// SI-ish H/s unit prefixes (H, KH, MH, GH, TH, PH per 1000), matching
// the convention nearly every real mining pool stats page uses.
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
// client-side JS, matching the "basic" first-pass scope requested.
func (s *Server) StatsHTMLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := s.Stats()
		shown, truncated := capSessionsForDisplay(st.Sessions, s.statsPageMaxSessions)
		data := statsPageData{
			GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
			Stats:                st,
			MaxAddressLabels:     s.maxAddressLabels,
			AddressCapped:        len(st.MinersByAddress) > 0 && st.MinersByAddress[len(st.MinersByAddress)-1].Address == "other",
			HideRemoteAddress:    s.hideRemoteAddress.Load(),
			ShownSessions:        shown,
			StatsPageMaxSessions: s.statsPageMaxSessions,
			SessionsCapped:       truncated,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := statsPageTemplate.Execute(w, data); err != nil {
			http.Error(w, fmt.Sprintf("failed to render stats page: %v", err), http.StatusInternalServerError)
		}
	})
}
