// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"fmt"
	"html/template"
	"net/http"
	"time"
)

// statsPageTemplate is the basic, single-page stats UI for
// leaf-proxy — mirrors internal/leaflib/solo/statsui.go's
// statsPageTemplate exactly (same "no JS framework, no client-side
// polling" scope), plus a small upstream-connection-health block
// leaf-solo has no analogue for (leaf-proxy has exactly one upstream
// pool connection whose health is worth surfacing here).
var statsPageTemplate = template.Must(template.New("proxy-stats").Funcs(template.FuncMap{
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
<title>leaf-proxy stats</title>
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
  <h1>leaf-proxy stats</h1>
  <div class="generated">generated {{.GeneratedAt}}</div>

  <div class="cards">
    <div class="card {{if .Stats.UpstreamConnected}}up{{else}}down{{end}}"><div class="value">{{if .Stats.UpstreamConnected}}UP{{else}}DOWN{{end}}</div><div class="label">Upstream pool connection</div></div>
    <div class="card"><div class="value">{{.Stats.UpstreamReconnects}}</div><div class="label">Upstream reconnects</div></div>
    <div class="card"><div class="value">{{.Stats.ActiveSessions}}</div><div class="label">Active downstream connections</div></div>
    <div class="card"><div class="value">{{.Stats.UniqueRemoteIPs}}</div><div class="label">Unique remote IPs</div></div>
    <div class="card"><div class="value">{{.Stats.TotalShares}}</div><div class="label">Total shares (connected sessions)</div></div>
    <div class="card"><div class="value">{{.Stats.TotalBlocks}}</div><div class="label">Total upstream-forwarded (connected sessions)</div></div>
    <div class="card"><div class="value">{{.Stats.MinDifficulty}} / {{.Stats.MedianDifficulty}} / {{.Stats.MaxDifficulty}}</div><div class="label">Vardiff min / median / max</div></div>
    <div class="card" title="Includes locally-credited shares below the upstream pool's requested difficulty, which are accepted on the miner's own self-claimed hash with no cryptographic re-validation -- see internal/leaflib/proxy/server.go's SessionStat.EstimatedHashrate doc comment (FIX_BRIEF.md, finding #16). Treat as an approximate, miner-spoofable indicator, not an authoritative measurement."><div class="value">{{formatHashrate .Stats.TotalEstimatedHashrate}}</div><div class="label">Global hashrate*</div></div>
  </div>
  <p class="empty">* Global hashrate includes locally-credited (unvalidated, self-reported) shares below the upstream pool's own requested difficulty -- see this leaf's own docs for the full caveat.</p>

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
    <tr><th>Session ID</th><th>Address</th><th>Worker</th><th>Port</th>{{if not $.HideRemoteAddress}}<th>Remote address</th>{{end}}<th>Connected</th><th>Uptime</th><th>Difficulty</th><th>Est. hashrate</th><th>Shares</th><th>Upstream-forwarded</th></tr>
    {{range .Stats.Sessions}}
    <tr>
      <td>{{.SessionID}}</td>
      <td>{{if .Address}}{{.Address}}{{else}}<span class="empty">(not logged in)</span>{{end}}</td>
      <td>{{.Worker}}</td>
      <td>{{.Port}}</td>
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

// formatHashrate renders a hashes/second estimate (see
// leaflib.EstimateHashrateHz's doc comment for the underlying
// formula) as a short, human-readable string with the standard
// SI-ish H/s unit prefixes (H, KH, MH, GH, TH, PH per 1000), matching
// the convention nearly every real mining pool stats page uses --
// a small local copy of solo/statsui.go's own formatHashrate
// (deliberately not shared/refactored into a common helper, per this
// package's convention of keeping a minimal, fully-contained
// footprint rather than introducing a cross-leaf dependency for one
// small formatting function).
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
// client-side JS, mirrors internal/leaflib/solo/statsui.go's
// StatsHTMLHandler exactly.
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
