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

  <h2>Connected sessions</h2>
  {{if .Stats.Sessions}}
  <table>
    <tr><th>Session ID</th><th>Address</th><th>Worker</th><th>Remote address</th><th>Connected</th><th>Uptime</th><th>Difficulty</th><th>Shares</th><th>Upstream-forwarded</th></tr>
    {{range .Stats.Sessions}}
    <tr>
      <td>{{.SessionID}}</td>
      <td>{{if .Address}}{{.Address}}{{else}}<span class="empty">(not logged in)</span>{{end}}</td>
      <td>{{.Worker}}</td>
      <td>{{.RemoteAddr}}</td>
      <td>{{formatTime .ConnectedAt}}</td>
      <td>{{connDuration .ConnectedAt}}</td>
      <td>{{.CurrentDifficulty}}</td>
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
}

// StatsHTMLHandler serves the basic stats UI page described above,
// rendered fresh from Stats() on every request — no caching, no
// client-side JS, mirrors internal/leaflib/solo/statsui.go's
// StatsHTMLHandler exactly.
func (s *Server) StatsHTMLHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := s.Stats()
		data := statsPageData{
			GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
			Stats:            st,
			MaxAddressLabels: s.maxAddressLabels,
			AddressCapped:    len(st.MinersByAddress) > 0 && st.MinersByAddress[len(st.MinersByAddress)-1].Address == "other",
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := statsPageTemplate.Execute(w, data); err != nil {
			http.Error(w, fmt.Sprintf("failed to render stats page: %v", err), http.StatusInternalServerError)
		}
	})
}
