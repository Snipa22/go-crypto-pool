// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

// DefaultStatsPageMaxSessions is the default -stats-page-max-sessions/
// LEAF_PROXY_STATS_PAGE_MAX_SESSIONS cap on how many SessionStat rows
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
<script>
  // Applied as early as possible (before first paint) to avoid a
  // light-then-dark flash on reload -- see DISPATCH_BRIEF_ADDENDUM_
  // DARKMODE.md section 1. Default (no stored preference yet) stays
  // the existing light palette -- opt-in only, never a surprise
  // behavior change for an operator who never touches the toggle.
  (function() {
    if (localStorage.getItem('leaf-proxy-stats-theme') === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  })();
</script>
<style>
  body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem; color: #1a1a1a; background: #fafafa; }
  h1 { margin-bottom: 0.25rem; }
  .generated { color: #666; font-size: 0.85rem; margin-bottom: 1.5rem; }
  .controls { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; font-size: 0.85rem; }
  .controls label { color: #666; }
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

  html[data-theme="dark"] body { color: #e0e0e0; background: #121212; }
  html[data-theme="dark"] .generated { color: #aaa; }
  html[data-theme="dark"] .controls label { color: #aaa; }
  html[data-theme="dark"] .card { background: #1a1a1a; border-color: #444; }
  html[data-theme="dark"] .card .label { color: #aaa; }
  html[data-theme="dark"] .card.up .value { color: #4caf50; }
  html[data-theme="dark"] .card.down .value { color: #ff5c5c; }
  html[data-theme="dark"] table { background: #1a1a1a; }
  html[data-theme="dark"] th, html[data-theme="dark"] td { border-color: #444; }
  html[data-theme="dark"] th { background: #262626; }
  html[data-theme="dark"] tr:nth-child(even) { background: #202020; }
  html[data-theme="dark"] .empty { color: #888; }
  html[data-theme="dark"] .other { color: #888; }
  html[data-theme="dark"] select, html[data-theme="dark"] button { background: #1a1a1a; color: #e0e0e0; border: 1px solid #444; }
</style>
</head>
<body>
  <h1>leaf-proxy stats</h1>
  <div class="generated">generated {{.GeneratedAt}}</div>

  <div class="controls">
    <button type="button" id="theme-toggle" onclick="leafProxyToggleTheme()">Toggle dark mode</button>
    <label for="refresh-select">Auto-refresh:
      <select id="refresh-select" onchange="leafProxySetRefresh(this.value)">
        <option value="0">Off</option>
        <option value="5000">5s</option>
        <option value="10000">10s</option>
        <option value="30000">30s</option>
        <option value="60000">60s</option>
      </select>
    </label>
  </div>

  <script>
    function leafProxyToggleTheme() {
      var isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      if (isDark) {
        document.documentElement.removeAttribute('data-theme');
        localStorage.setItem('leaf-proxy-stats-theme', 'light');
      } else {
        document.documentElement.setAttribute('data-theme', 'dark');
        localStorage.setItem('leaf-proxy-stats-theme', 'dark');
      }
    }

    function leafProxySetRefresh(ms) {
      localStorage.setItem('leaf-proxy-stats-refresh-ms', ms);
    }

    (function() {
      // Default (10000ms / 10s) matches today's existing hardcoded
      // <meta http-equiv="refresh" content="10"> behavior exactly
      // when an operator has never touched the control -- see
      // DISPATCH_BRIEF_ADDENDUM_DARKMODE.md section 2.
      var stored = localStorage.getItem('leaf-proxy-stats-refresh-ms');
      var intervalMs = stored === null ? 10000 : parseInt(stored, 10);
      if (isNaN(intervalMs)) {
        intervalMs = 10000;
      }
      var select = document.getElementById('refresh-select');
      if (select) {
        select.value = String(intervalMs);
      }
      scheduleRefresh();

      function scheduleRefresh() {
        // Re-read the stored value at schedule-time (not only once
        // at the top of this script) so selecting "Off" on THIS page
        // load correctly prevents the already-scheduled timer, per
        // the addendum's explicit requirement.
        var current = localStorage.getItem('leaf-proxy-stats-refresh-ms');
        var ms = current === null ? 10000 : parseInt(current, 10);
        if (isNaN(ms) || ms <= 0) {
          return;
        }
        setTimeout(function() {
          var latest = localStorage.getItem('leaf-proxy-stats-refresh-ms');
          var latestMs = latest === null ? 10000 : parseInt(latest, 10);
          if (isNaN(latestMs) || latestMs <= 0) {
            return;
          }
          location.reload();
        }, ms);
      }
    })();
  </script>

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

  <h2>Connected sessions{{if .SessionsCapped}} (showing {{len .ShownSessions}} of {{.Stats.ActiveSessions}}, capped to {{.StatsPageMaxSessions}}){{end}}</h2>
  {{if .ShownSessions}}
  <table>
    <tr><th>Session ID</th><th>Address</th><th>Worker</th><th>Port</th>{{if not $.HideRemoteAddress}}<th>Remote address</th>{{end}}<th>Connected</th><th>Uptime</th><th>Difficulty</th><th>Est. hashrate</th><th>Shares</th><th>Upstream-forwarded</th><th>Relogins</th></tr>
    {{range .ShownSessions}}
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
	// HideRemoteAddress mirrors internal/leaflib/solo/statsui.go's
	// identical field exactly — see that doc comment.
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

// HashrateReportSummary renders a single, xmrig-proxy/xnp-style
// foreground summary line from a fresh Stats() snapshot (DISPATCH_
// BRIEF.md "leaf-proxy ... foreground hashrate", Alex's ask:
// "hashrate shows in proxy side foreground mode like xmrig-proxy or
// xnp") -- e.g.
// "hashrate: total=12.34 MH/s sessions=7 shares=142 upstream_forwarded=3".
// Reuses formatHashrate (above) for the human-readable unit
// formatting rather than re-implementing it, per the brief's own
// explicit instruction. cmd/leaf-proxy/main.go's own periodic
// ticker is the intended (and, today, only) caller: a fixed,
// unconditional, always-on 30-second ticker with no disable/
// reconfigure flag at all (DISPATCH_BRIEF_HASHRATE_API_FOLLOWUP.md
// section 1, Alex's own ask verbatim: "show it at all log levels,
// make it a 30 second print no matter what"). That caller logs this
// string via the raw *log.Logger's Printf directly -- deliberately
// NOT the leveled debugLogger.Logf/Debugf gate -- so it is printed
// unconditionally at EVERY -log-level, including -log-level=0
// (quiet). This is an intentional, permanent exception to this
// leaf's usual "quiet means quiet" noise-gating; do not "fix" it by
// routing it back through a level check.
func (s *Server) HashrateReportSummary() string {
	st := s.Stats()
	return fmt.Sprintf("hashrate: total=%s sessions=%d shares=%d upstream_forwarded=%d",
		formatHashrate(st.TotalEstimatedHashrate), st.ActiveSessions, st.TotalShares, st.TotalBlocks)
}

// MinersAPIOverview is the "overview" object of the GET /api/miners
// JSON response (DISPATCH_BRIEF.md "leaf-proxy ... miner-stats API"),
// built from the exact same Stats() snapshot StatsHTMLHandler's stat
// cards already use -- deliberately "the same data, JSON-shaped", not
// a new stats-collection mechanism.
type MinersAPIOverview struct {
	UpstreamConnected  bool    `json:"upstream_connected"`
	UpstreamReconnects uint64  `json:"upstream_reconnects"`
	ActiveSessions     int     `json:"active_sessions"`
	UniqueRemoteIPs    int     `json:"unique_remote_ips"`
	TotalShares        uint64  `json:"total_shares"`
	TotalBlocks        uint64  `json:"total_blocks"`
	GlobalHashrateHz   float64 `json:"global_hashrate_hz"`
}

// MinerAPIEntry is one connected session's entry in the GET
// /api/miners JSON response's "miners" array -- field-for-field the
// same data SessionStat already carries (see that type's doc
// comment, including its FIX_BRIEF.md finding #16
// miner-spoofability caveat for EstimatedHashrateHz/ShareCount below
// a below-upstream-target share), JSON-shaped instead of HTML-row-
// shaped. RemoteAddr uses `omitempty` AND is only ever populated when
// s.hideRemoteAddress is false (MinersJSONHandler below) -- when
// hidden, the key is genuinely ABSENT from the marshaled JSON, not
// merely empty-stringed, mirroring StatsHTMLHandler's own "omit the
// column entirely" behavior for the HTML table.
type MinerAPIEntry struct {
	SessionID              string  `json:"session_id"`
	Address                string  `json:"address"`
	Worker                 string  `json:"worker"`
	Port                   string  `json:"port"`
	RemoteAddr             string  `json:"remote_addr,omitempty"`
	ConnectedAt            string  `json:"connected_at"`
	UptimeSeconds          int64   `json:"uptime_seconds"`
	Difficulty             uint64  `json:"difficulty"`
	EstimatedHashrateHz    float64 `json:"estimated_hashrate_hz"`
	ShareCount             uint64  `json:"share_count"`
	UpstreamForwardedCount uint64  `json:"upstream_forwarded_count"`
}

// MinersAPIResponse is the full GET /api/miners JSON response body.
// Miners is deliberately the FULL, uncapped set of currently-
// connected sessions -- see MinersJSONHandler's doc comment for the
// permanent, by-design guarantee this field carries (DISPATCH_
// BRIEF_HASHRATE_API_FOLLOWUP.md section 2).
type MinersAPIResponse struct {
	GeneratedAt string            `json:"generated_at"`
	Overview    MinersAPIOverview `json:"overview"`
	Miners      []MinerAPIEntry   `json:"miners"`
}

// MinersJSONHandler serves GET /api/miners: the same Stats() snapshot
// StatsHTMLHandler already renders as HTML, JSON-shaped instead
// (DISPATCH_BRIEF.md "leaf-proxy ... miner-stats API" -- Alex's ask:
// "API for miner stats - The metrics panel is semi-limited in this,
// though it's fine for normal stats for the proxy (Overall/live
// view)"). Intended registration: the SAME metricsMux /metrics and /
// are already registered on (cmd/leaf-proxy/main.go), so section 1's
// optional HTTP Basic Auth gate (metricsauth.go), once a password is
// configured, covers this route too.
//
// Provably, PERMANENTLY uncapped by design (DISPATCH_BRIEF_HASHRATE_
// API_FOLLOWUP.md section 2, Alex's own framing: "lets make sure
// /api/miners shows /all/ miners, the main stats page tends to
// suppress some data"): this handler builds its "miners" array from
// the raw st.Sessions returned by Stats() -- it deliberately does
// NOT apply capSessionsForDisplay's session cap (StatsHTMLHandler's
// ShownSessions truncation for a calm default HTML view) and does
// NOT expose CapAddressCounts's address-cardinality cap
// (st.MinersByAddress's "other"-bucket aggregation) in any form at
// all -- there is no address-cardinality concept in this response
// whatsoever, every connected session is listed individually by its
// own address. This is the "full/comprehensive" counterpart to the
// HTML stats page's deliberately-summarized default view, not an
// accident of how Stats() happens to be wired today. See
// miners_api_test.go's regression test, which is the real guardrail
// against a future "let's just reuse ShownSessions here for
// consistency" edit accidentally reintroducing a cap -- this comment
// is only here to make the intent impossible to miss.
func (s *Server) MinersJSONHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st := s.Stats()
		hideRemote := s.hideRemoteAddress.Load()

		miners := make([]MinerAPIEntry, 0, len(st.Sessions))
		for _, sess := range st.Sessions {
			entry := MinerAPIEntry{
				SessionID:              sess.SessionID,
				Address:                sess.Address,
				Worker:                 sess.Worker,
				Port:                   sess.Port,
				ConnectedAt:            sess.ConnectedAt.UTC().Format(time.RFC3339),
				UptimeSeconds:          int64(time.Since(sess.ConnectedAt).Round(time.Second).Seconds()),
				Difficulty:             sess.CurrentDifficulty,
				EstimatedHashrateHz:    sess.EstimatedHashrate,
				ShareCount:             sess.ShareCount,
				UpstreamForwardedCount: sess.BlockCount,
			}
			if !hideRemote {
				entry.RemoteAddr = sess.RemoteAddr
			}
			miners = append(miners, entry)
		}

		resp := MinersAPIResponse{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Overview: MinersAPIOverview{
				UpstreamConnected:  st.UpstreamConnected,
				UpstreamReconnects: st.UpstreamReconnects,
				ActiveSessions:     st.ActiveSessions,
				UniqueRemoteIPs:    st.UniqueRemoteIPs,
				TotalShares:        st.TotalShares,
				TotalBlocks:        st.TotalBlocks,
				GlobalHashrateHz:   st.TotalEstimatedHashrate,
			},
			Miners: miners,
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, fmt.Sprintf("failed to encode miners JSON: %v", err), http.StatusInternalServerError)
		}
	})
}
