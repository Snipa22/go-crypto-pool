// Copyright and license: see repository LICENSE (MIT).
package leaflib

import (
	"sync"
	"time"
)

// MinerIdentity captures, as ONE atomically-swappable unit, every
// piece of per-connection miner identity a leaf Session's handleLogin
// (solo/direct/proxy, each package's own session.go) previously stored
// as four SEPARATE atomic.Value fields (address/worker/agent/
// paymentID). Those four fields were mutated sequentially, not as one
// unit, so a concurrent reader on another goroutine (the periodic
// Stats()/Prometheus snapshot ticker, which reads the exact same
// fields) could observe a TORN READ mid-relogin: e.g. address already
// updated to a new login's value while worker/agent still held the
// previous login's values. Replacing the four fields with a single
// atomic.Value holding *MinerIdentity (swapped via one Store call in
// handleLogin) makes that torn-read impossible: any reader always sees
// either the complete old identity or the complete new one, never a
// mix.
//
// Extracted here (internal/leaflib), shared by all three leaf
// packages (solo/proxy/direct), mirroring the exact same sharing
// convention leaflib.VardiffConfig/leaflib.JobHistory already
// established for this repo's three structurally-parallel leaf
// flavors (see leaflib/vardiff.go's and wireshape.go's own doc
// comments) -- there is no import-cycle risk: solo/proxy/direct each
// already import leaflib (proxy/direct additionally import solo
// itself, but never the reverse), and leaflib imports none of them.
//
// PaymentID is documented on each package's own (former) paymentID
// field as "solo/proxy: captured for diagnostic parity only, no real
// downstream payout plumbing; direct: genuinely wired through to
// poolpb.Share.PaymentId" -- that distinction is a per-package
// consumption decision, not something this shared value type needs to
// encode itself.
type MinerIdentity struct {
	Address    string
	Worker     string
	Agent      string
	PaymentID  string
	LoggedInAt time.Time
}

// defaultLoginHistorySize mirrors every existing package's own
// defaultSessionJobHistorySize/defaultProxySessionJobHistorySize
// constant (8) -- see solo.Session's own doc comment (git history)
// for the full "why 8" rationale this reuses unchanged for the new
// login-identity history ring below.
const defaultLoginHistorySize = 8

// LoginHistory is a bounded, oldest-evicted-first, append-only ring of
// past MinerIdentity values -- the per-session login-history brief
// asks for (BRIEF.md part A.3): every time handleLogin runs on an
// already-logged-in session (a re-login, e.g. an xmrig-proxy
// `--reuse-timeout` connection-reuse slot rotation), the OLD identity
// being replaced is appended here before the new one is stored.
//
// DEVIATION FROM THE BRIEF'S OWN SUGGESTED MIRRORING: the brief asks
// this to "mirror the EXISTING jobList/jobLog bounded-history pattern"
// (leaflib.JobHistory). JobHistory is intentionally ID-KEYED (a
// job_id -> job map, existing purely to answer "did THIS session ever
// see this ID" for job-ownership SECURITY checks -- see its own doc
// comment). Login-identity history has no equivalent ownership/lookup
// question to answer -- it is a plain, order-preserving log of past
// identities for operator/log/stats visibility -- so a key-less,
// simpler bounded ring (this type) is used instead, sized identically
// (8, defaultLoginHistorySize) and evicting oldest-first exactly like
// JobHistory does. Noted here per the brief's own "say so in your
// commit if you deviate" instruction.
type LoginHistory struct {
	mu      sync.Mutex
	entries []MinerIdentity
	size    int
}

// NewLoginHistory constructs a LoginHistory bounded to size entries
// (defaultLoginHistorySize if size <= 0).
func NewLoginHistory(size int) *LoginHistory {
	if size <= 0 {
		size = defaultLoginHistorySize
	}
	return &LoginHistory{size: size}
}

// Append records identity as the newest entry, evicting the oldest
// entry once the bounded size is exceeded.
func (h *LoginHistory) Append(identity MinerIdentity) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.entries = append(h.entries, identity)
	size := h.size
	if size <= 0 {
		size = defaultLoginHistorySize
	}
	for len(h.entries) > size {
		h.entries = h.entries[1:]
	}
}

// Snapshot returns a copy of every currently-held entry, oldest
// first -- safe for the caller to read/range over without any
// further synchronization, and without risk of a subsequent Append
// mutating the caller's slice out from under it.
func (h *LoginHistory) Snapshot() []MinerIdentity {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]MinerIdentity, len(h.entries))
	copy(out, h.entries)
	return out
}

// Len reports how many entries are currently held (test/diagnostic/
// stats use).
func (h *LoginHistory) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.entries)
}
