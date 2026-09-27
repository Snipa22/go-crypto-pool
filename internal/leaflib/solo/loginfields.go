// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- REAL BUG FIX: login-field address/+diff/.paymentID/.identifier
// parsing ---
//
// Before this file existed, BOTH leaf-solo's and leaf-direct's
// handleLogin passed login.Login -- the RAW, UNSTRIPPED string exactly
// as the miner sent it -- straight into ValidateAddressForAlgo. That
// is wrong for the completely standard Monero-family stratum login
// convention every real xmrig/xmr-stak class miner supports:
//
//	// (verbatim from the real legacy source's own doc comment,
//	// nodejs-pool-sxmr lib/pool.js ~line 337-339)
//	// Username Layout - <address in BTC or XMR>.<Difficulty-via-worker-suffix, or identifier>
//	// Password Layout - <password>.<miner identifier>.<payment ID for XMR>
//
// A miner logging in as "<address>+50000" or "<address>.myrig" sent a
// string that is not a valid address on its own, so the real,
// byte-exact address validators (address.go's ValidateAddressForAlgo)
// correctly rejected it as malformed -- and the login was refused
// outright with "invalid address provided", locking out an entire,
// very common class of real miner from both leaf modes even though the
// address it actually supplied was perfectly valid and its requested
// fixed difficulty perfectly reasonable.
//
// ParseLoginFields below is a faithful port of the real legacy parse
// (pool.js's Miner constructor, ~line 386-422), with its exact
// clamping and precedence semantics; see that function's doc comment
// for the per-step citations and for the two deliberate, documented
// divergences (non-numeric "+" suffix handling, and the Monero-family
// scoping of the "." split).

// LegacyNiceHashDifficulty is the real, cited NiceHash fixed
// difficulty the legacy stack applies to any miner whose self-reported
// agent string contains "NiceHash":
// global.coinFuncs.niceHashDiff, whose real XMR value is 400000
// (nodejs-pool-sxmr lib/coins/xmr.js line 49:
// `this.niceHashDiff = 400000;`), consumed at pool.js line 392-395.
//
// SCOPED TO MONERO-FAMILY ALGOS ONLY (IsMoneroFamilyAlgo -- see
// ParseLoginFields). This constant is a per-coin value in the legacy
// stack (it lives on the coin module, not in shared pool code), and
// there is NO equivalent anywhere in this repo for Tari: neither
// internal/coinprofile.CoinProfile nor any other type carries a
// NiceHash-difficulty field, and a repo-wide search for "nicehash"
// (case-insensitive) matches nothing outside this file. NiceHash also
// does not operate a SHA3X/C29/RXT hashpower market at all, so there
// is no real value to port for Tari -- applying 400000 universally
// would be fabricating a constant for a coin the legacy source never
// defined one for.
const LegacyNiceHashDifficulty uint64 = 400000

// ErrTooManyLoginOptions is returned by ParseLoginFields when the
// login field contains more than one "+" separator -- the exact
// condition legacy rejects the login on (pool.js line 405-409:
// `this.error = "Too many options in the login field"; this.valid_miner
// = false; return;`). The message text is reproduced verbatim so
// operators grepping miner-facing errors see the same string they
// already know from the legacy stack.
var ErrTooManyLoginOptions = errors.New("Too many options in the login field")

// legacyHexMatch mirrors pool.js's own `hexMatch` regexp exactly
// (line 31: `let hexMatch = new RegExp("^[0-9a-f]+$");`) -- lowercase
// hex only, anchored at both ends. Used together with the exact
// length === 64 check at pool.js line 416 to decide whether a second
// dot-segment is a genuine Monero payment ID rather than a worker
// name.
var legacyHexMatch = regexp.MustCompile(`^[0-9a-f]+$`)

// LoginFields is the parsed result of one miner's raw stratum login
// field (plus its self-reported agent string) -- see ParseLoginFields.
type LoginFields struct {
	// Address is the STRIPPED payout address: the first "+"-segment
	// of the login field and (for Monero-family algos only) its first
	// "."-segment. This -- never the raw login string -- is what
	// callers must hand to ValidateAddressForAlgo.
	Address string

	// PaymentID is a genuine Monero payment ID: a second dot-segment
	// that is exactly 64 lowercase-hex characters (pool.js line 416).
	// Always empty for non-Monero-family algos (see ParseLoginFields'
	// scoping note). Empty when the miner supplied none.
	PaymentID string

	// Identifier is the miner-reported worker/rig name carried in a
	// dot-segment of the login field: either a non-64-hex second
	// segment (pool.js line 419-420) or a third segment (pool.js line
	// 421-423). Always empty for non-Monero-family algos. Empty when
	// the miner supplied none.
	//
	// NOTE: this is only a CANDIDATE worker name. The legacy
	// precedence rule is that the password field's own identifier wins
	// unless it is literally "x" (`pass_split[0] === "x" ?
	// addressSplit[N] : pass_split[0]`), and applying that precedence
	// is the caller's job -- it owns the real password/rigid fields
	// (see handleLogin in both leaf modes).
	Identifier string

	// FixedDiff reports whether this login requested (or was assigned)
	// a FIXED difficulty -- legacy's `this.fixed_diff` (pool.js lines
	// 389/393/403). True for a valid 2-part "+" split, and for a
	// NiceHash agent on a Monero-family algo. A fixed-difficulty
	// session's vardiff retarget loop must be skipped entirely for the
	// lifetime of that session, exactly as legacy's own retargetMiners
	// does (pool.js line 227-236 -- see vardiff.go's maybeRetarget in
	// both leaf modes).
	FixedDiff bool

	// FixedDiffFromLoginSuffix reports WHICH of the two real legacy
	// mechanisms set FixedDiff above: true when it came from the login
	// field's own "+<difficulty>" suffix (pool.js lines 402-411),
	// false when FixedDiff came ONLY from a NiceHash agent string
	// (pool.js lines 392-395). Always false when FixedDiff is false.
	//
	// The two are deliberately distinguishable because exactly one of
	// them is exempted for XNP-proxy sessions -- see
	// XNPProxyExemptFromFixedDiffPin below for the full rationale and
	// the cited legacy `proxyAddressList` escape hatch it implements.
	// A login carrying BOTH (a NiceHash agent AND a "+" suffix) counts
	// as suffix-driven, because the suffix's value is what actually
	// won: legacy's own ordering has the "+" split overwrite the
	// NiceHash default (see the switch below, ordering preserved
	// verbatim), so the resulting pin is the suffix's pin.
	FixedDiffFromLoginSuffix bool

	// Difficulty is the session's resulting STARTING difficulty. It is
	// the startingDiff passed in unless FixedDiff is true, in which
	// case it is the requested fixed value (clamped to
	// [minDiff,maxDiff] for the "+"-split case, exactly as legacy
	// clamps to global.config.pool.minDifficulty/maxDifficulty at
	// pool.js lines 404-411).
	Difficulty uint64
}

// ParseLoginFields is a faithful port of the real legacy login-field
// parse (nodejs-pool-sxmr lib/pool.js, Miner constructor, lines
// 386-423), reproduced here verbatim for citation:
//
//	let diffSplit = login.split("+");
//	let addressSplit = diffSplit[0].split(".");
//	this.address = addressSplit[0];
//	this.payout = addressSplit[0];
//	this.fixed_diff = false;
//	this.difficulty = startingDiff;
//	if (agent && agent.includes("NiceHash")) {
//	    this.fixed_diff = true;
//	    this.difficulty = global.coinFuncs.niceHashDiff;
//	}
//	if (diffSplit.length === 2) {
//	    this.fixed_diff = true;
//	    this.difficulty = Number(diffSplit[1]);
//	    if (this.difficulty < global.config.pool.minDifficulty) { this.difficulty = global.config.pool.minDifficulty; }
//	    if (this.difficulty > global.config.pool.maxDifficulty) { this.difficulty = global.config.pool.maxDifficulty; }
//	} else if (diffSplit.length > 2) {
//	    this.error = "Too many options in the login field";
//	    this.valid_miner = false;
//	    return;
//	}
//	if (typeof(addressSplit[1]) !== "undefined" && addressSplit[1].length === 64 && hexMatch.test(addressSplit[1])) {
//	    this.paymentID = addressSplit[1];
//	    this.payout = this.address + "." + this.paymentID;
//	} else if (typeof(addressSplit[1]) !== "undefined") {
//	    this.identifier = pass_split[0] === "x" ? addressSplit[1] : pass_split[0];
//	}
//	if (typeof(addressSplit[2]) !== "undefined") {
//	    this.identifier = pass_split[0] === "x" ? addressSplit[2] : pass_split[0];
//	}
//
// SCOPING DECISIONS (each stated explicitly, with the reasoning behind
// it):
//
//  1. The "+" fixed-difficulty split is applied UNIVERSALLY, for every
//     algo. It is algo-agnostic by construction (a difficulty is a
//     difficulty) and harmless for Tari: none of the three real Tari
//     address encodings go-tari-lib/address.Parse accepts (emoji,
//     base58, hex) can contain a literal "+", so a "+" in a Tari login
//     field is unambiguously a suffix, never part of the address.
//
//  2. The "." payment-ID/identifier split is gated to Monero-family
//     algos only (IsMoneroFamilyAlgo -- poolpb.Algo_ALGO_RXM plus
//     every confirmed internal/coinprofile.Registry coin), matching
//     the legacy reference's own Monero-only scope. FINDING behind
//     that decision: nothing in this repo has ever handled a
//     dot-suffixed payment-ID-bearing login address, for ANY algo.
//     address.go's ValidateAddressForAlgo hands the whole string to a
//     byte-exact decoder; on the Monero side that decoder
//     (go-xmr-lib/support.IsValidMainnet) accepts the INTEGRATED
//     address network tag 0x12 -- i.e. a payment ID embedded inside
//     the address itself -- but nothing anywhere parses the separate
//     "<address>.<paymentid>" convention; and coinprofile.ValidateAddress
//     explicitly documents that it checks ONLY the mainnet
//     standard-address prefix and deliberately does NOT accept
//     integrated-address prefixes at all (see that function's doc
//     comment). On the Tari side there is no payment-ID concept in the
//     address format whatsoever, and (as in point 1) no Tari encoding
//     can contain a ".". So there is no existing non-Monero behavior
//     to be consistent with, and extending the "." split beyond
//     Monero-family would be inventing a convention rather than
//     porting one.
//
//  3. The NiceHash fixed-difficulty default is likewise Monero-family
//     only -- see LegacyNiceHashDifficulty's doc comment for the full
//     "no Tari equivalent exists anywhere" finding.
//
// DELIBERATE DIVERGENCES FROM THE LEGACY SOURCE (both documented
// rather than silently "improved"):
//
//   - A non-numeric "+" suffix is REJECTED with a clear error instead
//     of being silently accepted. Legacy's `Number(diffSplit[1])`
//     yields NaN for e.g. "addr+abc", and every subsequent comparison
//     against NaN is false, so legacy leaves the miner's difficulty as
//     NaN and carries on with a structurally broken session. That is a
//     legacy bug, not a behavior worth porting; a negative value, by
//     contrast, IS ported faithfully (legacy clamps it up to
//     minDifficulty, and so does this).
//   - An out-of-int64-range numeric suffix is clamped to maxDiff
//     rather than erroring (strconv.ParseInt already saturates, and
//     the clamp legacy applies covers it) -- same observable outcome
//     as legacy's float64 Number() path for any absurdly large value.
//
// minDiff/maxDiff are this leaf's OWN already-configured
// -min-difficulty/-max-difficulty values, reached via the (already
// Normalized) VardiffConfig on each leaf's Server
// (s.server.vardiff.MinDifficulty/MaxDifficulty) -- the same absolute
// bounds vardiff.go's own retarget is clamped to, which is exactly
// what legacy's global.config.pool.minDifficulty/maxDifficulty are
// used for too.
func ParseLoginFields(algo poolpb.Algo, login, agent string, startingDiff, minDiff, maxDiff uint64) (LoginFields, error) {
	out := LoginFields{Difficulty: startingDiff}

	diffSplit := strings.Split(login, "+")
	out.Address = diffSplit[0]

	moneroFamily := IsMoneroFamilyAlgo(algo)

	// pool.js line 392-395: a NiceHash agent gets a fixed difficulty
	// BEFORE the "+"-split is consulted, so an explicit "+"-requested
	// difficulty still overrides it (and gets clamped) below --
	// ordering preserved exactly.
	if moneroFamily && strings.Contains(agent, "NiceHash") {
		out.FixedDiff = true
		out.Difficulty = LegacyNiceHashDifficulty
	}

	switch {
	case len(diffSplit) == 2:
		requested, err := parseLegacyFixedDifficulty(diffSplit[1])
		if err != nil {
			return LoginFields{}, err
		}
		out.FixedDiff = true
		out.FixedDiffFromLoginSuffix = true
		out.Difficulty = clampDifficulty(requested, minDiff, maxDiff)
	case len(diffSplit) > 2:
		return LoginFields{}, ErrTooManyLoginOptions
	}

	if moneroFamily {
		addressSplit := strings.Split(diffSplit[0], ".")
		out.Address = addressSplit[0]
		if len(addressSplit) > 1 {
			if isLegacyPaymentID(addressSplit[1]) {
				out.PaymentID = addressSplit[1]
			} else {
				out.Identifier = addressSplit[1]
			}
		}
		// pool.js line 421-423: a THIRD dot-segment is always an
		// identifier, and unconditionally overwrites whatever the
		// second segment contributed (a login of
		// "<addr>.<paymentid>.<rig>" therefore keeps BOTH).
		if len(addressSplit) > 2 {
			out.Identifier = addressSplit[2]
		}
	}

	return out, nil
}

// XNPProxyExemptFromFixedDiffPin reports whether this login's
// fixed-difficulty request must be honored as a STARTING difficulty
// only, WITHOUT permanently pinning the session out of vardiff
// retargeting for the lifetime of the connection (Session.fixedDiff in
// both leaf-direct and leaf-solo -- see that field's own doc comment).
//
// This is this leaf's implementation of the real legacy
// `proxyAddressList` escape hatch, which until now had no equivalent
// here at all (/workspace/nodejs-pool-sxmr/lib/pool.js, retargetMiners,
// lines ~227-236, quoted verbatim):
//
//	function retargetMiners() {
//	    for (let minerId in activeMiners) {
//	        let miner = activeMiners[minerId];
//	        if (!miner.fixed_diff || (miner.fixed_diff && proxyAddressList.indexOf(miner.payout) !== -1)) {
//	            miner.updateDifficulty();
//	        }
//	    }
//	}
//
// Legacy's own right-hand clause exists because an xmr-node-proxy
// aggregator legitimately logs in with a fixed difficulty (a pool
// OPERATOR configures the proxy's upstream username with a
// "+<difficulty>" suffix specifically to skip past the vardiff ramp-up
// curve for a connection that starts at a huge AGGREGATE hashrate from
// its very first share) and yet STILL needs ongoing retargeting,
// because that aggregate hashrate -- the sum of every sub-miner behind
// it -- changes over the life of the connection. Honoring the suffix as
// a permanent pin instead of a starting point leaves such a proxy stuck
// at whatever value its operator configured once, forever, no matter
// how its real downstream hashrate moves.
//
// MECHANISM DIVERGENCE, stated explicitly: legacy detects a proxy by an
// OPERATOR-MAINTAINED allowlist of known proxy payout addresses
// (`proxyAddressList`, populated from its pool config). This leaf has
// no proxy-address registry of any kind, so the equivalence is
// implemented using this leaf's OWN already-existing, already-tested
// XNP detection instead: the connecting client's self-reported agent
// string (IsXNPProxyAgent, protocol.go -- the same single
// implementation session.go's jobPayload already gates the XNP
// raw-template-blob/reservation-offset job fields on, deliberately
// reused rather than re-implemented). Semantically this is the
// STRONGER of the two: it identifies the actual aggregating client
// rather than trusting an address list to stay in sync with reality.
//
// SCOPE, deliberately narrow: only the login-string
// "+<difficulty>"-suffix-driven pin is exempted
// (FixedDiffFromLoginSuffix). The NiceHash-agent-string pin is NOT
// touched -- NiceHash is a genuine per-rental fixed-difficulty
// hashpower market maker, not an aggregating proxy needing ongoing
// retargeting, and legacy pins it the same way.
func (f LoginFields) XNPProxyExemptFromFixedDiffPin(agent string) bool {
	return f.FixedDiff && f.FixedDiffFromLoginSuffix && IsXNPProxyAgent(agent)
}

// isLegacyPaymentID mirrors pool.js line 416's exact test for "this
// second dot-segment is a genuine Monero payment ID, not a worker
// name": `addressSplit[1].length === 64 && hexMatch.test(addressSplit[1])`.
func isLegacyPaymentID(segment string) bool {
	return len(segment) == 64 && legacyHexMatch.MatchString(segment)
}

// parseLegacyFixedDifficulty parses the "+"-suffix's numeric
// difficulty. See ParseLoginFields' "DELIBERATE DIVERGENCES" note for
// why a non-numeric suffix errors (rather than legacy's silent NaN)
// and why a saturating out-of-range value does not.
func parseLegacyFixedDifficulty(raw string) (int64, error) {
	trimmed := strings.TrimSpace(raw)
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err == nil {
		return n, nil
	}
	// ParseInt already saturated n at MaxInt64/MinInt64 for a
	// well-formed-but-out-of-range value; clampDifficulty handles it.
	if numErr := (*strconv.NumError)(nil); errors.As(err, &numErr) && errors.Is(numErr.Err, strconv.ErrRange) {
		return n, nil
	}
	return 0, fmt.Errorf("invalid fixed difficulty %q in login field: must be a base-10 integer", trimmed)
}

// clampDifficulty ports pool.js lines 404-411's clamp exactly: below
// minDifficulty clamps up, above maxDifficulty clamps down. A negative
// requested value is treated as "below minDifficulty" and clamps up,
// matching legacy's own numeric comparison on a negative Number().
func clampDifficulty(requested int64, minDiff, maxDiff uint64) uint64 {
	if requested < 0 || uint64(requested) < minDiff {
		return minDiff
	}
	if uint64(requested) > maxDiff {
		return maxDiff
	}
	return uint64(requested)
}
