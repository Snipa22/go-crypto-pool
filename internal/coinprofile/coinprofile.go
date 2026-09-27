// Copyright and license: see repository LICENSE (MIT).
//
// Package coinprofile is the CoinProfile abstraction requested for
// generalizing go-crypto-pool's leaf binaries beyond the original
// tari/monero binary -coin choice: each standalone (non-merge-mined)
// RandomX/Monero-codebase-family coin gets its own CoinProfile entry,
// keyed by lowercase ticker in Registry, and its own dedicated
// poolpb.Algo enum value (see internal/proto/share.proto's ALGO_XMR
// and below) -- reusing the existing algo-keyed partitioning/payout
// machinery exactly the way ALGO_RXT/ALGO_C29/ALGO_SHA3X/ALGO_RXM
// already do, per AGENTS.md's "backend is a trust boundary, leaves own
// all algo-specific validation" convention and this repo's existing
// per-algo tracking pattern.
//
// ALGO_RXM ("RandomX-Monero-family", today ALWAYS Tari-merge-mined
// Monero via minotari_merge_mining_proxy -- see cmd/leaf-solo's
// resolveAlgo) is INTENTIONALLY NOT represented by a Registry entry
// here: RXM is a merge-mining relationship between Tari and Monero,
// not a standalone-coin daemon connection, and this package does not
// touch that path at all. XMR *does* get a Registry entry -- it is
// the new, genuinely-new capability this package adds: running
// standalone (non-merge-mined) Monero against a real monerod, tracked
// under its own new ALGO_XMR value, completely independent of RXM.
//
// # Coin verdicts
//
// Every entry in Registry is a CONFIRMED monerod-JSON-RPC-compatible
// fork (get_block_template/submit_block wire shape), verified against
// that coin's own real primary-source repository -- see each entry's
// doc comment below for the exact GitHub URL and the specific
// cryptonote_config.h constants (CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
// CRYPTONOTE_DISPLAY_DECIMAL_POINT/COIN, RPC_DEFAULT_PORT) the fields
// here were read from. Coins on Alex's original ~26-coin candidate
// list that are NOT in this Registry were either found to use RandomX
// as a PoW option WITHOUT speaking monerod's JSON-RPC (e.g. Epic Cash
// is Grin/MimbleWimble-derived, Veil is Bitcoin/PIVX-derived), or could
// not be positively verified against a real primary source in
// reasonable time -- see the PR description's full verdict table
// (confirmed-wired / excluded-not-compatible-with-citation /
// unverified-needs-research) for the complete accounting. Partial,
// honestly-verified coverage beats fabricated compatibility claims.
package coinprofile

import (
	"fmt"
	"strings"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// CoinProfile describes one standalone (non-merge-mined) monerod-family
// coin this pool can serve a dedicated leaf-solo/leaf-direct/leaf-proxy
// deployment for.
type CoinProfile struct {
	// Ticker is the coin's short ticker symbol, e.g. "XMR". Registry is
	// keyed by strings.ToLower(Ticker).
	Ticker string
	// Name is the coin's full human-readable name, e.g. "Monero".
	Name string
	// Algo is the dedicated poolpb.Algo enum value this coin's shares/
	// blocks/balance/payout tracking is partitioned under -- see
	// internal/backend/db's EnsureHeightPartition and the
	// pools_algo_network_pool_type_name_key constraint, which key
	// entirely off this string (via Algo.String()'s ALGO_XMR-style
	// name), reusing 100% of the existing per-algo machinery.
	Algo poolpb.Algo
	// Decimals is this coin's atomic-unit precision (e.g. Monero
	// piconero = 12), read from that coin's own
	// CRYPTONOTE_DISPLAY_DECIMAL_POINT / COIN=10^N constant -- verified
	// per-coin, NOT assumed to be 12 for every fork (several confirmed
	// forks here use a different precision).
	Decimals uint32
	// AddressNetworkBytes is the real, varint-encoded mainnet standard
	// (non-subaddress, non-integrated) CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX
	// value for this coin, exactly as it appears as the leading bytes
	// of a base58-decoded address payload (see
	// EncodeVarintPrefix/DecodeVarintPrefix and ValidateAddress) --
	// read from that coin's own cryptonote_config.h source, not
	// guessed or copied from Monero's.
	AddressNetworkBytes []byte
	// DefaultRPCPort is this coin's real monerod-compatible daemon's
	// default RPC_DEFAULT_PORT (mainnet), read from that coin's own
	// cryptonote_config.h. Purely informational/documentation today --
	// leaf binaries still require an explicit -monerod-url; this is
	// not used to construct a default URL.
	DefaultRPCPort int
	// CoinbaseExtraTagDefault is this coin's default coinbase-extra
	// ownership tag, following the existing "supportxtm-<algo>"
	// convention (e.g. "supportxtm-sha3x"/"supportxtm-rxt" already in
	// production) -- "supportxtm-<ticker>", lowercase.
	CoinbaseExtraTagDefault string
	// MonerodCompatible is true for every entry in Registry by
	// construction (see this package's doc comment on the verdict
	// process) -- carried as an explicit field, rather than implied
	// solely by registry membership, so callers that receive a
	// CoinProfile value (not just a lookup result) can still assert
	// the property directly.
	MonerodCompatible bool
}

// Registry is the set of confirmed CoinProfile entries, keyed by
// strings.ToLower(Ticker). Use Lookup rather than indexing this map
// directly, so callers get the same case-insensitivity/error-shape
// guarantee regardless of call site.
var Registry = map[string]CoinProfile{
	"xmr": {
		Ticker: "XMR",
		Name:   "Monero",
		Algo:   poolpb.Algo_ALGO_XMR,
		// CRYPTONOTE_DISPLAY_DECIMAL_POINT=12, COIN=10^12 ("piconero").
		Decimals: 12,
		// CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=18 (0x12), a single-byte varint.
		AddressNetworkBytes: []byte{0x12},
		// RPC_DEFAULT_PORT=18081.
		DefaultRPCPort: 18081,
		// Source: https://github.com/monero-project/monero
		// src/cryptonote_config.h (config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
		// config::RPC_DEFAULT_PORT, CRYPTONOTE_DISPLAY_DECIMAL_POINT/COIN).
		CoinbaseExtraTagDefault: "supportxtm-xmr",
		MonerodCompatible:       true,
	},
	"arq": {
		Ticker: "ARQ",
		Name:   "ArQmA",
		Algo:   poolpb.Algo_ALGO_ARQ,
		// blockchain_settings::ARQMA_DECIMALS=9.
		Decimals: 9,
		// CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=0x2cca (11466 decimal),
		// varint-encoded as {0xca, 0x59}.
		AddressNetworkBytes: []byte{0xca, 0x59},
		// RPC_DEFAULT_PORT=19994.
		DefaultRPCPort: 19994,
		// Source: https://github.com/arqma/arqma
		// src/cryptonote_config.h (config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
		// config::RPC_DEFAULT_PORT, config::blockchain_settings::ARQMA_DECIMALS).
		CoinbaseExtraTagDefault: "supportxtm-arq",
		MonerodCompatible:       true,
	},
	"xeq": {
		Ticker: "XEQ",
		Name:   "Equilibria",
		Algo:   poolpb.Algo_ALGO_XEQ,
		// CRYPTONOTE_DISPLAY_DECIMAL_POINT=4, COIN=10^4 -- NOT 12,
		// confirming the brief's warning not to assume Monero's
		// precision for every fork.
		Decimals: 4,
		// CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=289 (0x121 decimal),
		// varint-encoded as {0xa1, 0x02}.
		AddressNetworkBytes: []byte{0xa1, 0x02},
		// RPC_DEFAULT_PORT=9231.
		DefaultRPCPort: 9231,
		// Source: https://github.com/EquilibriaCC/Equilibria (a real
		// GitHub fork of monero-project/monero, confirmed via the
		// repository's own "fork"/"parent" metadata) src/cryptonote_config.h
		// (config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
		// config::RPC_DEFAULT_PORT, CRYPTONOTE_DISPLAY_DECIMAL_POINT/COIN).
		CoinbaseExtraTagDefault: "supportxtm-xeq",
		MonerodCompatible:       true,
	},
	"grft": {
		Ticker: "GRFT",
		Name:   "Graft Network",
		Algo:   poolpb.Algo_ALGO_GRFT,
		// CRYPTONOTE_DISPLAY_DECIMAL_POINT=10, COIN=10^10.
		Decimals: 10,
		// CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=90 ('G'), a single-byte varint.
		AddressNetworkBytes: []byte{0x5a},
		// RPC_DEFAULT_PORT=18981.
		DefaultRPCPort: 18981,
		// Source: https://github.com/graft-project/GraftNetwork
		// src/cryptonote_config.h (config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
		// config::RPC_DEFAULT_PORT, CRYPTONOTE_DISPLAY_DECIMAL_POINT/COIN).
		CoinbaseExtraTagDefault: "supportxtm-grft",
		MonerodCompatible:       true,
	},
	"sfx": {
		Ticker: "SFX",
		Name:   "Safex Cash",
		Algo:   poolpb.Algo_ALGO_SFX,
		// CRYPTONOTE_DISPLAY_DECIMAL_POINT=10, COIN=10^10 (SAFEX_CASH_COIN).
		Decimals: 10,
		// CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=0x10003798 (268449688
		// decimal), varint-encoded as {0x98, 0xef, 0x80, 0x80, 0x01}.
		AddressNetworkBytes: []byte{0x98, 0xef, 0x80, 0x80, 0x01},
		// RPC_DEFAULT_PORT=17402.
		DefaultRPCPort: 17402,
		// Source: https://github.com/safex/safexcore
		// src/cryptonote_config.h (config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
		// config::RPC_DEFAULT_PORT, CRYPTONOTE_DISPLAY_DECIMAL_POINT/SAFEX_CASH_COIN).
		CoinbaseExtraTagDefault: "supportxtm-sfx",
		MonerodCompatible:       true,
	},
	"zeph": {
		Ticker: "ZEPH",
		Name:   "Zephyr Protocol",
		Algo:   poolpb.Algo_ALGO_ZEPH,
		// CRYPTONOTE_DISPLAY_DECIMAL_POINT=12, COIN=10^12.
		Decimals: 12,
		// CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=0x6241d18c0 (26375690432
		// decimal), varint-encoded as {0xc0, 0xb1, 0xf4, 0xa0, 0x62}.
		AddressNetworkBytes: []byte{0xc0, 0xb1, 0xf4, 0xa0, 0x62},
		// RPC_DEFAULT_PORT=17767.
		DefaultRPCPort: 17767,
		// Source: https://github.com/ZephyrProtocol/zephyr
		// src/cryptonote_config.h (config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
		// config::RPC_DEFAULT_PORT, CRYPTONOTE_DISPLAY_DECIMAL_POINT/COIN).
		CoinbaseExtraTagDefault: "supportxtm-zeph",
		MonerodCompatible:       true,
	},
	"sal": {
		Ticker: "SAL",
		Name:   "Salvium",
		Algo:   poolpb.Algo_ALGO_SAL,
		// CRYPTONOTE_DISPLAY_DECIMAL_POINT=8, COIN=10^8.
		Decimals: 8,
		// CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX=0x3ef318 (4125464
		// decimal), varint-encoded as {0x98, 0xe6, 0xfb, 0x01}. This is
		// the legacy (pre-Carrot) standard-address prefix -- Salvium's
		// newer CARROT_PUBLIC_ADDRESS_BASE58_PREFIX is a distinct,
		// address-format-versioned prefix not modeled here.
		AddressNetworkBytes: []byte{0x98, 0xe6, 0xfb, 0x01},
		// RPC_DEFAULT_PORT=19081.
		DefaultRPCPort: 19081,
		// Source: https://github.com/salvium/salvium
		// src/cryptonote_config.h (config::CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX,
		// config::RPC_DEFAULT_PORT, CRYPTONOTE_DISPLAY_DECIMAL_POINT/COIN).
		CoinbaseExtraTagDefault: "supportxtm-sal",
		MonerodCompatible:       true,
	},
}

// Lookup resolves ticker (case-insensitive, tolerant of surrounding
// whitespace) against Registry. ok is false, with a zero CoinProfile,
// for any ticker not in Registry -- callers MUST fail fast on ok==false
// rather than silently falling through to a default coin (see
// cmd/leaf-solo and cmd/leaf-direct's resolveAlgo/resolveCoinProfile).
func Lookup(ticker string) (profile CoinProfile, ok bool) {
	profile, ok = Registry[NormalizeTicker(ticker)]
	return profile, ok
}

// NormalizeTicker lowercases and trims ticker -- the single
// normalization point every Registry lookup in this package and its
// callers should go through, so "XMR"/"xmr"/" Xmr " all resolve
// identically.
func NormalizeTicker(ticker string) string {
	return strings.ToLower(strings.TrimSpace(ticker))
}

// ByAlgo reverse-looks-up the CoinProfile whose Algo field equals algo.
// Used by callers that already have a resolved poolpb.Algo (e.g. for
// deriving a coinbase-extra-tag suffix) and need the coin's own
// ticker/profile back out. O(len(Registry)); Registry is small and
// this is never called on a hot path.
func ByAlgo(algo poolpb.Algo) (profile CoinProfile, ok bool) {
	for _, p := range Registry {
		if p.Algo == algo {
			return p, true
		}
	}
	return CoinProfile{}, false
}

// ErrUnknownTicker is returned (wrapped with the offending ticker) by
// any caller-facing resolution helper that requires a registered
// ticker -- see e.g. leaf-solo/leaf-direct's coin-flag resolution,
// which must fail fast at startup on an unrecognized ticker rather
// than silently falling through to Tari or Monero defaults.
type ErrUnknownTicker struct {
	Ticker string
}

func (e *ErrUnknownTicker) Error() string {
	return fmt.Sprintf("coinprofile: unknown/unregistered coin ticker %q -- see internal/coinprofile.Registry for supported tickers", e.Ticker)
}

// MustLookup is Lookup, but returns a typed *ErrUnknownTicker error
// instead of a bare ok bool -- convenient for callers (leaf main()
// functions) that want to log.Fatalf on an unrecognized ticker with a
// consistent, greppable error shape.
func MustLookup(ticker string) (CoinProfile, error) {
	profile, ok := Lookup(ticker)
	if !ok {
		return CoinProfile{}, &ErrUnknownTicker{Ticker: ticker}
	}
	return profile, nil
}
