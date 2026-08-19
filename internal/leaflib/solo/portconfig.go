// Copyright and license: see repository LICENSE (MIT).
package solo

// PortConfig describes one stratum "port tier": a single listen
// address paired with the starting share difficulty that every miner
// connecting to THAT address begins at. This is the real multi-port
// mechanism ported from go-tari-sha3x-solo-stratum's
// subsystems/messages/structs.go PortConfig/PortPush shape
// (PoolPort/Difficulty/PortDesc/PortType/Hidden/Ssl) — that reference
// struct's field names describe a numeric TCP port plus per-port
// metadata; the ACTUAL starting-difficulty-assignment semantics ported
// here (confirmed against the reference's subsystems/poolStratum's
// miner-init and login handling, and subsystems/config's global
// StartingDifficulty) is: whichever port/listener a miner connects on
// determines the ONE difficulty value that miner's session starts at.
// From that point on, this go-crypto-pool leaf's own per-session
// vardiff retarget loop (vardiff.go) takes over exactly as it already
// does today — a port only stamps the STARTING point, nothing else.
//
// go-crypto-pool listens on Go net.Listener addresses (":4444",
// "0.0.0.0:4445", etc.), not bare numeric ports, so Address (a string)
// takes the place of the reference's PoolPort (an int). PortDesc is
// carried through unchanged as an operator-facing label ("low-diff",
// "high-diff", etc.) for logging. PortType/Hidden/Ssl from the
// reference struct are not needed for this leaf (no proxy protocol
// variants, no port-listing API, no per-port TLS support today) and
// are intentionally omitted rather than carried as unused dead fields
// — add them here if/when this leaf actually needs them.
type PortConfig struct {
	// Address is the net.Listen("tcp", Address) address this port
	// tier listens on, e.g. ":4444" or "0.0.0.0:4445".
	Address string

	// Difficulty is the starting share difficulty every session that
	// connects on Address begins at (see this type's doc comment).
	// Must be > 0; a zero value is normalized to the package's
	// documented default (10000, matching the pre-existing
	// LEAF_SOLO_STARTING_DIFFICULTY default) by whichever config
	// loader constructs a PortConfig list, not by Server/Session
	// themselves.
	Difficulty uint64

	// PortDesc is a human-readable operator label for this tier
	// (e.g. "low-diff", "high-diff", "default"), surfaced in startup
	// connection logging so operators can tell tiers apart without
	// cross-referencing raw addresses. Optional; an empty PortDesc is
	// valid and simply omitted from log lines that would otherwise
	// include it.
	PortDesc string
}
