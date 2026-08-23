// Copyright and license: see repository LICENSE (MIT).
package tariaddr

import "strings"

// Network mirrors tari_common::configuration::Network
// (tari/common/src/configuration/network.rs) — specifically the six
// #[repr(u8)] variants and their exact wire-byte values, which are
// load-bearing for TariAddress encoding/decoding (they are literally
// the first byte of every encoded address). Only the pieces of the
// real Network type relevant to address (de)serialization are
// ported: the byte<->variant mapping and the string<->variant
// mapping (Display/FromStr). Network::as_wire_byte,
// Network::get_current*, and Network::set_current are p2p-liveness
// concerns unrelated to address parsing and are intentionally not
// reproduced here.
type Network uint8

const (
	MainNet   Network = 0x00
	StageNet  Network = 0x01
	NextNet   Network = 0x02
	LocalNet  Network = 0x10
	Igor      Network = 0x24
	Esmeralda Network = 0x26
)

// AsByte returns the network's wire byte, matching Network::as_byte.
func (n Network) AsByte() byte { return byte(n) }

// String returns the network's key string, matching
// Network::as_key_str / the Display impl for Network.
func (n Network) String() string {
	switch n {
	case MainNet:
		return "mainnet"
	case StageNet:
		return "stagenet"
	case NextNet:
		return "nextnet"
	case Igor:
		return "igor"
	case Esmeralda:
		return "esmeralda"
	case LocalNet:
		return "localnet"
	default:
		return "unknown"
	}
}

// NetworkFromByte mirrors impl TryFrom<u8> for Network: it accepts
// only the six real wire-byte values and rejects everything else
// with ErrInvalidNetwork (the byte-value equivalent of
// ConfigurationError in the Rust source, mapped the same way
// SingleAddress::from_bytes/DualAddress::from_bytes map it).
func NetworkFromByte(v byte) (Network, error) {
	switch v {
	case byte(MainNet):
		return MainNet, nil
	case byte(StageNet):
		return StageNet, nil
	case byte(NextNet):
		return NextNet, nil
	case byte(LocalNet):
		return LocalNet, nil
	case byte(Igor):
		return Igor, nil
	case byte(Esmeralda):
		return Esmeralda, nil
	default:
		return 0, ErrInvalidNetwork
	}
}

// NetworkFromString mirrors impl FromStr for Network: case-insensitive
// key strings, with "esme" as an accepted alias for Esmeralda exactly
// as in the Rust source.
func NetworkFromString(value string) (Network, error) {
	switch strings.ToLower(value) {
	case "mainnet":
		return MainNet, nil
	case "nextnet":
		return NextNet, nil
	case "stagenet":
		return StageNet, nil
	case "localnet":
		return LocalNet, nil
	case "igor":
		return Igor, nil
	case "esmeralda", "esme":
		return Esmeralda, nil
	default:
		return 0, newCreationError("invalid network option: " + value)
	}
}
