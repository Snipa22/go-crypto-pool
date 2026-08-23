// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"errors"
	"strings"

	tariaddress "github.com/Snipa22/go-tari-lib/address"
	xmraddress "github.com/Snipa22/go-xmr-lib/support"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// maxLoginAddressLen mirrors internal/backend/addressmap's own
// maxAddressLen exactly: a generous upper bound on a well-formed
// Monero or Tari address's length, used only as a cheap pre-check
// ahead of the real, coin-specific byte-exact decoders below — not
// itself a format validator.
const maxLoginAddressLen = 512

// ValidateAddressForAlgo performs real, coin-aware, byte-exact
// payment-address validation for a miner's login address, dispatched
// on algo exactly the way every other per-algo decision in this leaf
// already is (job.Algo/JobManagerConfig.Algo — see job.go). This is
// the SAME real validation internal/backend/addressmap already does
// for its own XMR<->Tari mapping endpoint (see that package's
// validateTariAddress/validateXMRAddress) — reusing the exact same
// upstream library calls rather than reimplementing prefix/length
// heuristics here:
//
//   - poolpb.Algo_ALGO_SHA3X, poolpb.Algo_ALGO_C29, poolpb.Algo_ALGO_RXT
//     (Tari's three native PoW algos — see tariPowAlgo in node.go) all
//     pay out to a Tari wallet address, validated via
//     github.com/Snipa22/go-tari-lib/address.Parse: a byte-exact Go
//     port of the real Tari Base Layer tari_address implementation
//     that tries emoji, then base58, then hex encodings and verifies
//     the DammSum checksum, network byte, features byte, and that the
//     embedded public key(s) decode to a canonical compressed
//     Ristretto255 point — not merely that the string is the right
//     length.
//   - poolpb.Algo_ALGO_RXM (Monero merge-mining/native RandomX) pays
//     out to a Monero wallet address, validated via
//     github.com/Snipa22/go-xmr-lib/support's
//     IsValidMainnet/IsValidTestnet: base58-decodes the address and
//     verifies its trailing 4-byte Keccak checksum against the
//     address's own payload, then confirms the leading network-tag
//     byte is one of Monero's real mainnet/testnet address tag bytes.
//     Both mainnet and testnet are accepted (mirroring
//     addressmap.validateXMRAddress) since this leaf is not itself
//     scoped to a single network by this check.
//   - poolpb.Algo_ALGO_UNSPECIFIED is treated as SHA3X (Tari), the
//     same backward-compatibility normalization JobManagerConfig.Algo
//     already applies (see job.go) — callers here always pass a
//     JobManager's own already-normalized Algo() value, so this
//     branch is defensive, not a distinct real code path.
func ValidateAddressForAlgo(algo poolpb.Algo, address string) error {
	if strings.TrimSpace(address) == "" {
		return errors.New("invalid address provided, please use a valid address")
	}
	if len(address) > maxLoginAddressLen {
		return errors.New("invalid address provided: too long")
	}

	switch algo {
	case poolpb.Algo_ALGO_RXM:
		return validateMoneroLoginAddress(address)
	case poolpb.Algo_ALGO_SHA3X, poolpb.Algo_ALGO_C29, poolpb.Algo_ALGO_RXT, poolpb.Algo_ALGO_UNSPECIFIED:
		return validateTariLoginAddress(address)
	default:
		return errors.New("invalid address provided: no address validator configured for this leaf's algo")
	}
}

// validateTariLoginAddress is validateAddressForAlgo's Tari-side real
// decoder call, split out only so its doc comment/citation is next to
// the exact call site (mirrors addressmap.validateTariAddress).
func validateTariLoginAddress(address string) error {
	if _, err := tariaddress.Parse(address); err != nil {
		return errors.New("invalid address provided: not a valid Tari address (" + err.Error() + ")")
	}
	return nil
}

// validateMoneroLoginAddress is validateAddressForAlgo's Monero-side
// real decoder call (mirrors addressmap.validateXMRAddress exactly,
// including accepting either mainnet or testnet).
func validateMoneroLoginAddress(address string) error {
	validMain, err := xmraddress.IsValidMainnet(address)
	if err != nil {
		return errors.New("invalid address provided: not a valid Monero address (" + err.Error() + ")")
	}
	if validMain {
		return nil
	}
	validTest, err := xmraddress.IsValidTestnet(address)
	if err != nil {
		return errors.New("invalid address provided: not a valid Monero address (" + err.Error() + ")")
	}
	if validTest {
		return nil
	}
	return errors.New("invalid address provided: not a valid Monero address (bad checksum or unrecognized network byte)")
}
