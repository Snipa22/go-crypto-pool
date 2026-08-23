// Command backend is the entrypoint for the unified go-crypto-pool
// backend service. It opens a Postgres connection pool, wires it into
// the HTTP+Protobuf share/block ingestion API (internal/backend/api),
// and serves it.
//
// Configuration is via environment variables (no flags/config file yet
// — this is the first runnable pass, not the final ops story):
//
//	GCPOOL_DB_DSN            (required) Postgres DSN, e.g.
//	                         "postgres://user:pass@host:5432/db?sslmode=disable"
//	GCPOOL_LISTEN_ADDR       (optional) HTTP listen address, default ":8080"
//	GCPOOL_AUTH_HEADER_NAME  (optional) shared-secret auth header name to
//	                         require on /api/v1/share and /api/v1/block,
//	                         e.g. "Authorization". Must be set together
//	                         with GCPOOL_AUTH_HEADER_VALUE, or not at all
//	                         — see internal/backend/api.Config: both
//	                         empty means no auth check is performed
//	                         (matches the leaf transport's opt-in v1 auth
//	                         story).
//	GCPOOL_AUTH_HEADER_VALUE (optional) expected value for the header
//	                         above.
//	GCPOOL_NETWORK           (required) the network this backend is
//	                         configured for. Accepts "mainnet" or
//	                         "testnet" (case-insensitive). There is no
//	                         default — startup fails fast if this is
//	                         missing or does not parse to a valid
//	                         network, since silently defaulting to
//	                         either network here is exactly the kind of
//	                         cross-network contamination this backend
//	                         must prevent. Every submitted Share/Block
//	                         must carry this exact network or it is
//	                         rejected with 400.
//	GCPOOL_TARI_GRPC_ADDR    (optional) host:port of a real Tari base
//	                         node's GRPC endpoint. When set, the block
//	                         unlocker (internal/backend/unlocker) polls
//	                         every pending ALGO_RXT/ALGO_C29/ALGO_SHA3X
//	                         block against it (internal/backend/chain.
//	                         TariVerifier) to detect maturity/orphaning.
//	                         When unset, those algos' blocks are simply
//	                         never auto-unlocked — a deliberate opt-in,
//	                         not a startup failure, since not every
//	                         deployment mines every coin.
//	GCPOOL_MONERO_RPC_ADDR   (optional) base URL of a real monerod
//	                         JSON-RPC endpoint (e.g.
//	                         "http://127.0.0.1:18081"). When set, the
//	                         unlocker polls every pending ALGO_RXM block
//	                         against it (internal/backend/chain.
//	                         MoneroVerifier). Same opt-in behavior as
//	                         GCPOOL_TARI_GRPC_ADDR above.
//	GCPOOL_UNLOCKER_POLL_INTERVAL (optional) how often the unlocker
//	                         re-checks pending blocks, as a
//	                         time.ParseDuration string (e.g. "60s").
//	                         Default "60s". Only consulted if at least
//	                         one of the two RPC addrs above is set.
//	GCPOOL_UNLOCKER_TARI_MATURITY (optional) confirmations required
//	                         before a Tari-family block (RXT/C29/SHA3X)
//	                         is marked unlocked/payable. Default 60 —
//	                         a PLACEHOLDER, operationally-tunable value,
//	                         not a Tari protocol constant; pool
//	                         operators should set this to their own
//	                         real reorg-safety requirement.
//	GCPOOL_UNLOCKER_MONERO_MATURITY (optional) confirmations required
//	                         before an RXM block is marked unlocked/
//	                         payable. Default 60, mirroring Monero's
//	                         own real CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW
//	                         (coinbase spend maturity) — a sensible
//	                         starting default, but still operator-
//	                         tunable via this variable, not hardcoded.
//	GCPOOL_PAYOUT_FEE_ADDRESS (optional) pool operator fee-collection
//	                         payment address. When set, every block
//	                         the unlocker marks matured also triggers
//	                         a real internal/backend/payout.Calculator
//	                         PPS/PPLNS/Solo payout cycle for that
//	                         block, crediting miner balances. When
//	                         unset, blocks still mature/unlock
//	                         correctly — they are simply never
//	                         auto-paid out. See
//	                         buildPayoutCalculator's doc comment for
//	                         the rest of this feature's env vars
//	                         (GCPOOL_PAYOUT_COIN_DEV_ADDRESS,
//	                         GCPOOL_PAYOUT_POOL_DEV_ADDRESS,
//	                         GCPOOL_PAYOUT_{PPS,PPLNS,SOLO}_FEE_PERCENT,
//	                         GCPOOL_PAYOUT_{,POOL_}DEV_DONATION_PERCENT,
//	                         GCPOOL_PAYOUT_PPLNS_SHARE_MULTI).
//	GCPOOL_MONERO_WALLET_RPC_ADDR (optional) base URL of a real
//	                         monero-wallet-rpc endpoint (e.g.
//	                         "http://127.0.0.1:18083"). When set, the
//	                         real internal/backend/disburse.Engine
//	                         periodically pays out every miner's
//	                         accrued pending_balance via a real
//	                         on-chain transfer (internal/backend/wallet.
//	                         MoneroWalletRPC). When unset, balances
//	                         still accrue correctly, they simply
//	                         aren't disbursed on-chain automatically.
//	                         See buildDisburseEngine's doc comment for
//	                         the rest of this feature's env vars
//	                         (GCPOOL_MONERO_WALLET_RPC_{USER,PASSWORD},
//	                         GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC,
//	                         GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH,
//	                         GCPOOL_DISBURSE_POLL_INTERVAL).
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/api"
	"github.com/Snipa22/go-crypto-pool/internal/backend/chain"
	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/backend/disburse"
	"github.com/Snipa22/go-crypto-pool/internal/backend/metrics"
	"github.com/Snipa22/go-crypto-pool/internal/backend/payout"
	"github.com/Snipa22/go-crypto-pool/internal/backend/unlocker"
	"github.com/Snipa22/go-crypto-pool/internal/backend/wallet"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

const defaultListenAddr = ":8080"

// defaultUnlockerPollInterval/defaultTariMaturity/defaultMoneroMaturity
// are this command's PLACEHOLDER defaults for the unlocker's env vars
// — see this file's package doc comment for why these are
// operator-tunable rather than baked-in protocol constants.
const (
	defaultUnlockerPollInterval = 60 * time.Second
	defaultTariMaturity         = int64(60)
	defaultMoneroMaturity       = int64(60)
)

// Version is the backend's build version, recorded on the
// backend_build_info Prometheus gauge. Overridable at build time via
// -ldflags "-X main.Version=...", e.g. from a CI-set git tag/commit;
// defaults to "dev" for local/unreleased builds.
var Version = "dev"

// parseNetwork parses the GCPOOL_NETWORK environment variable value
// into a poolpb.Network. Only "mainnet" and "testnet" (case-insensitive)
// are accepted; anything else (including empty string) is an error —
// there is deliberately no default value here.
func parseNetwork(raw string) (poolpb.Network, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "mainnet":
		return poolpb.Network_NETWORK_MAINNET, nil
	case "testnet":
		return poolpb.Network_NETWORK_TESTNET, nil
	default:
		return poolpb.Network_NETWORK_UNSPECIFIED, fmt.Errorf("GCPOOL_NETWORK: unrecognized value %q, want \"mainnet\" or \"testnet\"", raw)
	}
}

// networkDBString maps a poolpb.Network to the exact "MAINNET"/
// "TESTNET" string this schema's network columns/CHECK constraints
// use (see migrations/0001_initial_schema.up.sql) — deliberately
// separate from poolpb.Network's own generated String() method (which
// would render "NETWORK_MAINNET"/"NETWORK_TESTNET" instead), mirroring
// internal/backend/api's own private networkString helper since this
// command needs the identical mapping for payoutTrigger's network
// field but cannot import that unexported function.
func networkDBString(n poolpb.Network) string {
	switch n {
	case poolpb.Network_NETWORK_MAINNET:
		return "MAINNET"
	case poolpb.Network_NETWORK_TESTNET:
		return "TESTNET"
	default:
		return ""
	}
}

// repositoryAdapter adapts *db.Repository (whose InsertShare/InsertBlock
// operate on db.Share/db.Block) to api.ShareBlockRepository (which
// operates on api.ShareRecord/api.BlockRecord). This keeps
// internal/backend/api free of any dependency on internal/backend/db —
// this command is the only place the two packages need to meet.
type repositoryAdapter struct {
	repo *db.Repository
}

func (a repositoryAdapter) InsertShare(ctx context.Context, s api.ShareRecord, bucketSize int64) error {
	return a.repo.InsertShare(ctx, db.Share{
		Algo:           s.Algo,
		Network:        s.Network,
		PoolType:       s.PoolType,
		PoolID:         s.PoolID,
		BlockHeight:    s.BlockHeight,
		Shares:         s.Shares,
		PaymentAddress: s.PaymentAddress,
		PaymentID:      s.PaymentID,
		FoundBlock:     s.FoundBlock,
		BlockDiff:      s.BlockDiff,
		Timestamp:      s.Timestamp,
		Identifier:     s.Identifier,
		TrustedShare:   s.TrustedShare,
	}, bucketSize)
}

func (a repositoryAdapter) InsertBlock(ctx context.Context, b api.BlockRecord) error {
	return a.repo.InsertBlock(ctx, db.Block{
		Algo:       b.Algo,
		Network:    b.Network,
		PoolType:   b.PoolType,
		Hash:       b.Hash,
		Height:     b.Height,
		Difficulty: b.Difficulty,
		Shares:     b.Shares,
		Timestamp:  b.Timestamp,
		Unlocked:   b.Unlocked,
		Valid:      b.Valid,
		Value:      b.Value,
	})
}

// unlockerRepositoryAdapter adapts *db.Repository (whose
// PendingBlocks/SetBlockStatus operate on db.PendingBlock) to
// unlocker.Repository (which operates on unlocker.Block), mirroring
// repositoryAdapter's role above for the ingestion side — see
// unlocker.Repository's doc comment for why this indirection exists.
type unlockerRepositoryAdapter struct {
	repo *db.Repository
}

func (a unlockerRepositoryAdapter) PendingBlocks(ctx context.Context, algo string) ([]unlocker.Block, error) {
	rows, err := a.repo.PendingBlocks(ctx, algo)
	if err != nil {
		return nil, err
	}
	out := make([]unlocker.Block, 0, len(rows))
	for _, r := range rows {
		out = append(out, unlocker.Block{
			ID:         r.ID,
			Algo:       r.Algo,
			Network:    r.Network,
			Hash:       r.Hash,
			Height:     r.Height,
			PoolType:   r.PoolType,
			Difficulty: r.Difficulty,
			Value:      r.Value,
		})
	}
	return out, nil
}

func (a unlockerRepositoryAdapter) SetBlockStatus(ctx context.Context, id int64, valid, unlocked bool) error {
	return a.repo.SetBlockStatus(ctx, id, valid, unlocked)
}

// payoutRepositoryAdapter adapts *db.Repository (whose SharesAtHeight/
// SoloShare/CreditBalance operate on db.PayoutShare) to
// payout.Repository (which operates on payout.ShareRow), mirroring
// repositoryAdapter/unlockerRepositoryAdapter's role above.
type payoutRepositoryAdapter struct {
	repo *db.Repository
}

func (a payoutRepositoryAdapter) SharesAtHeight(ctx context.Context, algo, poolType string, height int64) ([]payout.ShareRow, error) {
	rows, err := a.repo.SharesAtHeight(ctx, algo, poolType, height)
	if err != nil {
		return nil, err
	}
	out := make([]payout.ShareRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, payout.ShareRow{
			Shares:         r.Shares,
			PaymentAddress: r.PaymentAddress,
			PaymentID:      r.PaymentID,
		})
	}
	return out, nil
}

func (a payoutRepositoryAdapter) SoloShare(ctx context.Context, algo string, height int64) (payout.ShareRow, bool, error) {
	r, found, err := a.repo.SoloShare(ctx, algo, height)
	if err != nil {
		return payout.ShareRow{}, false, err
	}
	return payout.ShareRow{
		Shares:         r.Shares,
		PaymentAddress: r.PaymentAddress,
		PaymentID:      r.PaymentID,
	}, found, nil
}

func (a payoutRepositoryAdapter) CreditBalance(ctx context.Context, algo, network, paymentAddress string, paymentID *string, amount int64) error {
	return a.repo.CreditBalance(ctx, algo, network, paymentAddress, paymentID, amount)
}

// disburseRepositoryAdapter adapts *db.Repository (whose
// PayableBalances/RecordPendingPayout/CompletePayoutSent/FailPayout
// operate on db.PayableBalance/db.DisburseEntry) to
// disburse.Repository (which operates on disburse.PayableBalance/
// disburse.DebitEntry), mirroring payoutRepositoryAdapter's role
// above.
type disburseRepositoryAdapter struct {
	repo *db.Repository
}

func (a disburseRepositoryAdapter) PayableBalances(ctx context.Context, algo, network string, minPayout int64) ([]disburse.PayableBalance, error) {
	rows, err := a.repo.PayableBalances(ctx, algo, network, minPayout)
	if err != nil {
		return nil, err
	}
	out := make([]disburse.PayableBalance, 0, len(rows))
	for _, r := range rows {
		out = append(out, disburse.PayableBalance{
			ID:             r.ID,
			PaymentAddress: r.PaymentAddress,
			PaymentID:      r.PaymentID,
			PendingBalance: r.PendingBalance,
		})
	}
	return out, nil
}

func (a disburseRepositoryAdapter) RecordPendingPayout(ctx context.Context, algo, network string, balanceIDs []int64, amount int64) (int64, error) {
	return a.repo.RecordPendingPayout(ctx, algo, network, balanceIDs, amount)
}

func (a disburseRepositoryAdapter) CompletePayoutSent(ctx context.Context, payoutID int64, entries []disburse.DebitEntry, txHash string, fee int64) error {
	dbEntries := make([]db.DisburseEntry, 0, len(entries))
	for _, e := range entries {
		dbEntries = append(dbEntries, db.DisburseEntry{BalanceID: e.BalanceID, Amount: e.Amount})
	}
	return a.repo.CompletePayoutSent(ctx, payoutID, dbEntries, txHash, fee)
}

func (a disburseRepositoryAdapter) FailPayout(ctx context.Context, payoutID int64, errMsg string) error {
	return a.repo.FailPayout(ctx, payoutID, errMsg)
}

// payoutTrigger adapts a *payout.Calculator into unlocker.PayoutTrigger
// — the concrete implementation the unlocker's Config.PayoutTrigger
// field is set to in production (see buildPayoutCalculator/run()
// below). network is fixed at construction time (this backend's own
// configured network — see GCPOOL_NETWORK), matching every other
// network-scoped write path in this command.
type payoutTrigger struct {
	calc    *payout.Calculator
	network string
}

func (t payoutTrigger) TriggerPayout(ctx context.Context, b unlocker.Block) error {
	_, err := t.calc.RunForMaturedBlock(ctx, b.Algo, t.network, b.PoolType, b.Height, b.Difficulty, b.Value)
	return err
}

// tariAlgos is every algo string mined against a Tari base node —
// mirrors internal/leaflib/solo/node.go's tariPowAlgo grouping exactly
// (SHA3X, C29, RXT all speak to the same base node GRPC surface; only
// RXM is Monero).
var tariAlgos = []string{"RXT", "C29", "SHA3X"}

// buildUnlockerConfig reads the GCPOOL_TARI_GRPC_ADDR/
// GCPOOL_MONERO_RPC_ADDR/GCPOOL_UNLOCKER_* environment variables (see
// this file's package doc comment) and returns a ready-to-use
// unlocker.Config plus whether any verifier was actually configured
// (ok == false means the caller should not start the unlocker at all
// — see run()).
func buildUnlockerConfig() (cfg unlocker.Config, ok bool, err error) {
	cfg.Coins = map[string]unlocker.CoinConfig{}

	pollInterval := defaultUnlockerPollInterval
	if raw := os.Getenv("GCPOOL_UNLOCKER_POLL_INTERVAL"); raw != "" {
		pollInterval, err = time.ParseDuration(raw)
		if err != nil {
			return cfg, false, fmt.Errorf("GCPOOL_UNLOCKER_POLL_INTERVAL: %w", err)
		}
	}
	cfg.PollInterval = pollInterval

	if addr := os.Getenv("GCPOOL_TARI_GRPC_ADDR"); addr != "" {
		maturity := defaultTariMaturity
		if raw := os.Getenv("GCPOOL_UNLOCKER_TARI_MATURITY"); raw != "" {
			m, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil {
				return cfg, false, fmt.Errorf("GCPOOL_UNLOCKER_TARI_MATURITY: %w", parseErr)
			}
			maturity = m
		}
		verifier := chain.NewTariVerifier(addr)
		for _, algo := range tariAlgos {
			cfg.Coins[algo] = unlocker.CoinConfig{Verifier: verifier, MaturityDepth: maturity}
		}
		ok = true
	}

	if addr := os.Getenv("GCPOOL_MONERO_RPC_ADDR"); addr != "" {
		maturity := defaultMoneroMaturity
		if raw := os.Getenv("GCPOOL_UNLOCKER_MONERO_MATURITY"); raw != "" {
			m, parseErr := strconv.ParseInt(raw, 10, 64)
			if parseErr != nil {
				return cfg, false, fmt.Errorf("GCPOOL_UNLOCKER_MONERO_MATURITY: %w", parseErr)
			}
			maturity = m
		}
		cfg.Coins["RXM"] = unlocker.CoinConfig{Verifier: chain.NewMoneroVerifier(addr), MaturityDepth: maturity}
		ok = true
	}

	return cfg, ok, nil
}

// sortedKeys returns m's keys sorted, purely for deterministic,
// readable startup log output (buildUnlockerConfig's map iteration
// order is otherwise unspecified).
func sortedKeys(m map[string]unlocker.CoinConfig) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parsePercentEnv parses an optional percentage (0-100) environment
// variable, returning def if raw is unset/empty. Mirrors
// buildUnlockerConfig's *ParseInt-then-error-wrap style for its own
// numeric env vars.
func parsePercentEnv(name, raw string, def float64) (float64, error) {
	if raw == "" {
		return def, nil
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return v, nil
}

// buildPayoutCalculator reads the GCPOOL_PAYOUT_* environment
// variables and returns a ready-to-use *payout.Calculator plus
// whether payout calculation should actually be wired into the
// unlocker's matured-block trigger (ok == false when
// GCPOOL_PAYOUT_FEE_ADDRESS is unset — a deployment that hasn't
// configured a fee address yet gets correct chain-maturity tracking
// out of the unlocker alone, exactly mirroring buildUnlockerConfig's
// own opt-in story for GCPOOL_TARI_GRPC_ADDR/GCPOOL_MONERO_RPC_ADDR).
//
//	GCPOOL_PAYOUT_FEE_ADDRESS       (required to enable payout) pool
//	                                operator fee-collection address.
//	GCPOOL_PAYOUT_COIN_DEV_ADDRESS  (optional) coin developer donation
//	                                address.
//	GCPOOL_PAYOUT_POOL_DEV_ADDRESS  (optional) pool software developer
//	                                donation address.
//	GCPOOL_PAYOUT_PPS_FEE_PERCENT, GCPOOL_PAYOUT_PPLNS_FEE_PERCENT,
//	GCPOOL_PAYOUT_SOLO_FEE_PERCENT (optional) per-pool-type operator
//	                                fee percentage (0-100). Default 0.
//	GCPOOL_PAYOUT_DEV_DONATION_PERCENT,
//	GCPOOL_PAYOUT_POOL_DEV_DONATION_PERCENT (optional) donation split
//	                                percentage (0-100) of each fee cut.
//	                                Default 0 (no donation split).
//	GCPOOL_PAYOUT_PPLNS_SHARE_MULTI (optional) PPLNS window multiplier.
//	                                Default 2 (a placeholder, operator-
//	                                tunable value — see payout.Config's
//	                                doc comment).
func buildPayoutCalculator(repo *db.Repository, m *metrics.Metrics) (calc *payout.Calculator, ok bool, err error) {
	feeAddress := os.Getenv("GCPOOL_PAYOUT_FEE_ADDRESS")
	if feeAddress == "" {
		return nil, false, nil
	}

	cfg := payout.Config{
		FeeAddress:      feeAddress,
		CoinDevAddress:  os.Getenv("GCPOOL_PAYOUT_COIN_DEV_ADDRESS"),
		PoolDevAddress:  os.Getenv("GCPOOL_PAYOUT_POOL_DEV_ADDRESS"),
		PPLNSShareMulti: defaultPPLNSShareMulti,
		Metrics:         m,
	}

	if cfg.PPSFeePercent, err = parsePercentEnv("GCPOOL_PAYOUT_PPS_FEE_PERCENT", os.Getenv("GCPOOL_PAYOUT_PPS_FEE_PERCENT"), 0); err != nil {
		return nil, false, err
	}
	if cfg.PPLNSFeePercent, err = parsePercentEnv("GCPOOL_PAYOUT_PPLNS_FEE_PERCENT", os.Getenv("GCPOOL_PAYOUT_PPLNS_FEE_PERCENT"), 0); err != nil {
		return nil, false, err
	}
	if cfg.SoloFeePercent, err = parsePercentEnv("GCPOOL_PAYOUT_SOLO_FEE_PERCENT", os.Getenv("GCPOOL_PAYOUT_SOLO_FEE_PERCENT"), 0); err != nil {
		return nil, false, err
	}
	if cfg.DevDonationPercent, err = parsePercentEnv("GCPOOL_PAYOUT_DEV_DONATION_PERCENT", os.Getenv("GCPOOL_PAYOUT_DEV_DONATION_PERCENT"), 0); err != nil {
		return nil, false, err
	}
	if cfg.PoolDevDonationPercent, err = parsePercentEnv("GCPOOL_PAYOUT_POOL_DEV_DONATION_PERCENT", os.Getenv("GCPOOL_PAYOUT_POOL_DEV_DONATION_PERCENT"), 0); err != nil {
		return nil, false, err
	}
	if raw := os.Getenv("GCPOOL_PAYOUT_PPLNS_SHARE_MULTI"); raw != "" {
		v, parseErr := strconv.ParseFloat(raw, 64)
		if parseErr != nil {
			return nil, false, fmt.Errorf("GCPOOL_PAYOUT_PPLNS_SHARE_MULTI: %w", parseErr)
		}
		cfg.PPLNSShareMulti = v
	}

	return payout.New(payoutRepositoryAdapter{repo: repo}, cfg), true, nil
}

const defaultPPLNSShareMulti = 2

// defaultDisbursePollInterval/defaultDisburseMaxDestinationsPerBatch
// are this command's PLACEHOLDER defaults for the disbursement
// engine's env vars — see this file's package doc comment for why
// these are operator-tunable rather than baked-in protocol constants.
const (
	defaultDisbursePollInterval            = 10 * time.Minute
	defaultDisburseMaxDestinationsPerBatch = 15
)

// buildDisburseEngine reads the GCPOOL_MONERO_WALLET_RPC_* /
// GCPOOL_DISBURSE_* environment variables and returns a ready-to-use
// *disburse.Engine plus whether the real payout-disbursement loop
// should actually be started (ok == false when
// GCPOOL_MONERO_WALLET_RPC_ADDR is unset — a deployment that hasn't
// configured a wallet RPC endpoint yet still gets correct payout
// CALCULATION (crediting pending_balance, via buildPayoutCalculator
// above), it simply never auto-disburses those balances on-chain).
// Disbursement is Monero-only today — internal/backend/wallet has no
// Tari-family WalletClient implementation yet, mirroring
// GCPOOL_MONERO_RPC_ADDR's coin-specific scope on the chain-
// verification side.
//
//	GCPOOL_MONERO_WALLET_RPC_ADDR     (required to enable disbursement)
//	                                  base URL of a real monero-wallet-rpc
//	                                  endpoint (e.g. "http://127.0.0.1:18083").
//	GCPOOL_MONERO_WALLET_RPC_USER,
//	GCPOOL_MONERO_WALLET_RPC_PASSWORD (optional) HTTP Digest auth
//	                                  credentials, matching whatever
//	                                  --rpc-login the real
//	                                  monero-wallet-rpc process was
//	                                  started with. Both empty means
//	                                  no auth is attempted.
//	GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC (optional) minimum pending_balance
//	                                  (atomic units) required before a
//	                                  miner is paid out at all. Default 0.
//	GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH (optional) cap on
//	                                  destinations per real Transfer
//	                                  call. Default 15.
//	GCPOOL_DISBURSE_POLL_INTERVAL     (optional) how often the
//	                                  disbursement engine runs a cycle,
//	                                  as a time.ParseDuration string.
//	                                  Default "10m".
func buildDisburseEngine(repo *db.Repository, m *metrics.Metrics) (engine *disburse.Engine, interval time.Duration, ok bool, err error) {
	addr := os.Getenv("GCPOOL_MONERO_WALLET_RPC_ADDR")
	if addr == "" {
		return nil, 0, false, nil
	}

	var opts []wallet.Option
	user := os.Getenv("GCPOOL_MONERO_WALLET_RPC_USER")
	pass := os.Getenv("GCPOOL_MONERO_WALLET_RPC_PASSWORD")
	if user != "" || pass != "" {
		opts = append(opts, wallet.WithDigestAuth(user, pass))
	}
	walletClient := wallet.NewMoneroWalletRPC(addr, opts...)

	cfg := disburse.Config{
		Wallet:                  walletClient,
		MaxDestinationsPerBatch: defaultDisburseMaxDestinationsPerBatch,
		Metrics:                 m,
	}
	if raw := os.Getenv("GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC"); raw != "" {
		v, parseErr := strconv.ParseInt(raw, 10, 64)
		if parseErr != nil {
			return nil, 0, false, fmt.Errorf("GCPOOL_DISBURSE_MIN_PAYOUT_ATOMIC: %w", parseErr)
		}
		cfg.MinPayoutAtomic = v
	}
	if raw := os.Getenv("GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH"); raw != "" {
		v, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			return nil, 0, false, fmt.Errorf("GCPOOL_DISBURSE_MAX_DESTINATIONS_PER_BATCH: %w", parseErr)
		}
		cfg.MaxDestinationsPerBatch = v
	}

	interval = defaultDisbursePollInterval
	if raw := os.Getenv("GCPOOL_DISBURSE_POLL_INTERVAL"); raw != "" {
		v, parseErr := time.ParseDuration(raw)
		if parseErr != nil {
			return nil, 0, false, fmt.Errorf("GCPOOL_DISBURSE_POLL_INTERVAL: %w", parseErr)
		}
		interval = v
	}

	return disburse.New(disburseRepositoryAdapter{repo: repo}, cfg), interval, true, nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("backend: %v", err)
	}
}

func run() error {
	dsn := os.Getenv("GCPOOL_DB_DSN")
	if dsn == "" {
		return errors.New("GCPOOL_DB_DSN environment variable is required")
	}

	listenAddr := os.Getenv("GCPOOL_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	authHeaderName := os.Getenv("GCPOOL_AUTH_HEADER_NAME")
	authHeaderValue := os.Getenv("GCPOOL_AUTH_HEADER_VALUE")

	network, err := parseNetwork(os.Getenv("GCPOOL_NETWORK"))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer pool.Close()

	repo := db.NewRepository(pool)

	// m is shared across the HTTP API handler, the unlocker, and the
	// payout calculator so every real Prometheus metric this process
	// produces (shares/blocks ingestion, unlocker poll passes, payout
	// cycles) is served on the one GET /metrics endpoint api.Handler
	// already exposes, rather than standing up a second registry/
	// listener just for the backend's internal poll loops.
	m := metrics.New(Version)
	handler := api.NewHandler(repositoryAdapter{repo: repo}, api.Config{
		AuthHeaderName:  authHeaderName,
		AuthHeaderValue: authHeaderValue,
		Network:         network,
		Version:         Version,
		Metrics:         m,
	})

	unlockerCfg, unlockerEnabled, err := buildUnlockerConfig()
	if err != nil {
		return fmt.Errorf("configuring block unlocker: %w", err)
	}
	unlockerCfg.Metrics = m

	payoutCalc, payoutEnabled, err := buildPayoutCalculator(repo, m)
	if err != nil {
		return fmt.Errorf("configuring payout calculator: %w", err)
	}
	if payoutEnabled {
		unlockerCfg.PayoutTrigger = payoutTrigger{calc: payoutCalc, network: networkDBString(network)}
		log.Print("backend: payout calculation enabled, wired into the block unlocker's matured-block trigger")
	} else {
		log.Print("backend: payout calculation disabled (GCPOOL_PAYOUT_FEE_ADDRESS not set); blocks will still be marked matured/unlocked, just never auto-paid out")
	}

	if unlockerEnabled {
		u := unlocker.New(unlockerRepositoryAdapter{repo: repo}, unlockerCfg)
		log.Printf("backend: block unlocker enabled, polling every %s for algos %v", unlockerCfg.PollInterval, sortedKeys(unlockerCfg.Coins))
		go u.RunLoop(ctx)
	} else {
		log.Print("backend: block unlocker disabled (neither GCPOOL_TARI_GRPC_ADDR nor GCPOOL_MONERO_RPC_ADDR is set)")
	}

	disburseEngine, disburseInterval, disburseEnabled, err := buildDisburseEngine(repo, m)
	if err != nil {
		return fmt.Errorf("configuring payout disbursement engine: %w", err)
	}
	if disburseEnabled {
		targets := []disburse.Target{{Algo: "RXM", Network: networkDBString(network)}}
		log.Printf("backend: payout disbursement engine enabled, polling every %s for %v", disburseInterval, targets)
		go disburseEngine.RunLoop(ctx, targets, disburseInterval)
	} else {
		log.Print("backend: payout disbursement engine disabled (GCPOOL_MONERO_WALLET_RPC_ADDR not set); pending_balance will still accrue, it just won't be auto-paid out on-chain")
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler.Mux(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("backend: listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		log.Print("backend: shutdown signal received, draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down http server: %w", err)
		}
		return <-errCh
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	}
}
