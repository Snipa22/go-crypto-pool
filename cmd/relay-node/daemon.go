// Copyright and license: see repository LICENSE (MIT).
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/protobuf/proto"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/relay"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/solo"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// Daemon is relay-node's entire runtime: a single configured
// solo.NodeClient (one physical node -- Tari GRPC or a
// monerod-JSON-RPC-compatible endpoint, see NewDaemon) polled for its
// chain tip, publishing the real, coin-specific block template onto
// the shared relay.Relay whenever the tip genuinely advances, plus a
// found-block subscribe handler that attempts local resubmission of
// any relayed block matching this instance's own configured Algo/
// Network. This is deliberately NOT a pool leaf (see this binary's
// own doc comment in main.go): no miner-facing port, no share
// validation, no backend transport, no wallet/payout logic -- see the
// brief this was built from (relay-node-brief.md) for the full scope
// discussion.
//
// The zero value is not usable; construct via NewDaemon. Safe for
// concurrent use (mu guards the only genuinely mutable state: the
// last-observed tip height).
type Daemon struct {
	// Node is this instance's single configured block-source
	// connection. For -coin=tari this is a *solo.GRPCNodeClient
	// talking to a real Tari base node; for -coin=monero it is a
	// *solo.MoneroNodeClient talking to either raw monerod (ALGO_XMR)
	// or a minotari_merge_mining_proxy listener (ALGO_RXM) -- see
	// solo.MoneroNodeClient's own doc comment for that same
	// baseURL-dual-purpose convention leaf-direct/leaf-solo already
	// rely on. Required.
	Node solo.NodeClient

	// Relay is the shared, best-effort NATS relay this instance
	// publishes fresh templates to and subscribes to found-block
	// broadcasts on. Safe to be a disabled (empty-URL) *relay.Relay --
	// every method used here is already a complete no-op in that case
	// (see relay.Relay.Enabled()'s doc comment). Required (construct
	// via relay.NewRelay even when disabled, never leave nil -- every
	// method on a nil *relay.Relay would panic, unlike a disabled
	// one).
	Relay *relay.Relay

	// Algo is this instance's single configured mining algorithm --
	// one of poolpb.Algo_ALGO_RXT/_C29/_SHA3X (Tari) or
	// poolpb.Algo_ALGO_RXM/_XMR (Monero-family). Every fetched
	// template and every relay message this instance publishes or
	// filters incoming messages against is tagged with this SAME
	// algo (via leaflib.AlgoWireName, the exact same wire-string
	// convention every other relay publisher/subscriber in this
	// codebase already uses -- see this package's own doc comment on
	// why relay-node does NOT invent a separate tagging scheme).
	Algo poolpb.Algo

	// Coin is "tari" or "monero" -- the coin FAMILY (not the single
	// algo) this instance serves, used only to pick the right
	// TemplateData-encoding/BlockData-decoding branch (see
	// templateDataForJob/handleFoundBlock below). Required.
	Coin string

	// Network is the lowercase network tag ("mainnet"/"testnet")
	// stamped on every published relay message and matched against
	// every received one -- mirrors every other binary's own
	// cfg.network convention exactly (see cmd/leaf-direct/main.go's
	// networkFromString/networkLabel).
	Network string

	// PayoutAddress is passed to every solo.NodeClient.GetBlockTemplate
	// call. This daemon does no payouts of its own -- see this
	// binary's own doc comment / the PR description for the explicit,
	// unresolved "what address convention should relay-node use"
	// design question this field's value represents.
	PayoutAddress string

	Logger *log.Logger

	mu             sync.Mutex
	lastHeight     uint64
	heightObserved bool
}

// NewDaemon constructs a ready-to-use Daemon. logger defaults to
// log.Default() if nil.
func NewDaemon(node solo.NodeClient, r *relay.Relay, algo poolpb.Algo, coin, network, payoutAddress string, logger *log.Logger) *Daemon {
	if logger == nil {
		logger = log.Default()
	}
	return &Daemon{
		Node: node, Relay: r, Algo: algo, Coin: coin, Network: network,
		PayoutAddress: payoutAddress, Logger: logger,
	}
}

// PollOnce fetches the real current chain-tip height from d.Node and,
// on a genuine height increase over the last-observed value, fetches
// a fresh real block template and best-effort-publishes it over
// d.Relay (see publishTemplateForHeight). Mirrors
// solo.JobManager.tipPollLoop's own "seed baseline on first
// observation, only act on a genuine increase" logic exactly (see
// job.go) -- this is a deliberate behavioral match, not a
// coincidence, so relay-node's own tip-poll semantics are consistent
// with every other leaf's.
//
// Returns a non-nil error only for a genuine GetTipInfo/
// GetBlockTemplate failure (both already logged here too) -- callers
// (the periodic ticker loop in Run, and the ZMQ fast-trigger wiring in
// main.go) treat a non-nil error as non-fatal: this daemon's own
// design (see relay-node-brief.md) never treats a transient upstream
// node hiccup as a reason to exit.
func (d *Daemon) PollOnce(ctx context.Context) error {
	height, err := d.Node.GetTipInfo(ctx)
	if err != nil {
		d.Logger.Printf("relay-node: tip poll failed: %v", err)
		return fmt.Errorf("relay-node: tip poll: %w", err)
	}

	d.mu.Lock()
	last := d.lastHeight
	observed := d.heightObserved
	d.mu.Unlock()

	if !observed {
		// First successful observation: just seed the baseline, same
		// as JobManager.tipPollLoop's identical first-tick behavior --
		// there is nothing to have moved FROM yet, so this is not a
		// real "new tip" event worth publishing.
		d.mu.Lock()
		d.lastHeight = height
		d.heightObserved = true
		d.mu.Unlock()
		d.Logger.Printf("relay-node: seeded baseline tip height=%d", height)
		return nil
	}

	if height <= last {
		// Unchanged (the overwhelmingly common case between two
		// consecutive polls) or a same-or-lower height (never treated
		// as a new tip) -- nothing to publish.
		return nil
	}

	d.Logger.Printf("relay-node: new tip detected (height %d -> %d), fetching fresh template", last, height)
	d.mu.Lock()
	d.lastHeight = height
	d.mu.Unlock()

	if err := d.publishTemplateForHeight(ctx, height); err != nil {
		d.Logger.Printf("relay-node: fetching/publishing template for height %d failed: %v", height, err)
		return err
	}
	return nil
}

// publishTemplateForHeight fetches a real, fresh block template from
// d.Node (the actual point of this daemon's "template push" job, see
// relay-node-brief.md) and best-effort-publishes it as a
// relay.TemplateMessage. A publish error is logged and returned but
// never treated as fatal by any caller -- matches every other
// relay.Relay.PublishTemplate call site in this codebase (see
// solo/job.go's publishTemplate doc comment).
func (d *Daemon) publishTemplateForHeight(ctx context.Context, height uint64) error {
	job, err := d.Node.GetBlockTemplate(ctx, d.PayoutAddress, d.Algo)
	if err != nil {
		return fmt.Errorf("relay-node: GetBlockTemplate: %w", err)
	}

	data, err := templateDataForJob(d.Coin, d.Node, job)
	if err != nil {
		// Not fatal to the poll loop -- log and still publish a bare
		// (empty-TemplateData) tip notification, mirroring
		// solo/job.go's own existing publishTemplate, whose
		// TemplateMessage.TemplateData is ALWAYS empty today (see
		// that function's doc comment) -- an empty TemplateData is
		// already a documented-valid, real production shape for this
		// exact message type, not a degraded error case.
		d.Logger.Printf("relay-node: could not encode real template payload for height %d (publishing a bare tip notification instead): %v", height, err)
	}

	algo := leaflib.AlgoWireName(d.Algo)
	msg := relay.TemplateMessage{
		Algo:         algo,
		Network:      d.Network,
		Height:       job.Height,
		TemplateData: data,
		Hash:         hex.EncodeToString(job.BlockHash),
	}
	if err := d.Relay.PublishTemplate(ctx, msg); err != nil {
		return fmt.Errorf("relay-node: PublishTemplate: %w", err)
	}
	d.Logger.Printf("relay-node: published template height=%d algo=%s network=%s template_data_bytes=%d", job.Height, algo, d.Network, len(data))
	return nil
}

// templateDataForJob encodes job's real, coin-specific upstream
// template payload as the []byte relay.TemplateMessage.TemplateData
// carries -- see this package's own doc comment (main.go) for the
// full design-decision writeup (also called out explicitly in the PR
// description, per the brief's own requirement):
//
//   - Tari (job.TemplateData holds a real, EXPORTED
//     *tari_generated.GetNewBlockResult -- see solo/node.go's
//     tariJobFromResult): proto.Marshal of that exact GRPC response.
//     This is the complete real upstream payload (Block/Header/Pow
//     chain and all), genuinely sufficient for a subscribing leaf's
//     own job-construction code to rebuild an equivalent Job from
//     scratch, since it is byte-for-byte the same message
//     solo.GetBlockTemplate itself just received from the base node.
//     Deliberately NOT delegated to
//     node.TemplateBytesForRelay(job) here even though the Monero
//     branch below now is: relay-node's -coin=tari NodeClient is
//     always a real *solo.GRPCNodeClient (see main.go's NewGRPCNodeClient
//     construction), and GRPCNodeClient.TemplateBytesForRelay is a
//     hard-coded "not supported" stub for every call (see node.go's
//     errRelayTemplateAdoptionNotSupported doc comment: leaf-solo's
//     per-operator payout addresses make relay-template ADOPTION
//     unsafe for that NodeClient, full stop) -- calling it here would
//     make every single Tari publish fail. This mirrors solo/job.go's
//     own publishTemplate, whose TemplateMessage.TemplateData is
//     likewise never populated via that path for a leaf-solo-style
//     NodeClient.
//   - Monero-family (RXM/XMR): delegates to
//     node.TemplateBytesForRelay(job), the EXACT SAME
//     solo.NodeClient method leaf-direct's own solo/job.go
//     (publishTemplateForJob/jobForSession) calls, and whose
//     *solo.MoneroNodeClient implementation (monero_node.go) encodes
//     the richer moneroRelayTemplateWire JSON struct (hashing_blob/
//     template_blob/seed_hash/prev_hash/difficulty/height/
//     reserved_offset) that MoneroNodeClient.JobFromTemplateBytes
//     decodes on the receiving side. Previously this branch instead
//     hand-rolled its own encoding of the raw, unconverted
//     job.RawTemplateBlob bytes -- a DIFFERENT, incompatible wire
//     shape publishing onto the SAME NATS subject a leaf-direct
//     instance's JobFromTemplateBytes was already trying (and
//     failing) to JSON-decode. See this fix's own PR description /
//     commit message for the full root-cause writeup (real production
//     NATS capture + log line).
//
// Returns an error (never a panic) if job.TemplateData does not hold
// the expected real Tari type for a Tari job, or if
// node.TemplateBytesForRelay errors or returns no data for a
// Monero-family job -- both indicate a genuinely malformed/unexpected
// Job from this daemon's own configured NodeClient, not something to
// silently paper over (publishTemplateForHeight's caller already
// treats a non-nil error here as non-fatal, publishing a bare tip
// notification instead -- see that function's doc comment).
func templateDataForJob(coin string, node solo.NodeClient, job *solo.Job) ([]byte, error) {
	switch coin {
	case coinTari:
		result, ok := job.TemplateData.(*tari_generated.GetNewBlockResult)
		if !ok || result == nil {
			return nil, fmt.Errorf("relay-node: job.TemplateData does not hold a real *tari_generated.GetNewBlockResult (got %T)", job.TemplateData)
		}
		data, err := proto.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("relay-node: marshaling Tari GetNewBlockResult: %w", err)
		}
		return data, nil
	case coinMonero:
		data, err := node.TemplateBytesForRelay(job)
		if err != nil {
			return nil, fmt.Errorf("relay-node: TemplateBytesForRelay: %w", err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("relay-node: TemplateBytesForRelay returned no data for a monero-family job (job.TemplateData missing or of an unexpected type)")
		}
		return data, nil
	default:
		return nil, fmt.Errorf("relay-node: unknown coin %q", coin)
	}
}

// Run launches the periodic tip-poll ticker loop, blocking until ctx
// is cancelled. interval must be > 0 (validated by main.go's flag
// parsing before this is ever called).
func (d *Daemon) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = d.PollOnce(ctx)
		}
	}
}

// SubscribeFoundBlocks registers d.handleFoundBlock on d.Relay's
// found-block subject (relay.DefaultSubject/Config.Subject -- see
// relay.Relay.Subscribe). A complete no-op (registers nothing, no-op
// unsubscribe, nil error) when d.Relay is disabled/unconfigured --
// see relay.Relay.Subscribe's own doc comment.
func (d *Daemon) SubscribeFoundBlocks() (unsubscribe func(), err error) {
	return d.Relay.Subscribe(d.handleFoundBlock)
}

// handleFoundBlock is relay.Relay.Subscribe's real callback: it is
// only ever invoked for a genuinely new (non-self, non-duplicate)
// relay.BlockMessage (see Subscribe's own doc comment for that
// filtering, already done before this is ever called). This method
// applies this daemon's OWN, additional Algo+Network filter (a shared
// relay subject fans out every coin/algo/network's found blocks to
// every subscriber -- see relay.go's package doc comment -- so each
// subscriber must filter for itself) and, only on a match, attempts a
// real local resubmission via d.Node.SubmitBlock.
//
// BlockData wire format (see main.go's doc comment / the PR
// description for the full writeup): internal/leaflib/direct/
// server.go's submitBlockDirect marshals Tari BlockData as
// proto.Marshal(*tari_generated.Block) (see that file's
// marshalBlockForRelay); internal/leaflib/direct/session.go's own
// ALGO_RXM/ALGO_XMR/etc block-find branch now publishes Monero-family
// BlockData as the raw, already-nonce-patched
// solo.MoneroCandidate.TemplateBlob bytes (no proto marshal step --
// MoneroCandidate is a plain byte slice, no proto involved). Both
// coin families are handled below via a real decode+resubmit.
func (d *Daemon) handleFoundBlock(msg relay.BlockMessage) {
	wantAlgo := leaflib.AlgoWireName(d.Algo)
	if msg.Algo != wantAlgo || msg.Network != d.Network {
		d.Logger.Printf("relay-node: ignoring relayed block (algo=%s network=%s height=%d) -- does not match this instance's configured algo=%s network=%s", msg.Algo, msg.Network, msg.Height, wantAlgo, d.Network)
		return
	}

	switch d.Coin {
	case coinTari:
		block, err := unmarshalTariBlockForRelay(msg.BlockData)
		if err != nil {
			d.Logger.Printf("relay-node: failed to unmarshal relayed Tari block payload (height=%d hash=%s): %v", msg.Height, msg.Hash, err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.Node.SubmitBlock(ctx, block); err != nil {
			d.Logger.Printf("relay-node: local resubmission FAILED for relayed block (height=%d hash=%s publisher=%s): %v", msg.Height, msg.Hash, msg.PublisherID, err)
			return
		}
		d.Logger.Printf("relay-node: local resubmission SUCCEEDED for relayed block (height=%d hash=%s publisher=%s)", msg.Height, msg.Hash, msg.PublisherID)
	case coinMonero:
		candidate := &solo.MoneroCandidate{TemplateBlob: msg.BlockData}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.Node.SubmitBlock(ctx, candidate); err != nil {
			d.Logger.Printf("relay-node: local resubmission FAILED for relayed monero-family block (height=%d hash=%s publisher=%s): %v", msg.Height, msg.Hash, msg.PublisherID, err)
			return
		}
		d.Logger.Printf("relay-node: local resubmission SUCCEEDED for relayed monero-family block (height=%d hash=%s publisher=%s)", msg.Height, msg.Hash, msg.PublisherID)
	default:
		d.Logger.Printf("relay-node: received a matching found-block relay message but this daemon's own coin %q is unrecognized -- skipping", d.Coin)
	}
}

// unmarshalTariBlockForRelay decodes data (a real
// proto.Marshal(*tari_generated.Block), see
// internal/leaflib/direct/server.go's marshalBlockForRelay -- the ONLY
// real producer of this wire shape today) back into a
// *tari_generated.Block. Deliberately duplicated here rather than
// imported from internal/leaflib/direct (that function is unexported
// there, and this repo's own established convention -- see solo/
// node.go's convertRawTemplateBlobToHashingBlob doc comment -- is to
// duplicate small, single-call-site helpers like this rather than
// export them across an otherwise-unrelated package boundary).
func unmarshalTariBlockForRelay(data []byte) (*tari_generated.Block, error) {
	var block tari_generated.Block
	if err := proto.Unmarshal(data, &block); err != nil {
		return nil, err
	}
	return &block, nil
}
