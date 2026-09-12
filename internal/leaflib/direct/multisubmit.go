// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"github.com/Snipa22/go-tari-lib/nodeGRPC"
)

// blockSubmitClient is the minimal set of operations
// MultiNodeSubmitter needs from one node's own independent GRPC
// connection. *nodeGRPC.Client (github.com/Snipa22/go-tari-lib, the
// real per-call-injectable client type — NOT the older
// package-level-singleton-only nodeGRPC.InitNodeGRPC API that
// go-tari-grpc-lib/v3 alone exposes, which cannot support N distinct
// concurrent node connections) satisfies this directly. Defined as an
// interface purely so tests can inject fakes without dialing any real
// GRPC connection.
type blockSubmitClient interface {
	SubmitBlock(block *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error)
	Close() error
}

// NodeSubmitResult is one configured node's own real, individual
// outcome from a MultiNodeSubmitter.SubmitBlock call — see that
// method's doc comment for why every node's result is reported
// individually rather than collapsed into a single bool.
//
// BlockHash is the base node's own real, canonical block hash — the
// raw bytes of tari_generated.SubmitBlockResponse.block_hash, i.e.
// the base node's own GRPC SubmitBlock RPC response, NOT a locally
// computed placeholder. It is only populated when Accepted is true
// (a rejected/errored submission has no response to read a hash
// from); callers needing the real hash for backend reporting/relay
// should use realBlockHashHex on the results slice rather than
// picking an arbitrary result's BlockHash directly.
type NodeSubmitResult struct {
	Address   string
	Accepted  bool
	Err       error
	BlockHash []byte
}

// realBlockHashHex extracts the real, base-node-confirmed block hash
// (hex-encoded) from results: the first accepted result carrying a
// non-empty BlockHash — see NodeSubmitResult's doc comment (this is
// the base node's own SubmitBlockResponse.block_hash, not a locally
// computed nonce/height placeholder). Returns "" if no accepted
// result carries a hash (e.g. every configured node rejected/
// errored).
//
// Every accepting node should report the identical real chain hash
// for the same accepted block; if a later accepted result reports a
// DIFFERENT non-empty hash than the one already selected, that's
// logged as a warning (a serious anomaly worth investigating) but
// does not change the returned value — the first one found still
// wins, per this function's own contract.
func realBlockHashHex(results []NodeSubmitResult, logger *log.Logger) string {
	var hash string
	for _, r := range results {
		if !r.Accepted || len(r.BlockHash) == 0 {
			continue
		}
		h := hex.EncodeToString(r.BlockHash)
		if hash == "" {
			hash = h
			continue
		}
		if h != hash && logger != nil {
			logger.Printf("direct: WARNING: node %s reported block hash %s, differing from already-selected real hash %s for the same accepted block submission — every accepting node should report the identical real chain hash", r.Address, h, hash)
		}
	}
	return hash
}

// MultiNodeSubmitter submits a found block to multiple configured Tari
// base node GRPC addresses IN PARALLEL, minimizing propagation lag/
// orphan risk across the real network (Alex, 2026-08-22: "direct is
// always better [than relay]" — this is the direct half of that
// statement; see internal/leaflib/relay for the secondary,
// best-effort relay-broadcast half).
//
// Each configured address gets its own independent *nodeGRPC.Client
// connection (github.com/Snipa22/go-tari-lib's real injectable Client
// type) — this is structurally required: N distinct node addresses
// submitted to concurrently cannot share go-tari-grpc-lib/v3's
// package-level singleton connection (there is exactly one shared
// connection/address for the whole process in that older API).
type MultiNodeSubmitter struct {
	mu      sync.RWMutex
	clients map[string]blockSubmitClient
	logger  *log.Logger
}

// NewMultiNodeSubmitter dials addresses (deduplicated) via
// nodeGRPC.NewClient, one independent Client per address. Per
// go-tari-lib's own doc comment on NewClient/grpc.NewClient: this
// performs no blocking I/O — connections are established lazily on
// first real RPC use — so this constructor itself cannot fail due to a
// currently-unreachable node; an address that never comes up simply
// contributes real, individually-reported connection errors to every
// future SubmitBlock call's NodeSubmitResult for that address, without
// preventing submission to any OTHER configured address.
func NewMultiNodeSubmitter(addresses []string, logger *log.Logger) (*MultiNodeSubmitter, error) {
	if logger == nil {
		logger = log.Default()
	}
	clients := make(map[string]blockSubmitClient, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, addr := range addresses {
		if addr == "" {
			continue
		}
		if _, dup := seen[addr]; dup {
			continue
		}
		seen[addr] = struct{}{}
		c, err := nodeGRPC.NewClient(addr)
		if err != nil {
			return nil, fmt.Errorf("direct: dialing multi-submit node %s: %w", addr, err)
		}
		clients[addr] = c
	}
	return &MultiNodeSubmitter{clients: clients, logger: logger}, nil
}

// newMultiNodeSubmitterForTest constructs a MultiNodeSubmitter directly
// from an already-built client map, bypassing any real dialing — used
// by multisubmit_test.go to inject fake blockSubmitClients.
func newMultiNodeSubmitterForTest(clients map[string]blockSubmitClient, logger *log.Logger) *MultiNodeSubmitter {
	if logger == nil {
		logger = log.Default()
	}
	return &MultiNodeSubmitter{clients: clients, logger: logger}
}

// Addresses returns the currently-configured node addresses (sorted
// order not guaranteed), purely for logging/diagnostics at startup.
func (m *MultiNodeSubmitter) Addresses() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, 0, len(m.clients))
	for addr := range m.clients {
		out = append(out, addr)
	}
	return out
}

// SubmitBlock submits block to every configured node address IN
// PARALLEL (real goroutines + a real, bounded wait via sync.WaitGroup
// — never sequential dispatch, since the whole point is minimizing
// propagation time across every configured node simultaneously), and
// returns:
//
//   - results: EVERY configured node's own real, individual outcome
//     (accepted, or the real error it returned/timed out with) — a
//     partial failure is honestly reported per-node, not collapsed away.
//   - success: true if AT LEAST ONE configured node accepted the
//     block (a single accepting node is sufficient for the block to
//     enter the real network — see this type's doc comment) — false
//     only if every configured node rejected/errored/timed out, or no
//     nodes are configured at all.
//
// ctx bounds the whole parallel dispatch: if ctx is cancelled/expires
// before a given node's goroutine finishes, that node's result records
// ctx.Err() rather than the call blocking indefinitely (this directly
// guards against the "no timeouts anywhere" bug class called out
// elsewhere in this codebase's own review notes).
func (m *MultiNodeSubmitter) SubmitBlock(ctx context.Context, block *tari_generated.Block) (results []NodeSubmitResult, success bool) {
	m.mu.RLock()
	clients := make(map[string]blockSubmitClient, len(m.clients))
	for addr, c := range m.clients {
		clients[addr] = c
	}
	m.mu.RUnlock()

	if len(clients) == 0 {
		return nil, false
	}

	type namedResult struct {
		addr string
		res  NodeSubmitResult
	}
	resultCh := make(chan namedResult, len(clients))

	var wg sync.WaitGroup
	for addr, client := range clients {
		wg.Add(1)
		go func(addr string, client blockSubmitClient) {
			defer wg.Done()
			resultCh <- namedResult{addr: addr, res: submitToOneNode(ctx, addr, client, block)}
		}(addr, client)
	}

	// Wait for every goroutine to finish (each individually respects
	// ctx via submitToOneNode's own select), then drain the buffered
	// channel — len(clients) sends are already guaranteed above, so
	// this never blocks past that.
	wg.Wait()
	close(resultCh)

	results = make([]NodeSubmitResult, 0, len(clients))
	for nr := range resultCh {
		results = append(results, nr.res)
		if nr.res.Accepted {
			success = true
		}
		if m.logger != nil {
			if nr.res.Accepted {
				m.logger.Printf("direct: multi-node block submit ACCEPTED by %s", nr.res.Address)
			} else {
				m.logger.Printf("direct: multi-node block submit rejected/failed at %s: %v", nr.res.Address, nr.res.Err)
			}
		}
	}
	return results, success
}

// submitToOneNode runs one node's real SubmitBlock call on the calling
// goroutine (SubmitBlock above already parallelizes across nodes by
// running one of these per goroutine), respecting ctx cancellation via
// a select against a completion channel so a slow/hanging node can
// never make the overall dispatch block past ctx's own
// deadline/cancellation.
func submitToOneNode(ctx context.Context, addr string, client blockSubmitClient, block *tari_generated.Block) NodeSubmitResult {
	done := make(chan NodeSubmitResult, 1)
	go func() {
		resp, err := client.SubmitBlock(block)
		res := NodeSubmitResult{Address: addr, Accepted: err == nil, Err: err}
		if err == nil {
			res.BlockHash = resp.GetBlockHash()
		}
		done <- res
	}()
	select {
	case r := <-done:
		return r
	case <-ctx.Done():
		return NodeSubmitResult{Address: addr, Accepted: false, Err: ctx.Err()}
	}
}

// Close closes every configured node's underlying GRPC connection.
func (m *MultiNodeSubmitter) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	for addr, c := range m.clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("direct: closing multi-submit client %s: %w", addr, err)
		}
	}
	return firstErr
}
