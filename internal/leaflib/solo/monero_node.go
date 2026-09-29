// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// minReservedOffsetHeadroom is the largest byte offset any XNP-proxy-
// shape field actually needs into the reservation region: client_
// nonce_offset = ReservedOffset+12 (session.go's jobPayload,
// ALGO_RXM branch) is bigger than client_pool_offset's ReservedOffset
// +8, so it is the real binding constraint this bounds check must
// satisfy.
const minReservedOffsetHeadroom = 12

// MoneroNodeClient is the production NodeClient implementation for
// Monero (ALGO_RXM), backed by a real monerod JSON-RPC 2.0 connection
// ("/json_rpc" — get_block_template, submit_block, get_info). It is the
// direct Monero counterpart of GRPCNodeClient (node.go) and lives in
// this package (rather than a separate one) precisely so that both
// leaf-solo and leaf-direct can construct/embed the SAME NodeClient
// implementation, per this codebase's coin-agnostic-core goal (see
// node.go's package doc comment).
//
// CRITICAL CORRECTNESS NOTE — nonce offset is NOT a fixed constant.
// Monero's real blockhashing_blob/blocktemplate_blob header (confirmed
// from Monero's own core developer, moneromooo-monero, on
// github.com/monero-project/monero/issues/3302) is:
//
//	struct block_header {
//	  uint8_t major_version;   // varint (LEB128, same encoding as protobuf/Go's binary.Uvarint)
//	  uint8_t minor_version;   // varint
//	  uint64_t timestamp;      // varint — GROWS over time, so its encoded length can grow too
//	  crypto::hash prev_id;    // fixed 32 bytes
//	  uint32_t nonce;          // fixed 4 bytes
//	};
//
// major_version/minor_version/timestamp are real LEB128 varints of
// VARIABLE length. The commonly-cited "nonce is always at byte offset
// 39" is explicitly called out by that same Monero developer as "a bit
// of a hack which works for a fair amount of time still" — not a stable
// constant. Hardcoding 39 is a real latent bug: it silently produces a
// wrong nonce offset (and therefore wrong/rejected candidate blocks)
// the moment timestamp's own varint encoding grows past 4 bytes (this
// has already happened once historically for Monero mainnet/testnet).
//
// This implementation therefore ALWAYS walks the three real varints
// itself (parseMoneroBlockHeaderNonceOffset, below) on every single
// call, for whatever blockhashing_blob is in hand at that moment — it
// never caches or assumes a stable offset across calls, jobs, or chain
// heights.
type MoneroNodeClient struct {
	baseURL string
	client  *http.Client
	nowFunc func() time.Time

	// reservationUnavailableCounter, if non-nil (wired via
	// SetReservationUnavailableMetric — cmd/leaf-solo and
	// cmd/leaf-direct's main.go, or their respective Server.
	// EnableMetrics, do this after constructing both the metrics
	// registry and this client), is incremented once per
	// GetBlockTemplate call whose real ReservedOffset+12 does not fit
	// within the real returned blocktemplate_blob length (see
	// GetBlockTemplate's bounds check below and Job.
	// ReservedOffsetUsable's doc comment for the full rationale).
	// Left nil (a no-op) in every test/call site that doesn't wire a
	// counter, matching this field's own "optional observability
	// hook" nil-is-safe convention.
	reservationUnavailableCounter prometheus.Counter

	// instanceID is this leaf process's own real per-instance
	// disambiguator, stamped into every template this client ever
	// hands back (see stampInstanceID below) at
	// ReservedOffset+4:ReservedOffset+8 -- the EXACT reserved-region
	// sub-offset the real, live legacy nodejs-pool-sxmr reference
	// (lib/coins/xmr.js, `instanceId.copy(this.buffer,
	// this.reserveOffset + 4, 0, 4)`) uses for the identical purpose:
	// so that multiple pool-server entities (or, in this codebase,
	// multiple leaf-direct/leaf-solo processes sharing one relayed
	// template via TemplateBytesForRelay/JobFromTemplateBytes) never
	// serve byte-identical coinbases to their own downstream
	// sessions.
	//
	// DELIBERATELY FIXED FOR THE WHOLE PROCESS LIFETIME -- NOT
	// rotated periodically. Legacy nodejs-pool-sxmr rotates its own
	// instanceId every 100 blocks; that rotation was a
	// legacy-cluster-specific detail (multiple worker processes
	// sharing one Redis-backed pool state, needing to periodically
	// re-randomize to avoid a different class of collision across
	// its own worker pool). A single Go process here has no such
	// multi-worker-sharing concern: this instanceID's only job is to
	// distinguish THIS process's own served coinbases from every
	// OTHER leaf process's, for as long as this process is running.
	// Keeping it fixed for the process's whole lifetime is simpler,
	// sufficient for that purpose, and easier to reason about/log
	// (see NewMoneroNodeClient and the cmd/leaf-direct, cmd/leaf-solo
	// startup log lines) than reimplementing legacy's rotation
	// scheme would be -- this is an intentional design choice, not
	// an oversight.
	instanceID [4]byte
}

// SetReservationUnavailableMetric wires a Prometheus counter that this
// client increments every time a real monerod get_block_template
// response's ReservedOffset does not fit within its own returned
// blocktemplate_blob (see GetBlockTemplate's bounds check and Job.
// ReservedOffsetUsable's doc comment). Safe to call with nil (clears
// the hook back to a no-op). Not safe to call concurrently with
// in-flight GetBlockTemplate calls on the same client.
func (c *MoneroNodeClient) SetReservationUnavailableMetric(counter prometheus.Counter) {
	c.reservationUnavailableCounter = counter
}

// SetInstanceID overrides this client's own instanceID (see that
// field's doc comment) with an explicit 4-byte value, for tests that
// need two (or more) MoneroNodeClient instances with deterministic,
// DIFFERENT instance IDs (e.g. proving two clients stamp genuinely
// distinct bytes into an otherwise-identical template -- see
// monero_node_test.go/monero_node_relay_test.go). NewMoneroNodeClient
// already populates a real crypto/rand-drawn instanceID at
// construction; production call sites never need to call this --
// it exists purely for deterministic test construction, mirroring
// this file's existing SetReservationUnavailableMetric precedent for
// exactly that kind of test-only override. Not safe to call
// concurrently with in-flight GetBlockTemplate/JobFromTemplateBytes
// calls on the same client.
func (c *MoneroNodeClient) SetInstanceID(id [4]byte) {
	c.instanceID = id
}

// InstanceID returns this client's own real, process-lifetime-fixed
// 4-byte instance identifier (see that field's doc comment) --
// exported so a deployed leaf's own startup log line
// (cmd/leaf-direct/main.go, cmd/leaf-solo/main.go) can report exactly
// which bytes this running process is actually stamping into every
// template it serves.
func (c *MoneroNodeClient) InstanceID() [4]byte {
	return c.instanceID
}

// NewMoneroNodeClient returns a MoneroNodeClient talking to the real
// monerod JSON-RPC endpoint at baseURL (e.g. "http://148.163.90.157:28081"
// — no trailing slash or "/json_rpc" suffix required, this type appends
// it itself).
//
// Draws a real, fresh 4-byte instanceID via crypto/rand.Read, once,
// right here -- see that field's doc comment for the full rationale
// (mirrors legacy nodejs-pool-sxmr's own crypto.randomBytes(4)
// instanceId shape, fixed for this process's whole lifetime rather
// than legacy's periodic rotation). A crypto/rand.Read failure here is
// effectively unrecoverable (the OS's CSPRNG is unavailable) -- panic
// rather than silently falling back to a predictable/zero instanceID,
// which would defeat this field's entire purpose. This mirrors this
// same package's existing coinbaseExtraRandomSuffix precedent
// (node.go) for the identical "crypto/rand failure is unrecoverable,
// panic rather than degrade silently" call.
func NewMoneroNodeClient(baseURL string) *MoneroNodeClient {
	c := &MoneroNodeClient{
		baseURL: bytesTrimSuffix(baseURL, "/"),
		client:  &http.Client{Timeout: 30 * time.Second},
		nowFunc: time.Now,
	}
	if _, err := cryptorand.Read(c.instanceID[:]); err != nil {
		panic(fmt.Sprintf("solo: monero: crypto/rand.Read failed while generating this leaf's per-process instance ID: %v", err))
	}
	return c
}

// bytesTrimSuffix trims a single trailing suffix from s if present —
// a tiny local helper so this file has no extra "strings" import for
// exactly one call site.
func bytesTrimSuffix(s, suffix string) string {
	if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
		return s[:len(s)-len(suffix)]
	}
	return s
}

// moneroRPCRequest is a real, minimal Monero daemon JSON-RPC 2.0
// envelope — monerod's /json_rpc endpoint (get_block_template,
// submit_block, get_last_block_header, ...) uses this exact shape.
type moneroRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      string `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// moneroRPCError is monerod's real JSON-RPC error shape, e.g.
// {"code":-6,"message":"Wrong block blob"} for a rejected submit_block.
type moneroRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *moneroRPCError) Error() string {
	return fmt.Sprintf("monero daemon rpc error %d: %s", e.Code, e.Message)
}

// moneroRPCResponse is the generic JSON-RPC 2.0 response envelope;
// Result is left as json.RawMessage so each call site unmarshals into
// its own real result type.
//
// ID is deliberately json.RawMessage, NOT string. Real production
// evidence (live journalctl from leaf-solo-rxm.service against a real
// monerod testnet daemon) confirmed that monerod's submit_block
// response echoes "id" back as a bare JSON NUMBER, not a string —
// even though get_block_template/get_info happen to echo it as a
// string (matching the "0" string this client's own call() sends as
// its request id). Real-world monerod RPC handling is evidently not
// internally consistent about the wire type of an echoed id across
// its own different methods, and JSON-RPC 2.0 itself only requires id
// to be a string, number, or null — never assume it's always one
// specific Go type. Hardcoding ID as `string` meant json.Unmarshal
// failed at the TOP-LEVEL struct decode for every single submit_block
// response, before rpcResp.Error/rpcResp.Result were ever inspected —
// masking whether the real daemon actually accepted or rejected the
// block behind a spurious local decode error instead. Nothing in this
// package ever reads rpcResp.ID after decode (confirmed by grep), so
// json.RawMessage is the correct, lowest-risk fix: it accepts any
// valid JSON id shape (string, number, or null) with zero downstream
// type-assertion needed.
type moneroRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *moneroRPCError `json:"error"`
}

// callRaw performs one real JSON-RPC 2.0 request against
// baseURL+"/json_rpc" and returns the raw, still-undecoded "result"
// payload on success (rpcResp.Error != nil is still surfaced as a
// real, failing error here exactly as call() does) -- factored out of
// call() (below) so SubmitBlockAuxChains can apply its own
// wire-shape-tolerant decode to the raw bytes (see that method's own
// doc comment) instead of being forced through call()'s single
// generic json.Unmarshal-into-out shape.
func (c *MoneroNodeClient) callRaw(ctx context.Context, method string, params any) (json.RawMessage, error) {
	reqBody, err := json.Marshal(moneroRPCRequest{
		JSONRPC: "2.0",
		ID:      "0",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return nil, fmt.Errorf("solo: monero: marshaling %s request: %w", method, err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/json_rpc", bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("solo: monero: building %s request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: %s request failed: %w", method, err)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: reading %s response body: %w", method, err)
	}

	var rpcResp moneroRPCResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return nil, fmt.Errorf("solo: monero: decoding %s response (status %d): %w", method, httpResp.StatusCode, err)
	}
	if rpcResp.Error != nil {
		return nil, rpcResp.Error
	}
	return rpcResp.Result, nil
}

// call performs one real JSON-RPC 2.0 request against baseURL+"/json_rpc"
// and unmarshals a successful result into out (which may be nil if the
// caller doesn't need the result body, e.g. a bare status check).
func (c *MoneroNodeClient) call(ctx context.Context, method string, params any, out any) error {
	result, err := c.callRaw(ctx, method, params)
	if err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(result, out); err != nil {
			return fmt.Errorf("solo: monero: decoding %s result payload: %w", method, err)
		}
	}
	return nil
}

// moneroGetBlockTemplateResult is monerod's real get_block_template
// result shape (confirmed via a real live call against
// 148.163.90.157:28081 this session — see monero_node_test.go).
type moneroGetBlockTemplateResult struct {
	BlockHashingBlob  string `json:"blockhashing_blob"`
	BlockTemplateBlob string `json:"blocktemplate_blob"`
	Difficulty        uint64 `json:"difficulty"`
	Height            uint64 `json:"height"`
	PrevHash          string `json:"prev_hash"`
	ReservedOffset    int    `json:"reserved_offset"`
	SeedHash          string `json:"seed_hash"`
	SeedHeight        uint64 `json:"seed_height"`
	Status            string `json:"status"`
}

// moneroGetInfoResult is monerod's real get_info result shape — only
// the height field is needed by GetTipInfo.
type moneroGetInfoResult struct {
	Height uint64 `json:"height"`
}

// stampInstanceID is the ONE shared, unexported implementation both
// GetBlockTemplate (local fetch) and JobFromTemplateBytes
// (relay-adopted) call to write this client's OWN c.instanceID into
// the reserved region of a template it is about to hand back to a
// caller -- see MoneroNodeClient.instanceID's doc comment for the
// full production-bug rationale (multiple pool entities/leaves
// sharing one wallet address, or one leaf adopting another's relayed
// template, must never serve byte-identical coinbases).
//
// Mirrors the real, confirmed legacy nodejs-pool-sxmr layout EXACTLY:
// reservedOffset+4 (4 bytes) is instanceId's own slot within the
// broader |+0 minerNonce/extraNonce|+4 instanceId|+8 clientPoolNonce|
// +12 clientNonce| reserved-region layout (lib/coins/xmr.js) -- this
// package's own minReservedOffsetHeadroom (12) already exists
// specifically to cover that same full layout (client_nonce_offset =
// ReservedOffset+12 is the binding XNP-proxy constraint -- see that
// const's doc comment), so no new headroom constant is needed here.
//
// Always writes into templateBlob's own reserved region (bounds-
// checked below). ADDITIONALLY writes the identical bytes into
// hashingBlob too, IF AND ONLY IF the 4-byte stamp window
// (reservedOffset+4:reservedOffset+8) falls entirely within the
// shared header prefix both GetBlockTemplate and JobFromTemplateBytes
// already verify byte-for-byte equal
// (hashingBlob[:nonceOffset] == templateBlob[:nonceOffset]) -- this is
// required to keep that SAME equality check holding after this
// stamp, per this task's own explicit instruction (see this package's
// dispatch brief, section 3): "if stamping into that shared-prefix
// region would now make hashingBlob and templateBlob diverge ...
// stamp into BOTH blobs identically so the existing equality check
// still holds."
//
// REAL PRODUCTION DATA (this is the offset relationship confirmed and
// verified live against 148.163.90.157:28081 testnet, height 3097257,
// as part of this fix): reservedOffset=131, nonceOffset=39,
// len(blockhashing_blob)=76 -- i.e. reservedOffset+4=135 is both AFTER
// nonceOffset (39) and past the END of hashingBlob entirely (76). This
// is expected from Monero's own real block serialization, not a fluke
// of that one call: blockhashing_blob is a short, fixed-shape derived
// blob (header + merkle_root + tx-count varint, ~76-78 bytes) that
// never contains the coinbase transaction's own tx_extra bytes at
// all, whereas the reserved region lives INSIDE the coinbase tx
// (which blocktemplate_blob's real block serialization places
// immediately AFTER the header, i.e. always past nonceOffset+4 in
// genuine daemon responses). So in real production traffic, this
// function stamps templateBlob ONLY, and the hashingBlob branch below
// is simply never taken.
//
// It IS taken, however, for this package's own existing small,
// synthetic test fixtures (e.g. realFixtureBlobHex,
// monero_node_test.go/monero_node_relay_test.go), which reuse one
// short byte-identical blob as BOTH hashingBlob and templateBlob with
// small hand-picked reservedOffset values that legitimately DO fall
// before nonceOffset -- exercising this exact "stamp both" branch is
// why that check exists at all, rather than being unreachable
// dead code.
//
// Returns reservationUsable=false (and writes nothing to either blob)
// under the EXACT SAME condition GetBlockTemplate's own pre-existing
// XNP-proxy-reservation bounds check used (reservedOffset within
// [0, len(templateBlob)-minReservedOffsetHeadroom]) -- this function
// is now the single, canonical place that check lives; callers no
// longer duplicate it.
func (c *MoneroNodeClient) stampInstanceID(hashingBlob, templateBlob []byte, reservedOffset, nonceOffset int) (reservationUsable bool) {
	reservationUsable = reservedOffset >= 0 && reservedOffset+minReservedOffsetHeadroom <= len(templateBlob)
	if !reservationUsable {
		return false
	}
	copy(templateBlob[reservedOffset+4:reservedOffset+8], c.instanceID[:])
	// Shared-header-prefix case (see doc comment above): only reached
	// by this package's own small synthetic test fixtures today, real
	// daemon responses' reservedOffset is always well past nonceOffset.
	if reservedOffset+8 <= nonceOffset && reservedOffset+8 <= len(hashingBlob) {
		copy(hashingBlob[reservedOffset+4:reservedOffset+8], c.instanceID[:])
	}
	return true
}

// GetBlockTemplate implements NodeClient. algo is expected to be
// poolpb.Algo_ALGO_RXM (Monero's own RandomX PoW family, merge-mined)
// OR any of the standalone monerod-family algos this MoneroNodeClient
// now also serves (ALGO_XMR and the other confirmed
// internal/coinprofile.Registry entries -- see IsMoneroFamilyAlgo) —
// any other value is rejected, since this NodeClient only ever
// produces monerod-shaped (get_block_template/submit_block) block
// templates.
func (c *MoneroNodeClient) GetBlockTemplate(ctx context.Context, payoutAddress string, algo poolpb.Algo) (*Job, error) {
	if !IsMoneroFamilyAlgo(algo) {
		return nil, fmt.Errorf("solo: MoneroNodeClient does not support fetching block templates for algo %v (only ALGO_RXM or a registered monerod-compatible coin algo is supported)", algo)
	}
	if payoutAddress == "" {
		return nil, fmt.Errorf("solo: monero: GetBlockTemplate requires a non-empty payoutAddress")
	}

	var result moneroGetBlockTemplateResult
	err := c.call(ctx, "get_block_template", map[string]any{
		"wallet_address": payoutAddress,
		// reserve_size mirrors the real reference miners' typical
		// reservation for pool extranonce insertion into the
		// coinbase tx (see node.go's NodeClient doc comment —
		// reserved_offset is a SEPARATE concept from the nonce
		// offset this file parses for). This leaf DOES now use the
		// reservation for XNP-proxy-detected sessions: the parsed
		// result.ReservedOffset below is threaded onto both
		// moneroTemplateData and Job.ReservedOffset so session.go's
		// jobPayload can surface reserved_offset/client_nonce_offset/
		// client_pool_offset on the wire for a login whose agent
		// string identifies it as an xmr-node-proxy-class multi-tier
		// proxy client (see the real nodejs-pool-sxmr reference,
		// lib/pool.js ~211-231/478-548 and lib/coins/xmr.js ~137-152)
		// — an ordinary xmrig-class miner never sees these fields
		// (see protocol.go's JobPayload doc comment). Reserving space
		// unconditionally (regardless of whether any given session
		// turns out to be XNP-proxy-detected) also keeps the
		// template's own coinbase shape stable, which was this
		// field's original rationale before that use existed.
		"reserve_size": 60,
	}, &result)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: get_block_template: %w", err)
	}
	if result.Status != "OK" {
		return nil, fmt.Errorf("solo: monero: get_block_template returned non-OK status %q", result.Status)
	}

	hashingBlob, err := hex.DecodeString(result.BlockHashingBlob)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: blockhashing_blob is not valid hex: %w", err)
	}
	templateBlob, err := hex.DecodeString(result.BlockTemplateBlob)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: blocktemplate_blob is not valid hex: %w", err)
	}
	seedHash, err := hex.DecodeString(result.SeedHash)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: seed_hash is not valid hex: %w", err)
	}
	prevHash, err := hex.DecodeString(result.PrevHash)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: prev_hash is not valid hex: %w", err)
	}

	// Real, per-call varint parse — never assumed/cached. See this
	// file's package doc comment.
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(hashingBlob)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: parsing nonce offset from blockhashing_blob: %w", err)
	}
	if nonceOffset+4 > len(templateBlob) || nonceOffset+4 > len(hashingBlob) {
		return nil, fmt.Errorf("solo: monero: parsed nonce offset %d + 4 exceeds blob length (hashing=%d, template=%d)", nonceOffset, len(hashingBlob), len(templateBlob))
	}
	// Confirmed (see this file's package doc comment and the real
	// live comparison in monero_node_test.go) that blockhashing_blob
	// and blocktemplate_blob share an identical header prefix through
	// the nonce field — verify that here, defensively, on every real
	// call, rather than merely assuming it holds for whatever daemon
	// this client happens to be pointed at.
	if !bytes.Equal(hashingBlob[:nonceOffset], templateBlob[:nonceOffset]) {
		return nil, fmt.Errorf("solo: monero: blockhashing_blob and blocktemplate_blob header prefixes (through the parsed nonce offset %d) do not match — refusing to build a job from mismatched blobs", nonceOffset)
	}

	// XNP-PROXY RESERVATION BOUNDS CHECK, AND per-leaf-instance-ID
	// STAMPING — the actual fix for two real, confirmed production
	// bugs, both hinging on the exact same bounds check: (1) see
	// Job.ReservedOffsetUsable's doc comment for the full
	// live-reproduction evidence that an out-of-bounds
	// ReservedOffset must degrade gracefully rather than corrupt
	// data or fail the whole call (leaf-proxy correctly rejected a
	// job with "offset=179 blob_len=76" rather than corrupting data,
	// because monerod's own real reserved_offset for that
	// low-tx-volume testnet block did not actually fit within its
	// own returned blocktemplate_blob); (2) see stampInstanceID's
	// and MoneroNodeClient.instanceID's doc comments for why this
	// SAME reserved region also carries this leaf's own instance ID,
	// so that multiple pool leaves sharing one payout address never
	// serve byte-identical coinbases to their own downstream miners.
	//
	// This is deliberately NOT folded into the fmt.Errorf checks
	// above: an out-of-bounds ReservedOffset is a defect in
	// optional job features (the XNP-proxy-shape fields, and the
	// instance-ID stamp), not in the template as a whole — an
	// ordinary xmrig-class miner never reads ReservedOffset at all
	// (it mines against job.Header/the converted blockhashing_blob
	// via the completely separate nonceOffset already validated
	// above), so failing the WHOLE GetBlockTemplate call over this
	// would incorrectly take down normal mining every time monerod
	// returns a genuinely short, low-tx coinbase-only block.
	// Degrading gracefully (job still returned, ReservedOffsetUsable
	// left false, instance-ID stamp skipped) keeps normal mining
	// unaffected and only removes the proxy-shape fields/instance-ID
	// disambiguation for this one job.
	reservationUsable := c.stampInstanceID(hashingBlob, templateBlob, result.ReservedOffset, nonceOffset)
	if !reservationUsable {
		log.Printf("solo: monero: get_block_template's real reservation region (offset=%d) does not fit in the returned template blob (len=%d) -- XNP-proxy shape and per-instance stamp omitted for this job, height=%d", result.ReservedOffset, len(templateBlob), result.Height)
		if c.reservationUnavailableCounter != nil {
			c.reservationUnavailableCounter.Inc()
		}
	}

	// job_id must be a purely random, opaque wire token -- NEVER
	// derived from prevHash/height/any template content (see this
	// package's former moneroJobID, removed as part of the real
	// production bugfix documented on newRandomHexID's call sites
	// throughout this codebase). The concrete bug this closes: at an
	// UNMOVED tip, refreshLoop's periodic InvalidateAll (job.go)
	// forces a brand new GetBlockTemplate call whose PrevHash/Height
	// are IDENTICAL to the previous call's, but whose
	// RawTemplateBlob/ReservedOffset/reservation region are a
	// genuinely different template -- a prevHash+height-derived ID
	// collided across that rotation, so JobHistory.Record
	// (wireshape.go) treated the collision as "refresh in place" (the
	// LEGITIMATE case it's designed for -- RestampDifficulty reusing
	// an ID on purpose when only difficulty changed) and silently
	// overwrote the session's job-history entry to point at the NEW
	// template while a client's in-flight submit still referenced the
	// OLD job_id. ownJob(id) then found an entry (the ID collided) but
	// it pointed at the wrong RawTemplateBlob/ReservedOffset, so
	// nonce-patching produced a hash that was never actually mined --
	// RandomX re-validation correctly rejected it, presenting as
	// periodic reject bursts at job rotation. A purely random ID has
	// no such collision risk: two calls with byte-identical
	// prevHash/height now always mint two byte-distinct job IDs.
	id, err := newRandomHexID()
	if err != nil {
		return nil, fmt.Errorf("solo: monero: generating random job id: %w", err)
	}

	job := &Job{
		ID:                      id,
		Algo:                    algo,
		Height:                  result.Height,
		Header:                  hashingBlob,
		BlockHash:               prevHash,
		NetworkTargetDifficulty: result.Difficulty,
		TemplateData: &moneroTemplateData{
			HashingBlob:    hashingBlob,
			TemplateBlob:   templateBlob,
			NonceOffset:    nonceOffset,
			SeedHash:       seedHash,
			Difficulty:     result.Difficulty,
			Height:         result.Height,
			ReservedOffset: result.ReservedOffset,
		},
		VmKey:                seedHash,
		ReservedOffset:       result.ReservedOffset,
		ReservedOffsetUsable: reservationUsable,
		RawTemplateBlob:      templateBlob,
		CreatedAt:            c.now(),
	}
	return job, nil
}

// moneroTemplateData is MoneroNodeClient's own coin-specific
// Job.TemplateData payload (analogous to Tari's
// *tari_generated.GetNewBlockResult) — only this file's own
// BuildCandidateBlock/SubmitBlock ever type-assert it back out of a
// *Job, matching NodeClient's documented "opaque outside the owning
// implementation" contract (node.go).
type moneroTemplateData struct {
	HashingBlob  []byte
	TemplateBlob []byte
	NonceOffset  int
	SeedHash     []byte
	Difficulty   uint64
	Height       uint64

	// ReservedOffset is the real monerod get_block_template
	// reserved_offset for this template (result.ReservedOffset,
	// confirmed parsed above) — mirrors Job.ReservedOffset exactly;
	// see that field's doc comment (job.go) for the full XNP-proxy
	// rationale. Kept here too (in addition to Job.ReservedOffset)
	// purely so this type's own fields stay self-describing/complete
	// alongside HashingBlob/TemplateBlob, matching this struct's
	// existing convention of holding everything GetBlockTemplate
	// parsed for this template.
	ReservedOffset int
}

func (c *MoneroNodeClient) now() time.Time {
	if c.nowFunc != nil {
		return c.nowFunc()
	}
	return time.Now()
}

// GetTipInfo implements NodeClient via a real monerod get_info call.
func (c *MoneroNodeClient) GetTipInfo(ctx context.Context) (uint64, error) {
	var result moneroGetInfoResult
	if err := c.call(ctx, "get_info", nil, &result); err != nil {
		return 0, fmt.Errorf("solo: monero: get_info: %w", err)
	}
	return result.Height, nil
}

// MoneroCandidate is this file's own opaque candidate-block payload —
// what BuildCandidateBlock returns as its `candidate any` value for
// ALGO_RXM, and the ONLY shape SubmitBlock/SubmitBlockWithID/
// SubmitBlockAuxChains (below) ever accept back (see NodeClient.
// BuildCandidateBlock's own doc comment: "candidate is opaque to every
// caller outside this SAME NodeClient implementation").
//
// CORRECTION (this repo's git history has the full story): an earlier
// version of this fix widened this struct to carry a locally-computed
// BlockHash field alongside TemplateBlob, on the theory that computing
// Monero's real block ID entirely locally (Keccak-256 over a
// length-prefixed blockhashing_blob) would avoid a real, live-confirmed
// race between a post-submit get_block_header_by_height call and the
// daemon's own tip advancement. That local computation was CONFIRMED
// WRONG by live testing against the real testnet daemon (the computed
// hash did not match get_block_header_by_height's own reported hash
// for the same height, for three independently-computed candidates) —
// removed entirely. The REAL fix needs no local computation and no
// second RPC call at all: monerod's own submit_block JSON-RPC response
// has included a top-level "block_id" field directly since
// monero-project/monero commit e8cac61f4b9a662cbc1b00e46d1f9a3dd991c5f0
// ("core_rpc_server: return ID of submitted block", released in
// v0.18.0.0+246) — see moneroSubmitBlockAuxResult.BlockID and
// SubmitBlockWithID/SubmitBlockAuxChains below, which read it straight
// off the SAME response that already accepted the block.
type MoneroCandidate struct {
	// TemplateBlob is the real, nonce-patched blocktemplate_blob bytes
	// this candidate's SubmitBlock/SubmitBlockWithID/
	// SubmitBlockAuxChains actually submits to the daemon.
	TemplateBlob []byte
}

// BuildCandidateBlock implements NodeClient. It re-parses the real
// nonce offset for job's OWN blockhashing_blob (not reusing any offset
// value cached elsewhere), patches nonce into a COPY of the real
// blocktemplate_blob bytes at that offset, and computes the real
// Monero difficulty of proof.ResultHex (the miner's claimed RandomX
// hash — trusted here exactly as RXT's own BuildCandidateBlock trusts
// it; session.go's handleSubmit only calls this after
// validator.RandomXValidator has already confirmed that claimed hash is
// what the real daemon/RandomX computation actually produced for this
// job's blob+seed).
//
// This method does NOT compute (and MoneroCandidate does not carry) a
// block hash/ID at all — see MoneroCandidate's own doc comment for
// why: an earlier version of this fix tried to derive the real Monero
// block ID entirely locally here, and that derivation was confirmed
// WRONG by live testing. The real, canonical block ID is instead read
// straight off submit_block's own JSON-RPC response ("block_id",
// confirmed present on every real monerod v0.18.0.0+246+ acceptance)
// by SubmitBlockWithID/SubmitBlockAuxChains below, once this candidate
// is actually submitted.
func (c *MoneroNodeClient) BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (uint64, any, error) {
	data, ok := job.TemplateData.(*moneroTemplateData)
	if !ok || data == nil {
		return 0, nil, fmt.Errorf("solo: monero: job.TemplateData does not hold a real *moneroTemplateData (algo %v)", job.Algo)
	}

	// Real, per-call re-derivation — see this file's package doc
	// comment: never trust a cached/previously-computed offset, even
	// one computed moments ago for this SAME job's own blob, since
	// the whole point of this file is to never assume stability.
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(data.HashingBlob)
	if err != nil {
		return 0, nil, fmt.Errorf("solo: monero: re-parsing nonce offset for candidate construction: %w", err)
	}
	if nonceOffset != data.NonceOffset {
		return 0, nil, fmt.Errorf("solo: monero: nonce offset changed between GetBlockTemplate (%d) and BuildCandidateBlock (%d) for the SAME job's blob — refusing to build a candidate against stale offset data", data.NonceOffset, nonceOffset)
	}
	if nonceOffset+4 > len(data.TemplateBlob) {
		return 0, nil, fmt.Errorf("solo: monero: nonce offset %d + 4 exceeds template blob length %d", nonceOffset, len(data.TemplateBlob))
	}
	// GetBlockTemplate already confirmed hashingBlob[:nonceOffset] ==
	// templateBlob[:nonceOffset] and that nonceOffset+4 fits within
	// BOTH blobs (see that method's own bounds check) -- this check is
	// kept here too, defensively, on every call, rather than assumed,
	// matching this file's own "never assume stability" convention;
	// it can only fail here on a genuinely corrupted in-memory Job,
	// not any real daemon response shape this package hasn't already
	// validated.
	if nonceOffset+4 > len(data.HashingBlob) {
		return 0, nil, fmt.Errorf("solo: monero: nonce offset %d + 4 exceeds hashing blob length %d -- refusing to build a candidate from a malformed blob", nonceOffset, len(data.HashingBlob))
	}

	var nonceBuf [4]byte
	binary.LittleEndian.PutUint32(nonceBuf[:], uint32(nonce))

	candidate := make([]byte, len(data.TemplateBlob))
	copy(candidate, data.TemplateBlob)
	copy(candidate[nonceOffset:nonceOffset+4], nonceBuf[:])

	hashBytes, err := hex.DecodeString(proof.ResultHex)
	if err != nil {
		return 0, nil, fmt.Errorf("solo: monero: claimed result hash is not valid hex: %w", err)
	}
	diff, err := moneroDifficultyFromHash(hashBytes)
	if err != nil {
		return 0, nil, err
	}
	return diff, &MoneroCandidate{TemplateBlob: candidate}, nil
}

// SubmitBlock implements NodeClient via a real monerod submit_block
// call. candidate must be the *MoneroCandidate produced by this SAME
// implementation's own BuildCandidateBlock. This satisfies the
// coin-agnostic NodeClient interface's error-only contract; callers
// that need the real, daemon-reported block_id (leaf-direct/leaf-solo's
// own ALGO_RXM block-find handling) should instead call
// SubmitBlockWithID or SubmitBlockAuxChains (below), both of which
// perform the exact SAME real submit_block call and additionally
// surface that ID.
func (c *MoneroNodeClient) SubmitBlock(ctx context.Context, candidate any) error {
	_, _, err := c.submitBlockDecoded(ctx, candidate)
	return err
}

// moneroRelayTemplateWire is the small, explicit wire struct
// TemplateBytesForRelay serializes (via plain encoding/json, matching
// relay.TemplateMessage's own JSON-over-NATS convention -- there is no
// existing protobuf schema for Monero's template shape the way Tari
// has tari_generated.GetNewBlockResult, so inventing one here would be
// pure overhead) and JobFromTemplateBytes deserializes, carrying every
// field a receiving leaf-direct-Monero instance needs to reconstruct
// an equivalent *Job WITHOUT a local get_block_template round-trip --
// see GetBlockTemplate above, which is this type's own source of
// truth for exactly which fields are needed.
//
// Deliberately NOT included: NonceOffset and any pre-computed
// "reservation usable" bool. Both are re-derived independently by
// JobFromTemplateBytes from the deserialized HashingBlob/TemplateBlob
// bytes themselves (parseMoneroBlockHeaderNonceOffset + the same
// ReservedOffset+minReservedOffsetHeadroom bounds check
// GetBlockTemplate performs) rather than trusted verbatim from the
// sender -- matching this file's own "never assume stability, always
// re-derive" convention (see the package doc comment): a receiving
// instance validates the bytes it actually got, exactly like the
// sending instance validated its own local fetch, rather than
// propagating a value that could be stale or simply wrong for bytes
// that traveled over the wire.
type moneroRelayTemplateWire struct {
	HashingBlob    []byte `json:"hashing_blob"`
	TemplateBlob   []byte `json:"template_blob"`
	SeedHash       []byte `json:"seed_hash"`
	PrevHash       []byte `json:"prev_hash"`
	Difficulty     uint64 `json:"difficulty"`
	Height         uint64 `json:"height"`
	ReservedOffset int    `json:"reserved_offset"`
}

// JobFromTemplateBytes implements NodeClient -- the real, production
// implementation for leaf-direct's relay-template-adoption feature
// (see internal/leaflib/direct/node.go's Tari NodeClient.
// JobFromTemplateBytes, the pattern this mirrors), now genuinely wired
// for Monero/RXM leaf-direct too: every leaf-direct-Monero instance of
// a given pool/algo shares the SAME fleet-wide payout_address (unlike
// leaf-solo's per-operator addresses -- see
// errRelayTemplateAdoptionNotSupported's doc comment in node.go), so a
// relayed Monero template's coinbase already pays the correct
// destination -- adopting a sibling's relayed template is exactly as
// safe here as it already is for Tari leaf-direct.
//
// Deserializes data into a moneroRelayTemplateWire, then rebuilds a
// *Job via the exact same field shape/validation GetBlockTemplate
// itself produces (see that method above -- this deliberately never
// duplicates its bounds-checking logic with different rules):
//   - nonceOffset is re-parsed from the deserialized HashingBlob via
//     parseMoneroBlockHeaderNonceOffset, never trusted from the wire.
//   - The real header-prefix-match bounds check
//     (HashingBlob[:nonceOffset] == TemplateBlob[:nonceOffset], and
//     nonceOffset+4 fitting both blobs) is re-run against the
//     deserialized bytes -- a genuine error (never a fabricated Job)
//     is returned if it fails. Per startTemplateRelaySubscription's
//     existing caller code (job.go), an error here already falls back
//     gracefully to a plain cache invalidation, so failing loudly is
//     safe, not fatal.
//   - reservationUsable is likewise re-derived from
//     ReservedOffset+minReservedOffsetHeadroom against the
//     deserialized TemplateBlob's own real length, never trusted
//     verbatim from the sender.
//   - id is a freshly minted newRandomHexID() -- NEVER derived from
//     any relayed content (see the long comment directly above
//     GetBlockTemplate's own `id, err := newRandomHexID()` call for
//     the exact, already-diagnosed production incident this rule
//     prevents; a relay-adopted job follows the identical rule).
//
// Returns a real error (never a corrupted/partial Job) for malformed,
// truncated, or algo-mismatched input.
func (c *MoneroNodeClient) JobFromTemplateBytes(data []byte, algo poolpb.Algo) (*Job, error) {
	if !IsMoneroFamilyAlgo(algo) {
		return nil, fmt.Errorf("solo: monero: JobFromTemplateBytes does not support algo %v (only ALGO_RXM or a registered monerod-compatible coin algo is supported)", algo)
	}

	var wire moneroRelayTemplateWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("solo: monero: JobFromTemplateBytes: unmarshaling relay template wire struct: %w", err)
	}
	if len(wire.HashingBlob) == 0 || len(wire.TemplateBlob) == 0 {
		return nil, fmt.Errorf("solo: monero: JobFromTemplateBytes: relayed template is missing hashing_blob/template_blob")
	}

	// Real, per-call re-derivation -- never trusted from the wire.
	// See this file's package doc comment and moneroRelayTemplateWire's
	// own doc comment above.
	nonceOffset, err := parseMoneroBlockHeaderNonceOffset(wire.HashingBlob)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: JobFromTemplateBytes: parsing nonce offset from relayed blockhashing_blob: %w", err)
	}
	if nonceOffset+4 > len(wire.TemplateBlob) || nonceOffset+4 > len(wire.HashingBlob) {
		return nil, fmt.Errorf("solo: monero: JobFromTemplateBytes: parsed nonce offset %d + 4 exceeds relayed blob length (hashing=%d, template=%d)", nonceOffset, len(wire.HashingBlob), len(wire.TemplateBlob))
	}
	// Same defensive header-prefix-match check GetBlockTemplate
	// performs on its own local fetch -- re-run here against the
	// deserialized bytes rather than assumed to still hold after a
	// wire round-trip.
	if !bytes.Equal(wire.HashingBlob[:nonceOffset], wire.TemplateBlob[:nonceOffset]) {
		return nil, fmt.Errorf("solo: monero: JobFromTemplateBytes: relayed blockhashing_blob and blocktemplate_blob header prefixes (through the parsed nonce offset %d) do not match -- refusing to build a job from mismatched blobs", nonceOffset)
	}

	// Stamps THIS receiving instance's OWN c.instanceID into the
	// reserved region of the deserialized wire.TemplateBlob -- NOT
	// whatever the originating leaf may or may not have already
	// stamped (that leaf's own stamp, if any, was itself made
	// against ITS copy of these template bytes' underlying array
	// before serialization; this call operates on a fresh copy
	// decoded from the wire by json.Unmarshal above, so overwriting
	// here cannot clobber anything the sender needed -- see
	// stampInstanceID's doc comment for the full bounds/shared-prefix
	// rationale). This is the critical correctness property this
	// whole fix exists for: two different leaves adopting the
	// IDENTICAL relayed template bytes must still end up serving
	// DISTINCT coinbases to their own sessions. Also re-derives the
	// SAME reservationUsable bounds check GetBlockTemplate performs
	// (never trusted verbatim from the sender) -- see
	// moneroRelayTemplateWire's own doc comment.
	reservationUsable := c.stampInstanceID(wire.HashingBlob, wire.TemplateBlob, wire.ReservedOffset, nonceOffset)
	if !reservationUsable {
		log.Printf("solo: monero: JobFromTemplateBytes: relayed template's real reservation region (offset=%d) does not fit in the relayed template blob (len=%d) -- XNP-proxy shape and per-instance stamp omitted for this job, height=%d", wire.ReservedOffset, len(wire.TemplateBlob), wire.Height)
	}

	// job_id must be a purely random, opaque wire token -- NEVER
	// derived from relayed content (PrevHash/Height/any template
	// bytes). See GetBlockTemplate's own doc comment above for the
	// full, already-diagnosed production incident this rule
	// prevents; a relay-adopted job follows the identical rule.
	id, err := newRandomHexID()
	if err != nil {
		return nil, fmt.Errorf("solo: monero: JobFromTemplateBytes: generating random job id: %w", err)
	}

	job := &Job{
		ID:                      id,
		Algo:                    algo,
		Height:                  wire.Height,
		Header:                  wire.HashingBlob,
		BlockHash:               wire.PrevHash,
		NetworkTargetDifficulty: wire.Difficulty,
		TemplateData: &moneroTemplateData{
			HashingBlob:    wire.HashingBlob,
			TemplateBlob:   wire.TemplateBlob,
			NonceOffset:    nonceOffset,
			SeedHash:       wire.SeedHash,
			Difficulty:     wire.Difficulty,
			Height:         wire.Height,
			ReservedOffset: wire.ReservedOffset,
		},
		VmKey:                wire.SeedHash,
		ReservedOffset:       wire.ReservedOffset,
		ReservedOffsetUsable: reservationUsable,
		RawTemplateBlob:      wire.TemplateBlob,
		CreatedAt:            c.now(),
	}
	return job, nil
}

// TemplateBytesForRelay implements NodeClient -- the real, production
// counterpart to JobFromTemplateBytes above: serializes job's real
// underlying *moneroTemplateData (plus job.BlockHash, the real
// prev_hash JobFromTemplateBytes needs to rebuild Job.BlockHash) into
// the moneroRelayTemplateWire bytes JobFromTemplateBytes reconstructs
// from, for relay publishing/comparison (job.go's
// publishTemplateForJob and jobForSession's own tracked-best
// bookkeeping).
//
// Returns (nil, nil) -- never an error -- if job is nil or
// job.TemplateData does not hold the expected real *moneroTemplateData
// (e.g. a nil/zero-value Job, or one built by some other coin's
// NodeClient): this must never be treated as a reason to fail the
// primary tip-poll/publish path, matching solo.NodeClient.
// TemplateBytesForRelay's own interface doc comment and the Tari
// NodeClient implementation's identical contract.
func (c *MoneroNodeClient) TemplateBytesForRelay(job *Job) ([]byte, error) {
	if job == nil {
		return nil, nil
	}
	data, ok := job.TemplateData.(*moneroTemplateData)
	if !ok || data == nil {
		return nil, nil
	}

	wire := moneroRelayTemplateWire{
		HashingBlob:    data.HashingBlob,
		TemplateBlob:   data.TemplateBlob,
		SeedHash:       data.SeedHash,
		PrevHash:       job.BlockHash,
		Difficulty:     data.Difficulty,
		Height:         data.Height,
		ReservedOffset: data.ReservedOffset,
	}
	out, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("solo: monero: TemplateBytesForRelay: marshaling relay template wire struct: %w", err)
	}
	return out, nil
}

// SubmitBlockWithID performs the exact SAME real submit_block call as
// SubmitBlock, additionally returning the daemon's own real block_id
// string for the submitted candidate (see moneroSubmitBlockAuxResult's
// own doc comment for the full, monero-project/monero-source-confirmed
// wire shape and provenance). blockID is empty (never fabricated) when
// the response genuinely carried no block_id -- see this method's own
// doc comment on moneroSubmitBlockAuxResult.BlockID for when that can
// legitimately happen; callers must treat an empty blockID exactly as
// "the real hash is not known" and must never forward a placeholder in
// its place.
func (c *MoneroNodeClient) SubmitBlockWithID(ctx context.Context, candidate any) (blockID string, err error) {
	blockID, _, err = c.submitBlockDecoded(ctx, candidate)
	return blockID, err
}

// BlockIDSubmitter is implemented by a NodeClient whose SubmitBlock-
// equivalent RPC endpoint returns the daemon's own real block ID
// directly in its submit_block response (today: MoneroNodeClient --
// see SubmitBlockWithID above). Callers must type-assert for this
// optional capability (`node.(BlockIDSubmitter)`) rather than assuming
// every NodeClient implementation has it -- the Tari (-coin=tari)
// NodeClient implementation deliberately does not implement this
// interface at all (Tari's own real block hash comes from a separate,
// already-established path -- see internal/leaflib/direct/node.go's
// own SubmitBlock and multisubmit.go's realBlockHashHex). Every
// MoneroNodeClient also implements the wider AuxChainSubmitter
// interface (below), which callers should generally prefer when it is
// available, since it additionally surfaces merge-mined-chain
// acceptance in the SAME real submit_block call -- this narrower
// interface exists for callers (e.g. leaf-solo, which never forwards
// to a backend and has no merge-mine-chain concept) that only need the
// primary chain's own real block ID.
type BlockIDSubmitter interface {
	SubmitBlockWithID(ctx context.Context, candidate any) (blockID string, err error)
}

// Compile-time assertion that MoneroNodeClient satisfies
// BlockIDSubmitter.
var _ BlockIDSubmitter = (*MoneroNodeClient)(nil)

// AuxChainResult is one merge-mined chain's own real acceptance
// outcome from the SAME submit_block call as the primary (Monero)
// chain, as reported by a minotari_merge_mining_proxy sitting
// between this client and real monerod (see this package's own
// -coin=monero deployment convention: MoneroNodeClient's baseURL may
// point at either raw monerod OR at such a proxy — the wire protocol
// this package speaks is identical either way, since the proxy is a
// monerod-JSON-RPC-compatible surface).
//
// Confirmed against the real tari-project/tari source
// (applications/minotari_merge_mining_proxy/src/proxy/inner.rs,
// handle_submit_block, and src/proxy/utils.rs,
// append_aux_chain_data/MMPROXY_AUX_KEY_NAME): on a successful
// Tari-side submission, minotari_merge_mining_proxy calls
// append_aux_chain_data(json_resp, json!({"id": TARI_CHAIN_ID,
// "block_hash": resp.block_hash.to_hex()})), and append_aux_chain_data
// appends into result["_aux"]["chains"] (an array) --
// MMPROXY_AUX_KEY_NAME is "_aux", NOT a top-level "aux_chain_data" key
// (the shape this file used before this fix, which never actually
// matched the real proxy's wire format -- see
// moneroSubmitBlockAuxResult's own doc comment). "xtr" is Tari's own
// real aux-chain identifier in this response. When Tari's target isn't
// cleared, or IS cleared but the Tari base node then rejects the
// submission, no entry is appended for that chain -- this is NOT an
// error condition for the Monero leg, which this same submit_block
// response resolves entirely independently.
type AuxChainResult struct {
	// ChainID is the aux-chain identifier as reported by the proxy's
	// own response (e.g. "xtr" for Tari) -- callers match this
	// against their own configured chain-target list (see
	// internal/leaflib/direct.MergeMineChainConfig.AuxChainID) rather
	// than this package hardcoding any particular chain name.
	ChainID string
	// Hash is the real, chain-confirmed block hash for ChainID,
	// hex-encoded exactly as the proxy reported it.
	Hash string
}

// moneroSubmitBlockAuxResult decodes submit_block's real JSON-RPC
// result payload: a normal monerod-style {"status":"OK",
// "untrusted":bool,"block_id":"<hex>"} PLUS an optional
// "_aux":{"chains":[...]} object when the underlying endpoint is a
// merge-mining proxy, carrying each configured chain's own
// template-request-time info (difficulty/height/mining_hash/
// miner_reward) AND, on genuine acceptance, an "id"/"block_hash" pair
// for that chain (see AuxChainResult's own doc comment for the real,
// tari-project/tari-source-confirmed wire shape: "_aux" is
// minotari_merge_mining_proxy's own MMPROXY_AUX_KEY_NAME, NOT
// "aux_chain_data" -- that top-level key never actually existed on the
// real wire; using it was this file's own pre-fix bug). Only entries
// carrying BOTH a non-empty "id" AND a non-empty "block_hash" represent
// a genuine chain acceptance -- the "_aux.chains" array also carries
// template-request-time entries (difficulty/height/mining_hash/
// miner_reward, no block_hash at all) that must NOT be misinterpreted
// as an acceptance signal.
//
// BlockID is the daemon's OWN real, canonical block ID for the
// primary (Monero) chain -- a TOP-LEVEL field, sibling of status/
// untrusted, NOT nested under "_aux" at all. Confirmed present on the
// real, current monero-project/monero source (src/rpc/
// core_rpc_server_commands_defs.h's
// COMMAND_RPC_SUBMITBLOCK::response_t: `std::string block_id;`,
// serialized via KV_SERIALIZE(block_id) at the same level as
// status/untrusted) since commit
// e8cac61f4b9a662cbc1b00e46d1f9a3dd991c5f0 ("core_rpc_server: return
// ID of submitted block", first released in v0.18.0.0+246, June
// 2023) -- i.e. present and populated on every real accepted
// submit_block call against any monerod from that release onward.
// Can legitimately still be empty against an older, pre-e8cac61f
// monerod, or a merge-mining proxy that doesn't pass this field
// through untouched -- callers (session.go) must treat an empty
// BlockID defensively, exactly like this file's own former "hash
// unresolved" handling: skip backend-forwarding, log loudly, never
// fabricate a hash.
//
// Raw monerod itself never populates "_aux" at all (unknown field,
// silently ignored by json.Unmarshal) -- decoding this same struct
// against a raw-monerod submit_block response is safe and simply
// yields a nil Aux (zero AuxChainResult entries) alongside a real,
// populated BlockID.
type moneroSubmitBlockAuxResult struct {
	Status    string `json:"status"`
	Untrusted bool   `json:"untrusted"`
	BlockID   string `json:"block_id"`
	Aux       *struct {
		Chains []struct {
			ID        string `json:"id"`
			BlockHash string `json:"block_hash"`
		} `json:"chains"`
	} `json:"_aux"`
}

// SubmitBlockAuxChains performs the exact SAME real submit_block call
// SubmitBlock does, additionally decoding the response for (a) the
// daemon's own real block_id for the primary (Monero) chain (see
// moneroSubmitBlockAuxResult.BlockID's own doc comment) and (b) any
// real aux-chain acceptance entries under "_aux.chains" (see
// AuxChainResult's and moneroSubmitBlockAuxResult's own doc comments).
// A non-nil error here means submit_block itself failed (the SAME
// outcome SubmitBlock's own error return would represent) -- when
// that happens, blockID is always "" and auxChains is always nil:
// this deployment's mmproxy (submit_to_origin=false) reports the WHOLE
// call's outcome, so an error here does not distinguish "the primary
// chain rejected it" from "a configured secondary chain rejected it"
// -- callers must not assume a submit_block error is specific to
// either leg (see internal/leaflib/direct/session.go's ALGO_RXM
// block-find handling for how this ambiguity is handled
// conservatively: neither leg is forwarded to the backend on error,
// exactly mirroring this package's existing skipBackendForward-style
// "never fabricate, when in doubt leave it out" convention). On
// success (nil error), blockID/auxChains reflect exactly whatever the
// response genuinely carried -- blockID may still legitimately be ""
// (see moneroSubmitBlockAuxResult.BlockID's doc comment), and callers
// must handle that defensively rather than assume it.
//
// WIRE-SHAPE TOLERANCE: real, live-observed raw monerod submit_block
// success can shape the JSON-RPC "result" field as a bare STRING
// ("{}") rather than an object (confirmed live against this exact
// testnet daemon this session: {"id":-1,"jsonrpc":"2.0","result":"{}",
// "status":"OK","untrusted":false} -- note status/untrusted sitting
// at the TOP level, siblings of "result", and "result" itself being
// the literal string "{}", not an object). This mirrors this same
// file's own documented monerod-is-wire-inconsistent precedent (see
// moneroRPCResponse.ID's doc comment for the "id" field's own
// number-vs-string inconsistency on this SAME RPC method). This
// function decodes the real object shape first; if that fails AND
// the raw result is instead a JSON string that parses to an
// effectively-empty value ("" or "{}"), it is treated as a plain,
// non-aux success rather than a hard decode failure (logged
// distinctly so the degraded shape stays visible without breaking
// submission) -- blockID is necessarily "" in that degraded shape,
// since no object was ever decoded to read it from. A genuine
// daemon-reported RPC error (rpcResp.Error != nil) still fails loudly
// exactly as before -- this tolerance is specifically for the
// success-path response-shape ambiguity described above, never for a
// real error.
func (c *MoneroNodeClient) SubmitBlockAuxChains(ctx context.Context, candidate any) (blockID string, auxChains []AuxChainResult, err error) {
	return c.submitBlockDecoded(ctx, candidate)
}

// submitBlockDecoded is the shared, real implementation behind
// SubmitBlock/SubmitBlockWithID/SubmitBlockAuxChains -- every one of
// those methods performs the exact SAME real submit_block RPC call
// and decode; they differ only in which parts of this method's full
// return value they surface to their own caller.
func (c *MoneroNodeClient) submitBlockDecoded(ctx context.Context, candidate any) (blockID string, auxChains []AuxChainResult, err error) {
	mc, ok := candidate.(*MoneroCandidate)
	if !ok || mc == nil {
		return "", nil, fmt.Errorf("solo: monero: SubmitBlock: candidate is not a real *MoneroCandidate (got %T)", candidate)
	}
	rawResult, err := c.callRaw(ctx, "submit_block", []string{hex.EncodeToString(mc.TemplateBlob)})
	if err != nil {
		return "", nil, err
	}

	var result moneroSubmitBlockAuxResult
	if decodeErr := json.Unmarshal(rawResult, &result); decodeErr != nil {
		// Degraded-shape tolerance -- see this method's own doc
		// comment. Only the specific "result is a bare string that
		// parses to an effectively-empty value" shape is tolerated;
		// anything else is still a hard error.
		var bareString string
		if strErr := json.Unmarshal(rawResult, &bareString); strErr != nil {
			return "", nil, fmt.Errorf("solo: monero: decoding submit_block result payload: %w", decodeErr)
		}
		trimmed := strings.TrimSpace(bareString)
		if trimmed != "" && trimmed != "{}" {
			return "", nil, fmt.Errorf("solo: monero: submit_block result was a non-empty bare string %q (not decodable as an object, and not the known degraded \"{}\" success shape): %w", bareString, decodeErr)
		}
		log.Printf("solo: monero: submit_block returned a bare-string result %q (a known monerod wire-shape quirk on this RPC -- see moneroSubmitBlockAuxResult's doc comment) -- treating as a plain, non-aux success with no block_id available", bareString)
		return "", nil, nil
	}

	if result.Aux != nil {
		for _, entry := range result.Aux.Chains {
			if entry.ID == "" || entry.BlockHash == "" {
				continue
			}
			auxChains = append(auxChains, AuxChainResult{ChainID: entry.ID, Hash: entry.BlockHash})
		}
	}
	return result.BlockID, auxChains, nil
}

// AuxChainSubmitter is implemented by a NodeClient whose underlying
// submit_block-equivalent RPC endpoint may ALSO be a merge-mining
// proxy reporting one or more OTHER chains' own real acceptance
// outcome for the SAME submission (today: MoneroNodeClient, when its
// configured baseURL is a minotari_merge_mining_proxy listener rather
// than raw monerod -- see cmd/leaf-direct's -monerod-url doc comment
// and AuxChainResult's own doc comment). Callers must type-assert for
// this optional capability (`node.(AuxChainSubmitter)`) rather than
// assuming every NodeClient implementation has it -- the Tari
// (-coin=tari) NodeClient implementation deliberately does not
// implement this interface at all, since Tari mining has no
// analogous "one PoW submission, multiple independently-checked
// chain targets" concept today.
type AuxChainSubmitter interface {
	SubmitBlockAuxChains(ctx context.Context, candidate any) (blockID string, auxChains []AuxChainResult, err error)
}

// Compile-time assertion that MoneroNodeClient satisfies
// AuxChainSubmitter.
var _ AuxChainSubmitter = (*MoneroNodeClient)(nil)

// parseMoneroBlockHeaderNonceOffset computes the REAL, CURRENT byte
// offset of the 4-byte nonce field within blockhashingBlob by actually
// walking Monero's real block_header varint fields
// (major_version -> minor_version -> timestamp), each a standard
// LEB128/protobuf-style varint (Go's encoding/binary.Uvarint reads
// exactly this format), followed by a fixed 32-byte prev_id and then
// the 4-byte nonce itself. This deliberately does NOT hardcode any
// fixed offset (see this file's package doc comment for why that would
// be a real, latent, timestamp-growth-triggered bug) — every call walks
// the real bytes of whatever blob is passed in.
func parseMoneroBlockHeaderNonceOffset(blockhashingBlob []byte) (int, error) {
	offset := 0

	// major_version (varint)
	_, n := binary.Uvarint(blockhashingBlob[offset:])
	if n <= 0 {
		return 0, fmt.Errorf("solo: monero: malformed major_version varint at offset %d (blob len %d)", offset, len(blockhashingBlob))
	}
	offset += n

	// minor_version (varint)
	_, n = binary.Uvarint(blockhashingBlob[offset:])
	if n <= 0 {
		return 0, fmt.Errorf("solo: monero: malformed minor_version varint at offset %d (blob len %d)", offset, len(blockhashingBlob))
	}
	offset += n

	// timestamp (varint) — the field whose encoded length actually
	// grows over time, which is exactly why this whole function exists
	// instead of a hardcoded constant.
	_, n = binary.Uvarint(blockhashingBlob[offset:])
	if n <= 0 {
		return 0, fmt.Errorf("solo: monero: malformed timestamp varint at offset %d (blob len %d)", offset, len(blockhashingBlob))
	}
	offset += n

	// prev_id: fixed 32 bytes.
	const prevIDSize = 32
	if offset+prevIDSize > len(blockhashingBlob) {
		return 0, fmt.Errorf("solo: monero: blob too short for prev_id at offset %d (blob len %d)", offset, len(blockhashingBlob))
	}
	offset += prevIDSize

	// nonce: fixed 4 bytes, starting right here.
	const nonceSize = 4
	if offset+nonceSize > len(blockhashingBlob) {
		return 0, fmt.Errorf("solo: monero: blob too short for nonce at offset %d (blob len %d)", offset, len(blockhashingBlob))
	}
	return offset, nil
}

// moneroMax256 is 2^256 - 1, the real max value of Monero's 256-bit
// difficulty-check space (boost::multiprecision::uint256_t's max in the
// real difficulty.cpp check_hash_128 — see moneroDifficultyFromHash's
// doc comment).
var moneroMax256 = func() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 256)
	return max.Sub(max, big.NewInt(1))
}()

// moneroDifficultyFromHash implements Monero's own real
// difficulty-comparison formula, INDEPENDENTLY confirmed from Monero's
// real source (src/cryptonote_basic/difficulty.cpp, check_hash_128 —
// fetched and read directly this session, not assumed/guessed):
//
//	boost::multiprecision::uint512_t hashVal = 0;
//	for (int i = 0; i < 4; i++) {
//	  hashVal <<= 64;
//	  hashVal |= swap64le(((const uint64_t *) &hash)[3 - i]);
//	}
//	return hashVal * difficulty <= max256bit;
//
// Two real, confirmed facts fall out of that source, both verified by
// direct inspection rather than assumed:
//
//  1. Byte order: assembling the 256-bit value from word[3] down to
//     word[0], with swap64le a no-op on little-endian hosts, is
//     mathematically identical to reading the entire 32-byte hash
//     buffer as one little-endian integer (byte 0 = least significant
//     byte of the whole 256-bit value) — the SAME little-endian whole-
//     buffer convention this package's own rxtLittleEndianDifficulty
//     (rxt.go) uses for Tari's RXT. This genuinely is the same
//     direction; the "big-endian gotcha" some sources warn about does
//     NOT apply here for either coin.
//  2. Comparison shape: real Monero does NOT compute "the difficulty a
//     hash satisfies" as `floor(2^256-1 / hashVal)` and then compare —
//     it multiplies `hashVal * difficulty` and checks it doesn't
//     exceed 2^256-1. These are mathematically exactly equivalent for
//     an exact (non-overflowing) big integer division —
//     hashVal <= floor(max/difficulty) iff hashVal*difficulty <= max —
//     so this function's return value (the largest difficulty D for
//     which check_hash(hash, D) would be true) is computed via the
//     equivalent, session.go-friendly "produce a uint64 diff, then the
//     caller compares diff >= job.NetworkTargetDifficulty" shape this
//     codebase's NodeClient.BuildCandidateBlock contract already uses
//     for every other algo (see node.go's tariBuildCandidateBlock /
//     rxtLittleEndianDifficulty) — clamped to math.MaxUint64 rather
//     than overflowing, exactly like RXT's own clamp.
//
// This is a genuinely separate implementation from rxtLittleEndianDifficulty
// (rxt.go) — independently sourced from Monero's own C++, not copied
// from or reusing Tari's Rust-sourced formula — even though both
// ultimately share the little-endian-whole-buffer convention once
// actually checked against their real respective upstreams.
func moneroDifficultyFromHash(hash []byte) (uint64, error) {
	if len(hash) == 0 {
		return 0, errMoneroHashIsZero
	}

	buf := make([]byte, 32)
	n := len(hash)
	if n > 32 {
		n = 32
	}
	// Little-endian whole-buffer read: hash[0] is the least
	// significant byte of the 256-bit value, so reverse into a
	// big-endian buffer for math/big's SetBytes (which expects
	// big-endian input) — same technique as rxt.go's
	// rxtLittleEndianDifficulty, independently applied here.
	for i := 0; i < n; i++ {
		buf[31-i] = hash[i]
	}

	hashVal := new(big.Int).SetBytes(buf)
	if hashVal.Sign() == 0 {
		return 0, errMoneroHashIsZero
	}

	result := new(big.Int).Quo(moneroMax256, hashVal)
	maxUint64 := new(big.Int).SetUint64(^uint64(0))
	if result.Cmp(maxUint64) > 0 {
		return ^uint64(0), nil
	}
	return result.Uint64(), nil
}

var errMoneroHashIsZero = fmt.Errorf("solo: monero: hash is all-zero, cannot derive a difficulty (division by zero)")
