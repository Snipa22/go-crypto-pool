// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"

	"github.com/Snipa22/go-xmr-lib/support"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib/moneroblob"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// --- Per-job Monero extraNonce stamp regression tests ---
//
// THE BUG THESE EXIST FOR (live-reproduced on a real public stratum
// port, two separate logins, same leaf, same tip): both sessions got
// a BYTE-IDENTICAL `blob` in their job payloads, only job_id/target
// differed. Root cause: JobManager.jobFromSharedTemplate derived
// every per-xn *Job by copying tpl.Header/tpl.RawTemplateBlob BY
// REFERENCE and patching nothing, so every Monero-family miner on the
// leaf searched the exact same space as every other one.
//
// The fix ports the legacy nodejs-pool reference's own per-template
// `++this.extraNonce` + `writeUInt32BE(..., reserveOffset)` +
// `convertBlob(...)` mechanism (lib/coins/xmr.js
// BlockTemplate.nextBlob) into that derivation -- see
// JobManager.sharedTemplateGen and extraNonceStampedTemplate (job.go).
//
// Every test below runs against the REAL, go-xmr-lib-verified
// xnpFixtureRawTemplateBlob fixture (node_test.go) pushed through the
// REAL MoneroNodeClient.JobFromTemplateBytes production code path --
// no hand-fabricated binary block data anywhere.

// extraNonceTestSeedHash/extraNonceTestPrevHash are stable, obviously
// synthetic non-blob metadata fields (the real fixture only carries
// the two blobs; seed hash / prev hash are independent daemon fields
// that play no part in the byte-level stamp this file tests).
var (
	extraNonceTestSeedHash = bytes.Repeat([]byte{0xA5}, 32)
	extraNonceTestPrevHash = bytes.Repeat([]byte{0x5A}, 32)
)

// moneroFixtureTemplateWireBytes serializes the real fixture into the
// exact moneroRelayTemplateWire JSON shape
// MoneroNodeClient.JobFromTemplateBytes consumes, deriving the
// fixture's real blockhashing_blob the same way monerod itself derives
// it from a blocktemplate_blob (go-xmr-lib/support's
// ParseBlockFromTemplateBlob + GetBlockHashingBlob).
func moneroFixtureTemplateWireBytes(t *testing.T, height uint64) []byte {
	t.Helper()
	rawTemplate, err := hex.DecodeString(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("decoding fixture hex: %v", err)
	}
	parsedBlock, err := support.ParseBlockFromTemplateBlob(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("support.ParseBlockFromTemplateBlob(fixture): %v", err)
	}
	hashingBlob, err := support.GetBlockHashingBlob(parsedBlock)
	if err != nil {
		t.Fatalf("support.GetBlockHashingBlob(fixture): %v", err)
	}
	data, err := json.Marshal(moneroRelayTemplateWire{
		HashingBlob:    hashingBlob,
		TemplateBlob:   rawTemplate,
		SeedHash:       extraNonceTestSeedHash,
		PrevHash:       extraNonceTestPrevHash,
		Difficulty:     1 << 40,
		Height:         height,
		ReservedOffset: xnpFixtureReservedOffset,
	})
	if err != nil {
		t.Fatalf("marshaling relay template wire struct: %v", err)
	}
	return data
}

// fakeMoneroFixtureNodeClient is a NodeClient test double that serves
// genuinely REAL, go-xmr-lib-parseable Monero templates: every
// GetBlockTemplate call runs the real fixture bytes through the REAL
// MoneroNodeClient.JobFromTemplateBytes, so the returned *Job carries
// a real *moneroTemplateData, a real RawTemplateBlob, the real
// reserved_offset, and this client's own real per-leaf instanceID
// already stamped at reserved_offset+4 (monero_node.go's
// stampInstanceID) -- exactly the shape a live leaf-solo/leaf-direct
// Monero JobManager actually holds.
//
// This is what makes the assertions below able to inspect the REAL
// parsed coinbase tx_extra nonce region of each derived job, rather
// than merely asserting "some bytes differ".
type fakeMoneroFixtureNodeClient struct {
	client *MoneroNodeClient

	mu     sync.Mutex
	calls  int
	height uint64
}

func newFakeMoneroFixtureNodeClient(height uint64) *fakeMoneroFixtureNodeClient {
	return &fakeMoneroFixtureNodeClient{
		// A real MoneroNodeClient (never dialed -- only its pure,
		// no-I/O JobFromTemplateBytes/TemplateBytesForRelay/
		// BuildCandidateBlock methods are used here) so the
		// crypto/rand instanceID is real too.
		client: NewMoneroNodeClient("http://127.0.0.1:1"),
		height: height,
	}
}

func (f *fakeMoneroFixtureNodeClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeMoneroFixtureNodeClient) setHeight(height uint64) {
	f.mu.Lock()
	f.height = height
	f.mu.Unlock()
}

func (f *fakeMoneroFixtureNodeClient) GetBlockTemplate(_ context.Context, _ string, algo poolpb.Algo) (*Job, error) {
	f.mu.Lock()
	f.calls++
	height := f.height
	f.mu.Unlock()
	// The wire bytes must be rebuilt per call: JobFromTemplateBytes
	// stamps the instance ID INTO the deserialized template blob, so
	// reusing one pre-decoded buffer across calls would be a shared
	// mutable buffer, not an independent template.
	return f.client.JobFromTemplateBytes(moneroFixtureTemplateWireBytesFor(height), algo)
}

func (f *fakeMoneroFixtureNodeClient) GetTipInfo(_ context.Context) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.height, nil
}

func (f *fakeMoneroFixtureNodeClient) BuildCandidateBlock(job *Job, nonce uint64, proof SubmitProof) (uint64, any, error) {
	return f.client.BuildCandidateBlock(job, nonce, proof)
}

func (f *fakeMoneroFixtureNodeClient) SubmitBlock(_ context.Context, _ any) error {
	return errors.New("fakeMoneroFixtureNodeClient: SubmitBlock unexpectedly called")
}

func (f *fakeMoneroFixtureNodeClient) TemplateBytesForRelay(job *Job) ([]byte, error) {
	return f.client.TemplateBytesForRelay(job)
}

func (f *fakeMoneroFixtureNodeClient) JobFromTemplateBytes(data []byte, algo poolpb.Algo) (*Job, error) {
	return f.client.JobFromTemplateBytes(data, algo)
}

// moneroFixtureTemplateWireWithHeight caches the marshaled fixture
// wire bytes per height so GetBlockTemplate (which has no *testing.T)
// can serve them without re-running the go-xmr-lib derivation on
// every call. Populated by newExtraNonceFixtureJobManager below,
// which DOES have a *testing.T.
var (
	moneroFixtureWireMu sync.Mutex
	moneroFixtureWire   = map[uint64][]byte{}
)

func moneroFixtureTemplateWireBytesFor(height uint64) []byte {
	moneroFixtureWireMu.Lock()
	defer moneroFixtureWireMu.Unlock()
	out := make([]byte, len(moneroFixtureWire[height]))
	copy(out, moneroFixtureWire[height])
	return out
}

func primeMoneroFixtureWire(t *testing.T, heights ...uint64) {
	t.Helper()
	for _, h := range heights {
		data := moneroFixtureTemplateWireBytes(t, h)
		moneroFixtureWireMu.Lock()
		moneroFixtureWire[h] = data
		moneroFixtureWireMu.Unlock()
	}
}

// newExtraNonceFixtureJobManager wires a real RXM (Monero-family,
// therefore shared-template -- see usesSharedTemplate) JobManager to a
// fakeMoneroFixtureNodeClient, and resets the process-wide
// malformed-blob circuit breaker so a leftover open breaker from
// another test in this package can never refuse this test's own
// legitimate real-fixture conversions (see moneroblob's package doc
// comment for why that breaker is a genuine singleton).
func newExtraNonceFixtureJobManager(t *testing.T, heights ...uint64) (*JobManager, *fakeMoneroFixtureNodeClient) {
	t.Helper()
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	primeMoneroFixtureWire(t, heights...)
	node := newFakeMoneroFixtureNodeClient(heights[0])
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "extranonce-test-address",
		StaticDifficulty: 5000,
		Algo:             poolpb.Algo_ALGO_RXM,
		Logger:           log.New(io.Discard, "", 0),
	})
	return jm, node
}

// parsedExtraNonceRegion re-parses job's OWN RawTemplateBlob with
// go-xmr-lib's real ParseBlockFromTemplateBlob and returns the real
// coinbase tx_extra nonce region -- the actual 60 reserved bytes
// monerod handed back, whose layout is
// |+0 extraNonce|+4 instanceId|+8 clientPoolNonce|+12 clientNonce|.
// Asserting against THIS (rather than raw byte slices at hand-counted
// offsets) is what makes these tests prove the stamp landed in the
// genuine reserved region of a genuinely still-parseable block.
func parsedExtraNonceRegion(t *testing.T, job *Job) []byte {
	t.Helper()
	if len(job.RawTemplateBlob) == 0 {
		t.Fatal("job.RawTemplateBlob is empty -- cannot inspect its reserved region")
	}
	parsed, err := support.ParseBlockFromTemplateBlob(hex.EncodeToString(job.RawTemplateBlob))
	if err != nil {
		t.Fatalf("support.ParseBlockFromTemplateBlob on the derived job's own raw template blob: %v", err)
	}
	nonceRegion := parsed.MinerTxn.Extra.Nonce
	if len(nonceRegion) < 8 {
		t.Fatalf("parsed coinbase tx_extra nonce region is only %d bytes, want at least 8 (extraNonce at +0, instanceID at +4)", len(nonceRegion))
	}
	return nonceRegion
}

func stampedExtraNonce(t *testing.T, job *Job) uint32 {
	t.Helper()
	return binary.BigEndian.Uint32(parsedExtraNonceRegion(t, job)[0:4])
}

func stampedInstanceID(t *testing.T, job *Job) []byte {
	t.Helper()
	return parsedExtraNonceRegion(t, job)[4:8]
}

// TestSharedTemplateDifferentXNsGetDistinctExtraNonceStampedBlobs is
// THE regression test for the reported bug: two sequential jobForXN
// calls for two genuinely DIFFERENT xns, against the SAME shared
// template (proved by the single GetBlockTemplate call), must produce
// two *Jobs whose Header (the hashing blob a miner actually mines)
// AND RawTemplateBlob genuinely differ -- and must differ for the
// RIGHT reason (a real, incrementing extraNonce in the real coinbase
// tx_extra reserved region, not incidental noise).
func TestSharedTemplateDifferentXNsGetDistinctExtraNonceStampedBlobs(t *testing.T) {
	const height = 3_500_777
	jm, node := newExtraNonceFixtureJobManager(t, height)
	ctx := context.Background()

	jobA, err := jm.JobForXN(ctx, "aaaa")
	if err != nil {
		t.Fatalf("JobForXN(aaaa): %v", err)
	}
	jobB, err := jm.JobForXN(ctx, "bbbb")
	if err != nil {
		t.Fatalf("JobForXN(bbbb): %v", err)
	}

	// Still ONE shared template (this fix must not reintroduce the
	// per-session daemon-call stampede the shared-template feature
	// removed -- see job_shared_template_test.go).
	if got := node.callCount(); got != 1 {
		t.Fatalf("GetBlockTemplate call count = %d, want exactly 1 (both xns must still share ONE template)", got)
	}

	// THE actual bug: byte-identical blobs across sessions.
	if bytes.Equal(jobA.Header, jobB.Header) {
		t.Fatalf("BUG REGRESSION: two different xns got BYTE-IDENTICAL hashing blobs (Header) from the same shared template: %s", hex.EncodeToString(jobA.Header))
	}
	if bytes.Equal(jobA.RawTemplateBlob, jobB.RawTemplateBlob) {
		t.Fatal("BUG REGRESSION: two different xns got BYTE-IDENTICAL RawTemplateBlobs from the same shared template")
	}

	// ...and differ for the RIGHT reason: a real, incrementing
	// extraNonce at reserved_offset+0, big-endian, in the genuinely
	// re-parseable coinbase tx_extra reserved region. The counter
	// starts at 0 and is PRE-incremented (legacy's
	// `++this.extraNonce`), so the first two derivations are 1 and 2.
	if got := stampedExtraNonce(t, jobA); got != 1 {
		t.Errorf("first derived job's stamped extraNonce = %d, want 1 (counter starts at 0, pre-incremented per derivation)", got)
	}
	if got := stampedExtraNonce(t, jobB); got != 2 {
		t.Errorf("second derived job's stamped extraNonce = %d, want 2", got)
	}

	// The already-shipped per-leaf instanceID stamp at
	// reserved_offset+4 must be preserved verbatim and identically in
	// both (this fix writes a DIFFERENT 4 bytes, at +0, coexisting
	// with it exactly like legacy's extraNonce/instanceId do).
	idA := stampedInstanceID(t, jobA)
	idB := stampedInstanceID(t, jobB)
	if !bytes.Equal(idA, idB) {
		t.Errorf("per-leaf instanceID differs between two jobs derived from the SAME template (%x vs %x) -- the extraNonce stamp must not disturb the +4 slot", idA, idB)
	}
	if bytes.Equal(idA, []byte{0, 0, 0, 0}) {
		t.Error("per-leaf instanceID is all zeroes in the derived job -- the extraNonce stamp appears to have clobbered the +4 slot")
	}

	// The hashing blob must still be a real, correctly-sized RandomX
	// hashing blob (the extraNonce patch changes the coinbase, hence
	// the merkle root, hence the hashing blob -- but never its shape).
	for name, job := range map[string]*Job{"aaaa": jobA, "bbbb": jobB} {
		if len(job.Header) != xnpFixtureHashingBlobLen {
			t.Errorf("job for xn %s: len(Header) = %d, want %d (the real, correctly-sized RandomX hashing blob for this fixture)", name, len(job.Header), xnpFixtureHashingBlobLen)
		}
	}

	// Repeat requests for an already-cached xn must still return the
	// SAME Job (JobForXN's documented contract) -- the stamp happens
	// once per genuinely-new derivation, not once per getjob.
	again, err := jm.JobForXN(ctx, "aaaa")
	if err != nil {
		t.Fatalf("JobForXN(aaaa) repeat: %v", err)
	}
	if again != jobA {
		t.Fatal("a repeat JobForXN call for an already-cached xn returned a different *Job -- the extraNonce stamp must not fire on cache hits")
	}
}

// TestSharedTemplateStampedJobCarriesItsOwnTemplateData is the
// explicit consistency proof required alongside the stamp itself: the
// derived Job's own TemplateData.(*moneroTemplateData) must carry
// EXACTLY the patched HashingBlob/TemplateBlob that job's
// Header/RawTemplateBlob carry -- never the parent template's
// originals.
//
// This matters for real money, not tidiness:
// MoneroNodeClient.BuildCandidateBlock patches the miner's winning
// nonce into data.TemplateBlob and cross-checks the nonce offset it
// re-parses from data.HashingBlob. A Job whose TemplateData still
// pointed at the PARENT's unstamped buffers would therefore submit a
// block built on a template nobody ever mined.
func TestSharedTemplateStampedJobCarriesItsOwnTemplateData(t *testing.T) {
	const height = 3_500_778
	jm, _ := newExtraNonceFixtureJobManager(t, height)

	job, err := jm.JobForXN(context.Background(), "cccc")
	if err != nil {
		t.Fatalf("JobForXN: %v", err)
	}

	data, ok := job.TemplateData.(*moneroTemplateData)
	if !ok || data == nil {
		t.Fatalf("derived job's TemplateData does not hold a real *moneroTemplateData (%T)", job.TemplateData)
	}
	if !bytes.Equal(data.HashingBlob, job.Header) {
		t.Error("TemplateData.HashingBlob != job.Header -- the derived job's own TemplateData is not the extraNonce-stamped one")
	}
	if !bytes.Equal(data.TemplateBlob, job.RawTemplateBlob) {
		t.Error("TemplateData.TemplateBlob != job.RawTemplateBlob -- the derived job's own TemplateData is not the extraNonce-stamped one")
	}

	// And the parent shared template must be untouched (the stamp
	// always copies; it must never patch the shared template in
	// place, or every session would see every other session's
	// stamp).
	tpl, _, ok := jm.sharedTemplateSnapshot()
	if !ok {
		t.Fatal("no shared template established")
	}
	if bytes.Equal(tpl.RawTemplateBlob, job.RawTemplateBlob) {
		t.Fatal("the shared template's own RawTemplateBlob was mutated in place by the stamp")
	}
	if got := binary.BigEndian.Uint32(tpl.RawTemplateBlob[tpl.ReservedOffset : tpl.ReservedOffset+4]); got != 0 {
		t.Errorf("shared template's own reserved_offset+0 = %d, want 0 (never stamped in place)", got)
	}

	// BuildCandidateBlock must accept this derived job (its own
	// nonce-offset cross-check is exactly what a stale/mismatched
	// TemplateData would trip). The claimed result hash just needs to
	// be real 32-byte hex and non-zero (an all-zero hash is rejected
	// by its own division-by-zero guard); its actual difficulty is
	// irrelevant here.
	claimedHash := bytes.Repeat([]byte{0x11}, 32)
	_, candidate, err := jm.cfg.Node.BuildCandidateBlock(job, 0x818d1a00, SubmitProof{ResultHex: hex.EncodeToString(claimedHash)})
	if err != nil {
		t.Fatalf("BuildCandidateBlock on an extraNonce-stamped derived job: %v", err)
	}
	mc, ok := candidate.(*MoneroCandidate)
	if !ok || mc == nil {
		t.Fatalf("BuildCandidateBlock returned %T, want *MoneroCandidate", candidate)
	}
	// The candidate must be built on THIS job's stamped template
	// bytes: same extraNonce in the same reserved region.
	parsed, err := support.ParseBlockFromTemplateBlob(hex.EncodeToString(mc.TemplateBlob))
	if err != nil {
		t.Fatalf("re-parsing the candidate block: %v", err)
	}
	if got := binary.BigEndian.Uint32(parsed.MinerTxn.Extra.Nonce[0:4]); got != stampedExtraNonce(t, job) {
		t.Errorf("candidate block's extraNonce = %d, want %d (the job's own stamp) -- BuildCandidateBlock patched a stale buffer", got, stampedExtraNonce(t, job))
	}
}

// TestSharedTemplateExtraNonceRestartsOnGenuinelyNewTemplate is the
// required proof of the counter's lifetime rule: it is per-TEMPLATE,
// not per-JobManager. A genuinely new template generation (here, a
// real tip-change-shaped InvalidateAll followed by a fresh fetch)
// must restart the sequence at 1, exactly mirroring legacy's own
// `this.extraNonce = 0` living in the BlockTemplate CONSTRUCTOR.
func TestSharedTemplateExtraNonceRestartsOnGenuinelyNewTemplate(t *testing.T) {
	const (
		heightOne = 3_500_800
		heightTwo = 3_500_801
	)
	jm, node := newExtraNonceFixtureJobManager(t, heightOne, heightTwo)
	ctx := context.Background()

	first, err := jm.JobForXN(ctx, "aaaa")
	if err != nil {
		t.Fatalf("JobForXN(aaaa): %v", err)
	}
	second, err := jm.JobForXN(ctx, "bbbb")
	if err != nil {
		t.Fatalf("JobForXN(bbbb): %v", err)
	}
	if got := stampedExtraNonce(t, first); got != 1 {
		t.Fatalf("generation 1, first derivation: extraNonce = %d, want 1", got)
	}
	if got := stampedExtraNonce(t, second); got != 2 {
		t.Fatalf("generation 1, second derivation: extraNonce = %d, want 2", got)
	}

	// A genuinely new template generation.
	node.setHeight(heightTwo)
	jm.InvalidateAll(TemplateSourceLocal)

	afterOne, err := jm.JobForXN(ctx, "aaaa")
	if err != nil {
		t.Fatalf("JobForXN(aaaa) after invalidation: %v", err)
	}
	afterTwo, err := jm.JobForXN(ctx, "bbbb")
	if err != nil {
		t.Fatalf("JobForXN(bbbb) after invalidation: %v", err)
	}
	if got := node.callCount(); got != 2 {
		t.Fatalf("GetBlockTemplate call count = %d, want 2 (one per template generation)", got)
	}
	if afterOne.Height != heightTwo {
		t.Fatalf("post-invalidation job height = %d, want %d (a genuinely new template)", afterOne.Height, heightTwo)
	}
	if got := stampedExtraNonce(t, afterOne); got != 1 {
		t.Errorf("generation 2, first derivation: extraNonce = %d, want 1 -- the counter must RESTART for a genuinely new template, not continue from the previous generation", got)
	}
	if got := stampedExtraNonce(t, afterTwo); got != 2 {
		t.Errorf("generation 2, second derivation: extraNonce = %d, want 2", got)
	}
}

// TestSharedTemplateRelayAdoptionAlsoStampsExtraNonce covers the
// relay-adoption half of the brief: a leaf that ADOPTS a sibling's
// relayed template must give ITS OWN sessions the same "every new job
// gets a fresh stamp" treatment, on top of the already-shipped
// instanceID stamp -- both for the xns reseeded by the adoption
// itself (adoptRelayedJobShared) and for sessions arriving later off
// the adopted shared template (jobForXNFromSharedTemplate). Both go
// through the SAME jobFromSharedTemplate helper, which is exactly
// what this asserts (no forked second implementation).
func TestSharedTemplateRelayAdoptionAlsoStampsExtraNonce(t *testing.T) {
	const (
		localHeight    = 3_500_900
		adoptedHeight  = 3_500_950
		knownXNCount   = 3
		wantAdoptCalls = 1
	)
	jm, node := newExtraNonceFixtureJobManager(t, localHeight, adoptedHeight)
	ctx := context.Background()

	knownXNs := []string{"aa01", "aa02", "aa03"}
	for _, xn := range knownXNs {
		if _, err := jm.JobForXN(ctx, xn); err != nil {
			t.Fatalf("JobForXN(%s): %v", xn, err)
		}
	}
	if got := node.callCount(); got != wantAdoptCalls {
		t.Fatalf("pre-adoption GetBlockTemplate call count = %d, want %d", got, wantAdoptCalls)
	}

	// Reconstruct a "relayed" template exactly the way
	// startTemplateRelaySubscription does, then adopt it.
	adopted, err := jm.cfg.Node.JobFromTemplateBytes(moneroFixtureTemplateWireBytesFor(adoptedHeight), poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("JobFromTemplateBytes(relayed): %v", err)
	}
	jm.adoptRelayedJob(adopted)

	if got := node.callCount(); got != wantAdoptCalls {
		t.Fatalf("post-adoption GetBlockTemplate call count = %d, want still %d (adoption must need no local fetch)", got, wantAdoptCalls)
	}

	seen := map[uint32]string{}
	for _, xn := range knownXNs {
		job, err := jm.JobForXN(ctx, xn)
		if err != nil {
			t.Fatalf("JobForXN(%s) after adoption: %v", xn, err)
		}
		if job.Height != adoptedHeight {
			t.Fatalf("xn %s: height = %d, want the adopted %d", xn, job.Height, adoptedHeight)
		}
		nonce := stampedExtraNonce(t, job)
		if nonce == 0 {
			t.Fatalf("xn %s: job derived from the ADOPTED relay template carries no extraNonce stamp -- the relay-adoption path must stamp too", xn)
		}
		if prev, dup := seen[nonce]; dup {
			t.Fatalf("xn %s and xn %s were both derived from the adopted relay template with the SAME extraNonce %d -- duplicate search space", xn, prev, nonce)
		}
		seen[nonce] = xn
	}

	// A session arriving AFTER the adoption (a plain cache miss
	// against the adopted shared template) must draw from the SAME
	// counter, so it cannot collide with any of the reseeded xns.
	late, err := jm.JobForXN(ctx, "bb99")
	if err != nil {
		t.Fatalf("JobForXN(bb99) after adoption: %v", err)
	}
	if got := node.callCount(); got != wantAdoptCalls {
		t.Fatalf("a post-adoption new xn triggered a local GetBlockTemplate (count = %d) -- it must derive from the adopted shared template", got)
	}
	lateNonce := stampedExtraNonce(t, late)
	if prev, dup := seen[lateNonce]; dup {
		t.Fatalf("a session arriving after the adoption reused xn %s's extraNonce %d -- the adopting leaf's later sessions must draw from the same per-template counter", prev, lateNonce)
	}
	if len(seen) != knownXNCount {
		t.Fatalf("expected %d distinct extraNonce values across the reseeded xns, got %d", knownXNCount, len(seen))
	}
}

// --- Graceful degradation on an unparseable template ---

// malformedMoneroTemplateJob builds a shared template whose
// RawTemplateBlob is NOT a real, go-xmr-lib-parseable Monero block:
// its reserved region genuinely fits (so the stamp is attempted, not
// skipped on bounds), but re-deriving a hashing blob from the patched
// bytes trips the exact known go-xmr-lib v0.2.5 panic failure mode
// internal/leaflib/proxy's own applyJob tests already exercise
// (serialization consuming a corrupt length-prefixed field via direct
// slicing: "slice bounds out of range").
//
// Deliberately chosen to panic FAST rather than to trigger that
// library's OTHER known failure mode, the ConstructTXExtra infinite
// loop: that one leaks a permanently-CPU-core-spinning goroutine per
// trigger by design (see moneroblob's doc comment), and this suite
// must not add more of those.
func malformedMoneroTemplateJob() *Job {
	const (
		rawLen         = 128
		reservedOffset = 100
		nonceOffset    = 39 // real-shaped; never actually reached, conversion fails first
	)
	raw := make([]byte, rawLen)
	for i := range raw {
		raw[i] = byte(i % 256)
	}
	hashing := make([]byte, xnpFixtureHashingBlobLen)
	copy(hashing, raw[:xnpFixtureHashingBlobLen])
	return &Job{
		ID:                      "malformed-template-job",
		Algo:                    poolpb.Algo_ALGO_RXM,
		Height:                  4_000_000,
		Header:                  hashing,
		BlockHash:               extraNonceTestPrevHash,
		NetworkTargetDifficulty: 1 << 40,
		TemplateData: &moneroTemplateData{
			HashingBlob:    hashing,
			TemplateBlob:   raw,
			NonceOffset:    nonceOffset,
			SeedHash:       extraNonceTestSeedHash,
			Difficulty:     1 << 40,
			Height:         4_000_000,
			ReservedOffset: reservedOffset,
		},
		VmKey:                extraNonceTestSeedHash,
		ReservedOffset:       reservedOffset,
		ReservedOffsetUsable: true,
		RawTemplateBlob:      raw,
	}
}

// TestSharedTemplateUnparseableBlobDegradesToUnstampedBytes is the
// required graceful-degradation proof: a template whose raw blob
// cannot be re-parsed/re-converted must NOT fail job derivation, must
// NOT crash the process, and must fall back to serving the UNSTAMPED
// template bytes -- the exact behavior that existed before this fix.
func TestSharedTemplateUnparseableBlobDegradesToUnstampedBytes(t *testing.T) {
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	node := newFakeMoneroFixtureNodeClient(4_000_000)
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "extranonce-test-address",
		StaticDifficulty: 5000,
		Algo:             poolpb.Algo_ALGO_RXM,
		Logger:           log.New(io.Discard, "", 0),
	})
	tpl := malformedMoneroTemplateJob()
	jm.setSharedTemplate(tpl)

	job, err := jm.JobForXN(context.Background(), "dead")
	if err != nil {
		t.Fatalf("job derivation failed outright on an unparseable template blob -- it must degrade gracefully, never fail: %v", err)
	}
	if got := node.callCount(); got != 0 {
		t.Fatalf("GetBlockTemplate was called %d time(s) -- the pre-installed shared template should have been used", got)
	}
	if !bytes.Equal(job.Header, tpl.Header) {
		t.Error("derived job's Header is not the template's own UNSTAMPED hashing blob -- the fallback did not take effect")
	}
	if !bytes.Equal(job.RawTemplateBlob, tpl.RawTemplateBlob) {
		t.Error("derived job's RawTemplateBlob is not the template's own UNSTAMPED raw blob -- the fallback did not take effect")
	}
	if job.TemplateData != tpl.TemplateData {
		t.Error("derived job's TemplateData was replaced even though the stamp failed -- Header/RawTemplateBlob/TemplateData must move together, never a mix")
	}
	// It is still a real, usable per-session Job in every other
	// respect (own ID, own difficulty) -- degradation costs the
	// stamp, not the job.
	if job.ID == tpl.ID {
		t.Error("derived job reused the template's own ID")
	}
	if job.StaticDifficulty != 5000 {
		t.Errorf("derived job difficulty = %d, want 5000", job.StaticDifficulty)
	}
}

// TestSharedTemplateUnparseableBlobDoesNotWedgeTheCircuitBreaker
// proves the breaker is neither weakened NOR abused by this new call
// site: ONE genuinely unparseable template generation costs exactly
// ONE breaker trigger no matter how many sessions derive jobs from it
// (extraNonceStampedTemplate latches
// sharedTemplateGeneration.stampUnavailable), so a single bad
// template can never trip the process-wide breaker open and thereby
// also refuse the unrelated XNP-proxy submit path's own conversions.
//
// The derivation count here (well past moneroblob.BreakerThreshold)
// is the point: without the latch, this loop alone would open the
// breaker.
func TestSharedTemplateUnparseableBlobDoesNotWedgeTheCircuitBreaker(t *testing.T) {
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	opensBefore := moneroblob.GlobalBreaker.OpensTotal()

	node := newFakeMoneroFixtureNodeClient(4_000_000)
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "extranonce-test-address",
		StaticDifficulty: 5000,
		Algo:             poolpb.Algo_ALGO_RXM,
		Logger:           log.New(io.Discard, "", 0),
	})
	jm.setSharedTemplate(malformedMoneroTemplateJob())

	derivations := 4 * moneroblob.BreakerThreshold
	for i := 0; i < derivations; i++ {
		xn := hex.EncodeToString([]byte{byte(i >> 8), byte(i)})
		if _, err := jm.JobForXN(context.Background(), xn); err != nil {
			t.Fatalf("derivation %d failed outright: %v", i, err)
		}
	}

	if moneroblob.GlobalBreaker.IsOpen() {
		t.Fatalf("the process-wide malformed-blob circuit breaker OPENED after %d derivations from a single unparseable template -- the per-template-generation latch is not working, so one bad template would also refuse conversions on the XNP-proxy submit path", derivations)
	}
	if got := moneroblob.GlobalBreaker.OpensTotal(); got != opensBefore {
		t.Fatalf("breaker OpensTotal went %d -> %d", opensBefore, got)
	}

	// The breaker itself must NOT have been weakened: it still opens
	// on a genuine, sustained streak of real triggers. Proved here
	// against the very same singleton, using its real RecordTrigger
	// path (moneroblob's own tests cover the state machine in
	// isolation; this is specifically "the singleton this new call
	// site shares is still fully armed").
	for i := 0; i < moneroblob.BreakerThreshold; i++ {
		moneroblob.GlobalBreaker.RecordTrigger(log.New(io.Discard, "", 0))
	}
	if !moneroblob.GlobalBreaker.IsOpen() {
		t.Fatal("the shared breaker did not open after a full threshold of consecutive real triggers -- it has been weakened")
	}
}

// TestSharedTemplateStampIsSkippedForNonMoneroTemplateData is the
// no-regression guard for every non-Monero (Tari) and synthetic-test
// shared template: when the template carries no *moneroTemplateData,
// the derivation must take the EXACT pre-fix path, sharing the
// template's own Header/RawTemplateBlob/TemplateData by reference with
// no conversion attempt at all.
func TestSharedTemplateStampIsSkippedForNonMoneroTemplateData(t *testing.T) {
	moneroblob.GlobalBreaker.ResetForTest()
	t.Cleanup(func() { moneroblob.GlobalBreaker.ResetForTest() })

	tpl := &Job{
		ID:              "non-monero-template",
		Algo:            poolpb.Algo_ALGO_RXM,
		Height:          7,
		Header:          []byte("not-a-monero-hashing-blob"),
		RawTemplateBlob: []byte("not-a-monero-template-blob"),
		TemplateData:    struct{ Some string }{Some: "definitely not *moneroTemplateData"},
		ReservedOffset:  0,
	}
	jm := NewJobManager(JobManagerConfig{
		Node:             newFakeMoneroFixtureNodeClient(7),
		PayoutAddress:    "extranonce-test-address",
		StaticDifficulty: 11,
		Algo:             poolpb.Algo_ALGO_RXM,
		Logger:           log.New(io.Discard, "", 0),
	})
	jm.setSharedTemplate(tpl)

	job, err := jm.JobForXN(context.Background(), "beef")
	if err != nil {
		t.Fatalf("JobForXN: %v", err)
	}
	if !bytes.Equal(job.Header, tpl.Header) || !bytes.Equal(job.RawTemplateBlob, tpl.RawTemplateBlob) {
		t.Error("a non-Monero shared template's Header/RawTemplateBlob were altered -- the stamp must be Monero-family-only")
	}
	if job.TemplateData != tpl.TemplateData {
		t.Error("a non-Monero shared template's TemplateData was replaced -- the stamp must be Monero-family-only")
	}
}

// --- Logging-only diagnostic fix: every early-return path of
// extraNonceStampedTemplate must now produce a real, matchable log
// line (see this fix's own dispatch brief) -- none of the actual
// stamping logic/bounds-check thresholds/control flow changes; these
// tests exist purely to prove the NEW observability, calling
// extraNonceStampedTemplate directly (rather than through JobForXN)
// so each path can be exercised and asserted on in isolation.

// newLoggingTestJobManager returns a bare JobManager whose jm.logger
// writes to the returned *bytes.Buffer -- extraNonceStampedTemplate
// never touches jm.cfg.Node, so Node is deliberately left unset.
func newLoggingTestJobManager(t *testing.T) (*JobManager, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	jm := NewJobManager(JobManagerConfig{
		Algo:   poolpb.Algo_ALGO_RXM,
		Logger: log.New(&buf, "", 0),
	})
	return jm, &buf
}

// validStampableMoneroTemplateJob returns a *Job/*sharedTemplateGeneration
// pair that passes every one of extraNonceStampedTemplate's nil/type/
// empty-blob guards, with a real go-xmr-lib-parseable RawTemplateBlob
// (the xnpFixtureRawTemplateBlob fixture) -- so tests targeting a
// SPECIFIC later guard (the stampUnavailable latch, or the bounds
// check) can start from a template that would otherwise stamp
// successfully, isolating the one condition under test.
func validStampableMoneroTemplateJob(t *testing.T) (*Job, *sharedTemplateGeneration) {
	t.Helper()
	rawTemplate, err := hex.DecodeString(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("decoding fixture hex: %v", err)
	}
	parsedBlock, err := support.ParseBlockFromTemplateBlob(xnpFixtureRawTemplateBlob)
	if err != nil {
		t.Fatalf("support.ParseBlockFromTemplateBlob(fixture): %v", err)
	}
	hashingBlob, err := support.GetBlockHashingBlob(parsedBlock)
	if err != nil {
		t.Fatalf("support.GetBlockHashingBlob(fixture): %v", err)
	}
	tpl := &Job{
		ID:              "logging-test-template",
		Algo:            poolpb.Algo_ALGO_RXM,
		Height:          9_999_999,
		Header:          hashingBlob,
		RawTemplateBlob: rawTemplate,
		TemplateData: &moneroTemplateData{
			HashingBlob:    hashingBlob,
			TemplateBlob:   rawTemplate,
			NonceOffset:    39,
			SeedHash:       extraNonceTestSeedHash,
			Difficulty:     1 << 40,
			Height:         9_999_999,
			ReservedOffset: xnpFixtureReservedOffset,
		},
		ReservedOffset: xnpFixtureReservedOffset,
	}
	return tpl, &sharedTemplateGeneration{}
}

// fakeNonMoneroTemplateData is a deliberately-distinct, obviously-
// non-*moneroTemplateData concrete type, standing in for a real
// Tari-shaped TemplateData landing on this Monero-only path by
// mistake -- chosen so its %T-formatted type name
// ("solo.fakeNonMoneroTemplateData") is unambiguous in the asserted
// log output.
type fakeNonMoneroTemplateData struct{ notMonero string }

// TestExtraNonceStampedTemplateLogsNilTplOrGen covers dispatch-brief
// item 1: tpl == nil || gen == nil must now log which of the two was
// nil, instead of returning silently.
func TestExtraNonceStampedTemplateLogsNilTplOrGen(t *testing.T) {
	validTpl, validGen := validStampableMoneroTemplateJob(t)

	cases := []struct {
		name      string
		tpl       *Job
		gen       *sharedTemplateGeneration
		wantInLog string
	}{
		{"both nil", nil, nil, "tpl_nil=true gen_nil=true"},
		{"tpl nil only", nil, validGen, "tpl_nil=true gen_nil=false"},
		{"gen nil only", validTpl, nil, "tpl_nil=false gen_nil=true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jm, buf := newLoggingTestJobManager(t)
			_, ok := jm.extraNonceStampedTemplate(tc.tpl, tc.gen)
			if ok {
				t.Fatal("expected ok=false")
			}
			got := buf.String()
			if !strings.Contains(got, tc.wantInLog) {
				t.Fatalf("expected log output to contain %q, got:\n%s", tc.wantInLog, got)
			}
			if !strings.Contains(got, "extraNonce stamp") {
				t.Fatalf("expected log output to explain the stamp is being skipped, got:\n%s", got)
			}
		})
	}
}

// TestExtraNonceStampedTemplateLogsWrongTemplateDataType covers
// dispatch-brief item 2: TemplateData not being a *moneroTemplateData
// (a real Tari-shaped value, or a genuine nil) must log the actual
// concrete Go type found via %T, so the two cases are distinguishable
// from production logs.
func TestExtraNonceStampedTemplateLogsWrongTemplateDataType(t *testing.T) {
	t.Run("wrong concrete type", func(t *testing.T) {
		jm, buf := newLoggingTestJobManager(t)
		tpl, gen := validStampableMoneroTemplateJob(t)
		tpl.TemplateData = fakeNonMoneroTemplateData{notMonero: "tari-shaped"}

		_, ok := jm.extraNonceStampedTemplate(tpl, gen)
		if ok {
			t.Fatal("expected ok=false")
		}
		got := buf.String()
		if !strings.Contains(got, "solo.fakeNonMoneroTemplateData") {
			t.Fatalf("expected log output to name the actual concrete type via %%T, got:\n%s", got)
		}
	})

	t.Run("genuine nil", func(t *testing.T) {
		jm, buf := newLoggingTestJobManager(t)
		tpl, gen := validStampableMoneroTemplateJob(t)
		tpl.TemplateData = nil

		_, ok := jm.extraNonceStampedTemplate(tpl, gen)
		if ok {
			t.Fatal("expected ok=false")
		}
		got := buf.String()
		if !strings.Contains(got, "<nil>") {
			t.Fatalf("expected log output to show the genuinely-nil case distinctly (%%T of nil is \"<nil>\"), got:\n%s", got)
		}
	})
}

// TestExtraNonceStampedTemplateLogsEmptyRawTemplateBlob covers
// dispatch-brief item 3: len(tpl.RawTemplateBlob) == 0 must now log.
func TestExtraNonceStampedTemplateLogsEmptyRawTemplateBlob(t *testing.T) {
	jm, buf := newLoggingTestJobManager(t)
	tpl, gen := validStampableMoneroTemplateJob(t)
	tpl.RawTemplateBlob = nil

	_, ok := jm.extraNonceStampedTemplate(tpl, gen)
	if ok {
		t.Fatal("expected ok=false")
	}
	got := buf.String()
	if !strings.Contains(got, "empty RawTemplateBlob") {
		t.Fatalf("expected log output to mention the empty RawTemplateBlob, got:\n%s", got)
	}
	if !strings.Contains(got, "height=9999999") {
		t.Fatalf("expected log output to include the template height, got:\n%s", got)
	}
}

// TestExtraNonceStampedTemplateLatchedGenerationLogsExactlyOnce
// covers dispatch-brief item 4: once gen.stampUnavailable is latched
// true (by an earlier failed derivation, simulated directly here),
// every SUBSEQUENT call must still be logged, but EXACTLY ONCE across
// the whole generation -- never once per call (that would reintroduce
// the one-log-line-per-session flood
// sharedTemplateGeneration.stampUnavailable's own doc comment
// explicitly rules out), and never silently (the specific regression
// this fix closes).
func TestExtraNonceStampedTemplateLatchedGenerationLogsExactlyOnce(t *testing.T) {
	jm, buf := newLoggingTestJobManager(t)
	tpl, gen := validStampableMoneroTemplateJob(t)
	// Simulate an earlier derivation having already found this
	// generation un-stampable (e.g. via the bounds check or a failed
	// hashing-blob re-derivation) and latched it -- exactly the state
	// every call in this test observes.
	gen.stampUnavailable.Store(true)

	const derivations = 5
	for i := 0; i < derivations; i++ {
		_, ok := jm.extraNonceStampedTemplate(tpl, gen)
		if ok {
			t.Fatalf("derivation %d: expected ok=false once stampUnavailable is latched", i)
		}
	}

	got := buf.String()
	const wantSubstr = "already latched un-stampable"
	if count := strings.Count(got, wantSubstr); count != 1 {
		t.Fatalf("expected exactly 1 log line containing %q across %d calls on the same latched generation, got %d. Full log:\n%s", wantSubstr, derivations, count, got)
	}
}

// TestExtraNonceStampedTemplateLogsAnomalousBoundsCheckAsWarning
// covers dispatch-brief item 5: the ReservedOffset/
// minReservedOffsetHeadroom bounds check must now log via
// jm.logger.Printf (always-on, not jm.cfg.Debug.Debugf, which is a
// no-op without -debug), worded to reflect that this condition is a
// genuine anomaly for a real Monero block template -- never routine
// degradation.
func TestExtraNonceStampedTemplateLogsAnomalousBoundsCheckAsWarning(t *testing.T) {
	jm, buf := newLoggingTestJobManager(t)
	tpl, gen := validStampableMoneroTemplateJob(t)
	// Force the bounds check to fail: offset + minReservedOffsetHeadroom
	// must exceed len(RawTemplateBlob).
	tpl.ReservedOffset = len(tpl.RawTemplateBlob) - minReservedOffsetHeadroom + 1

	_, ok := jm.extraNonceStampedTemplate(tpl, gen)
	if ok {
		t.Fatal("expected ok=false")
	}
	if !gen.stampUnavailable.Load() {
		t.Error("expected gen.stampUnavailable to be latched true after the bounds check fails")
	}
	got := buf.String()
	for _, wantSubstr := range []string{
		"WARNING",
		"reserved region does not fit in template blob",
		"structurally impossible",
		"genuine anomaly",
	} {
		if !strings.Contains(got, wantSubstr) {
			t.Errorf("expected log output to contain %q, got:\n%s", wantSubstr, got)
		}
	}

	// A second call against the now-latched generation must NOT
	// repeat the WARNING line (that would defeat the whole point of
	// latching) -- it takes the separate, one-time
	// stampUnavailableLogged path covered by
	// TestExtraNonceStampedTemplateLatchedGenerationLogsExactlyOnce.
	buf.Reset()
	if _, ok := jm.extraNonceStampedTemplate(tpl, gen); ok {
		t.Fatal("expected ok=false on the second, already-latched call")
	}
	if got := buf.String(); strings.Contains(got, "WARNING: reserved region") {
		t.Errorf("expected the bounds-check WARNING to fire only once per generation, got a repeat:\n%s", got)
	}
}
