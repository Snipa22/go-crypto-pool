// Copyright and license: see repository LICENSE (MIT).
package direct

import (
	"bytes"
	"testing"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestNodeClientBuildCoinbaseExtraContainsConfiguredTag mirrors
// solo's own TestGRPCNodeClientBuildCoinbaseExtraContainsConfiguredTag
// for leaf-direct's independent NodeClient implementation -- verifies
// the exact bytes GetBlockTemplate would submit as CoinbaseExtra start
// with this instance's configured coinbaseExtraTag, without needing a
// real GRPC connection.
func TestNodeClientBuildCoinbaseExtraContainsConfiguredTag(t *testing.T) {
	tag := []byte("supportxtm-rxt")
	c := &NodeClient{coinbaseExtraTag: tag}

	extra := c.buildCoinbaseExtra()

	if !bytes.HasPrefix(extra, tag) {
		t.Fatalf("buildCoinbaseExtra() = %q, want prefix %q", extra, tag)
	}
}

func TestNodeClientBuildCoinbaseExtraDiffersPerCall(t *testing.T) {
	c := &NodeClient{coinbaseExtraTag: []byte("supportxtm-sha3x")}
	a := c.buildCoinbaseExtra()
	b := c.buildCoinbaseExtra()
	if bytes.Equal(a, b) {
		t.Errorf("two calls to buildCoinbaseExtra() produced identical bytes %q -- nonce is no longer randomized", a)
	}
}

// TestTariJobFromResult_JobIDsAreRandomNotContentDerived is
// leaf-direct's own counterpart to solo's identically-named test
// (internal/leaflib/solo/node_test.go) -- see that test's doc comment
// for the full "SHA3X was only accidentally safe" rationale. This
// package's own tariJobFromResult used to derive job.ID from
// leaflib.JobIDFromBlockHash(result.GetBlockHash()) alone; it now
// mints a purely random, opaque token via leaflib.NewRandomHexID
// instead, so two calls with byte-identical BlockHash/Height must
// still produce two distinct job IDs.
func TestTariJobFromResult_JobIDsAreRandomNotContentDerived(t *testing.T) {
	blockHash := bytes.Repeat([]byte{0xAB}, 32)
	result := &tari_generated.GetNewBlockResult{
		BlockHash:       blockHash,
		MergeMiningHash: bytes.Repeat([]byte{0xCD}, 32),
		Block: &tari_generated.Block{
			Header: &tari_generated.BlockHeader{Height: 12345},
		},
		MinerData: &tari_generated.MinerData{TargetDifficulty: 1000},
	}

	job1, err := tariJobFromResult(result, poolpb.Algo_ALGO_SHA3X)
	if err != nil {
		t.Fatalf("tariJobFromResult (1st call): %v", err)
	}
	job2, err := tariJobFromResult(result, poolpb.Algo_ALGO_SHA3X)
	if err != nil {
		t.Fatalf("tariJobFromResult (2nd call): %v", err)
	}

	if !bytes.Equal(job1.BlockHash, job2.BlockHash) {
		t.Fatalf("test premise violated: job1.BlockHash != job2.BlockHash")
	}
	if job1.Height != job2.Height {
		t.Fatalf("test premise violated: job1.Height != job2.Height")
	}
	if job1.ID == job2.ID {
		t.Fatalf("job1.ID == job2.ID (%q) for two tariJobFromResult calls with byte-identical BlockHash/Height -- job_id must be a purely random, opaque token, never content-derived", job1.ID)
	}
	if job1.ID == "" || job2.ID == "" {
		t.Fatalf("job1.ID=%q job2.ID=%q -- job.ID must never be empty", job1.ID, job2.ID)
	}
}
