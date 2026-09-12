// Copyright and license: see repository LICENSE (MIT).
package chain

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeTariRPC is an in-memory tariNodeRPC test double.
type fakeTariRPC struct {
	header     *tari_generated.BlockHeaderResponse
	headerErr  error
	blocksByHt map[uint64][]*tari_generated.Block
	blocksErr  error
	gotHash    []byte
	gotHeights []uint64
}

func (f *fakeTariRPC) GetHeaderByHash(hash []byte) (*tari_generated.BlockHeaderResponse, error) {
	f.gotHash = hash
	if f.headerErr != nil {
		return nil, f.headerErr
	}
	return f.header, nil
}

func (f *fakeTariRPC) GetBlockByHeight(heights []uint64) ([]*tari_generated.Block, error) {
	f.gotHeights = heights
	if f.blocksErr != nil {
		return nil, f.blocksErr
	}
	if len(heights) != 1 {
		return nil, errors.New("fakeTariRPC only supports single-height lookups")
	}
	return f.blocksByHt[heights[0]], nil
}

func blockWithHash(hashHex string) *tari_generated.Block {
	h, _ := hex.DecodeString(hashHex)
	return &tari_generated.Block{Header: &tari_generated.BlockHeader{Hash: h}}
}

func TestTariVerifier_CanonicalAndConfirmed(t *testing.T) {
	hashHex := "aabbccdd"
	hashBytes, _ := hex.DecodeString(hashHex)
	rpc := &fakeTariRPC{
		header: &tari_generated.BlockHeaderResponse{
			Header:        &tari_generated.BlockHeader{Hash: hashBytes, Height: 100},
			Confirmations: 12,
			Reward:        60000000,
		},
		blocksByHt: map[uint64][]*tari_generated.Block{100: {blockWithHash(hashHex)}},
	}
	v := newTariVerifierWithRPC(rpc)

	got, err := v.Verify(context.Background(), hashHex, 100)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !got.Found || got.Orphaned {
		t.Fatalf("Verify: got Found=%v Orphaned=%v, want Found=true Orphaned=false", got.Found, got.Orphaned)
	}
	if got.Confirmations != 12 {
		t.Fatalf("Verify: got Confirmations=%d, want 12", got.Confirmations)
	}
	if got.Reward != 60000000 {
		t.Fatalf("Verify: got Reward=%d, want 60000000 (from the real BlockHeaderResponse.Reward field, the SAME real GetHeaderByHash call already made for hash/confirmation checking -- no extra RPC)", got.Reward)
	}
	if hex.EncodeToString(rpc.gotHash) != hashHex {
		t.Fatalf("Verify: GetHeaderByHash called with hash %x, want %s", rpc.gotHash, hashHex)
	}
}

func TestTariVerifier_Orphaned(t *testing.T) {
	submittedHash := "aabbccdd"
	canonicalHash := "11223344"
	hashBytes, _ := hex.DecodeString(submittedHash)
	rpc := &fakeTariRPC{
		header: &tari_generated.BlockHeaderResponse{
			Header:        &tari_generated.BlockHeader{Hash: hashBytes, Height: 100},
			Confirmations: 3,
		},
		blocksByHt: map[uint64][]*tari_generated.Block{100: {blockWithHash(canonicalHash)}},
	}
	v := newTariVerifierWithRPC(rpc)

	got, err := v.Verify(context.Background(), submittedHash, 100)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if !got.Found || !got.Orphaned {
		t.Fatalf("Verify: got Found=%v Orphaned=%v, want Found=true Orphaned=true", got.Found, got.Orphaned)
	}
	if got.CanonicalHash != canonicalHash {
		t.Fatalf("Verify: got CanonicalHash=%s, want %s", got.CanonicalHash, canonicalHash)
	}
}

func TestTariVerifier_NotFound(t *testing.T) {
	rpc := &fakeTariRPC{headerErr: status.Error(codes.NotFound, "no such header")}
	v := newTariVerifierWithRPC(rpc)

	got, err := v.Verify(context.Background(), "aabbccdd", 100)
	if err != nil {
		t.Fatalf("Verify: unexpected error: %v", err)
	}
	if got.Found {
		t.Fatalf("Verify: got Found=true, want false for a not-found header")
	}
}

func TestTariVerifier_OtherRPCErrorPropagates(t *testing.T) {
	rpc := &fakeTariRPC{headerErr: status.Error(codes.Unavailable, "base node unreachable")}
	v := newTariVerifierWithRPC(rpc)

	_, err := v.Verify(context.Background(), "aabbccdd", 100)
	if err == nil {
		t.Fatal("Verify: expected an error for a non-NotFound RPC failure, got nil")
	}
}

func TestTariVerifier_HeightMismatchIsAnError(t *testing.T) {
	hashHex := "aabbccdd"
	hashBytes, _ := hex.DecodeString(hashHex)
	rpc := &fakeTariRPC{
		header: &tari_generated.BlockHeaderResponse{
			Header: &tari_generated.BlockHeader{Hash: hashBytes, Height: 200},
		},
	}
	v := newTariVerifierWithRPC(rpc)

	_, err := v.Verify(context.Background(), hashHex, 100)
	if err == nil {
		t.Fatal("Verify: expected an error when the returned header's height does not match the submitted height")
	}
}

func TestTariVerifier_InvalidHex(t *testing.T) {
	v := newTariVerifierWithRPC(&fakeTariRPC{})
	if _, err := v.Verify(context.Background(), "not-hex", 1); err == nil {
		t.Fatal("Verify: expected an error for non-hex hash input")
	}
}

func TestTariVerifier_NegativeHeight(t *testing.T) {
	v := newTariVerifierWithRPC(&fakeTariRPC{})
	if _, err := v.Verify(context.Background(), "aabbccdd", -1); err == nil {
		t.Fatal("Verify: expected an error for a negative height")
	}
}

// blockingTariRPC is a tariNodeRPC whose GetHeaderByHash blocks until
// release is closed -- simulating a hung base node with no way to
// cancel the underlying call (exactly the real go-tari-grpc-lib/v3
// nodeGRPC package's own constraint, see Verify's doc comment).
type blockingTariRPC struct {
	release chan struct{}
}

func (f *blockingTariRPC) GetHeaderByHash(hash []byte) (*tari_generated.BlockHeaderResponse, error) {
	<-f.release
	return nil, errors.New("blockingTariRPC: released after the test observed the timeout")
}

func (f *blockingTariRPC) GetBlockByHeight(heights []uint64) ([]*tari_generated.Block, error) {
	<-f.release
	return nil, errors.New("blockingTariRPC: released after the test observed the timeout")
}

// TestTariVerifier_CtxCancellationBoundsCallerWait is the regression
// test for PROD_HARDENING_REVIEW.md finding #20's TariVerifier.Verify
// item: a canceled/timed-out ctx must unblock Verify's CALLER
// promptly, even though the underlying nodeGRPC call it raced against
// cannot itself be canceled and keeps running in the background (see
// callWithContext's own doc comment).
func TestTariVerifier_CtxCancellationBoundsCallerWait(t *testing.T) {
	rpc := &blockingTariRPC{release: make(chan struct{})}
	defer close(rpc.release) // let the leaked goroutine finish so the test doesn't leave anything running after it returns
	v := newTariVerifierWithRPC(rpc)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := v.Verify(ctx, "aabbccdd", 100)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Verify: expected an error when ctx is canceled while the underlying RPC is still blocked")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify: got error %v, want one wrapping context.DeadlineExceeded", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Verify: took %s to return after a 20ms ctx timeout against a permanently-blocked RPC -- ctx cancellation did not bound the caller's wait", elapsed)
	}
}
