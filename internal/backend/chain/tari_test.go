// Copyright and license: see repository LICENSE (MIT).
package chain

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

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
