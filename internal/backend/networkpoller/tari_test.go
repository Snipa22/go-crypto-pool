// Copyright and license: see repository LICENSE (MIT).
package networkpoller

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeTariRPC struct {
	tip      *tari_generated.TipInfoResponse
	tipErr   error
	netState *tari_generated.GetNetworkStateResponse
	netErr   error
}

func (f *fakeTariRPC) GetTipInfo() (*tari_generated.TipInfoResponse, error) {
	if f.tipErr != nil {
		return nil, f.tipErr
	}
	return f.tip, nil
}

func (f *fakeTariRPC) GetNetworkState() (*tari_generated.GetNetworkStateResponse, error) {
	if f.netErr != nil {
		return nil, f.netErr
	}
	return f.netState, nil
}

func TestTariNetworkSource_FetchNetworkState_RandomX(t *testing.T) {
	hashBytes, _ := hex.DecodeString("deadbeef")
	rpc := &fakeTariRPC{
		tip: &tari_generated.TipInfoResponse{
			Metadata: &tari_generated.MetaData{BestBlockHeight: 5000, BestBlockHash: hashBytes},
		},
		netState: &tari_generated.GetNetworkStateResponse{
			TariRandomxEstimatedHashRate: 123456,
			Sha3XEstimatedHashRate:       999,
		},
	}
	s := newTariNetworkSourceWithRPC(rpc, TariAlgoRandomX)

	state, err := s.FetchNetworkState(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.Height != 5000 {
		t.Fatalf("height = %d, want 5000", state.Height)
	}
	if state.BestBlockHash != "deadbeef" {
		t.Fatalf("best block hash = %q, want deadbeef", state.BestBlockHash)
	}
	if state.Difficulty != nil {
		t.Fatalf("difficulty = %v, want nil (see TariNetworkSource doc comment)", state.Difficulty)
	}
	if state.EstimatedHashrateHS == nil || *state.EstimatedHashrateHS != 123456 {
		t.Fatalf("estimated hashrate = %v, want 123456 (RandomX-specific)", state.EstimatedHashrateHS)
	}
}

func TestTariNetworkSource_FetchNetworkState_SHA3X(t *testing.T) {
	rpc := &fakeTariRPC{
		tip: &tari_generated.TipInfoResponse{
			Metadata: &tari_generated.MetaData{BestBlockHeight: 10},
		},
		netState: &tari_generated.GetNetworkStateResponse{
			Sha3XEstimatedHashRate:       555,
			TariRandomxEstimatedHashRate: 777,
		},
	}
	s := newTariNetworkSourceWithRPC(rpc, TariAlgoSHA3X)

	state, err := s.FetchNetworkState(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.EstimatedHashrateHS == nil || *state.EstimatedHashrateHS != 555 {
		t.Fatalf("estimated hashrate = %v, want 555 (SHA3X-specific)", state.EstimatedHashrateHS)
	}
}

func TestTariNetworkSource_FetchNetworkState_Cuckaroo(t *testing.T) {
	rpc := &fakeTariRPC{
		tip: &tari_generated.TipInfoResponse{
			Metadata: &tari_generated.MetaData{BestBlockHeight: 10},
		},
		netState: &tari_generated.GetNetworkStateResponse{
			CuckarooEstimatedHashRate: &tari_generated.UDecimalValue{Units: 42, Nanos: 500000000},
		},
	}
	s := newTariNetworkSourceWithRPC(rpc, TariAlgoCuckaroo)

	state, err := s.FetchNetworkState(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := 42.5
	if state.EstimatedHashrateHS == nil || *state.EstimatedHashrateHS != want {
		t.Fatalf("estimated hashrate = %v, want %v", state.EstimatedHashrateHS, want)
	}
}

func TestTariNetworkSource_GetTipInfoError(t *testing.T) {
	rpc := &fakeTariRPC{tipErr: errors.New("connection refused")}
	s := newTariNetworkSourceWithRPC(rpc, TariAlgoRandomX)

	if _, err := s.FetchNetworkState(context.Background()); err == nil {
		t.Fatal("expected an error when GetTipInfo fails")
	}
}

func TestTariNetworkSource_GetNetworkStateError(t *testing.T) {
	rpc := &fakeTariRPC{
		tip:    &tari_generated.TipInfoResponse{Metadata: &tari_generated.MetaData{BestBlockHeight: 1}},
		netErr: errors.New("unavailable"),
	}
	s := newTariNetworkSourceWithRPC(rpc, TariAlgoRandomX)

	if _, err := s.FetchNetworkState(context.Background()); err == nil {
		t.Fatal("expected an error when GetNetworkState fails")
	}
}

// TestTariNetworkSource_GetNetworkStatePermissionDenied is the
// regression test for the real, live-confirmed bug: the real
// Esmeralda testnet base node returns PermissionDenied for
// GetNetworkState (its real GRPC permission scope doesn't admit that
// method), which used to fail this Source's ENTIRE fetch -- including
// the real, independently-fetched, always-available tip height/hash
// from GetTipInfo. A PermissionDenied/Unauthenticated/Unimplemented
// GetNetworkState error must degrade to a real State with a nil
// EstimatedHashrateHS instead.
func TestTariNetworkSource_GetNetworkStatePermissionDenied(t *testing.T) {
	hashBytes, _ := hex.DecodeString("deadbeef")
	for _, code := range []codes.Code{codes.PermissionDenied, codes.Unauthenticated, codes.Unimplemented} {
		t.Run(code.String(), func(t *testing.T) {
			rpc := &fakeTariRPC{
				tip: &tari_generated.TipInfoResponse{
					Metadata: &tari_generated.MetaData{BestBlockHeight: 5000, BestBlockHash: hashBytes},
				},
				netErr: status.Error(code, "method not allowed on this node"),
			}
			s := newTariNetworkSourceWithRPC(rpc, TariAlgoRandomX)

			state, err := s.FetchNetworkState(context.Background())
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if state.Height != 5000 {
				t.Fatalf("height = %d, want 5000 (real tip data must survive a forbidden GetNetworkState)", state.Height)
			}
			if state.BestBlockHash != "deadbeef" {
				t.Fatalf("best block hash = %q, want deadbeef", state.BestBlockHash)
			}
			if state.EstimatedHashrateHS != nil {
				t.Fatalf("estimated hashrate = %v, want nil when GetNetworkState is forbidden", *state.EstimatedHashrateHS)
			}
		})
	}
}

func TestTariNetworkSource_NoMetadata(t *testing.T) {
	rpc := &fakeTariRPC{tip: &tari_generated.TipInfoResponse{}}
	s := newTariNetworkSourceWithRPC(rpc, TariAlgoRandomX)

	if _, err := s.FetchNetworkState(context.Background()); err == nil {
		t.Fatal("expected an error when GetTipInfo returns no metadata")
	}
}
