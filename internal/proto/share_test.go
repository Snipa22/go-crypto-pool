package poolpb

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestShareRoundTrip verifies marshal/unmarshal for Share with the
// RandomX raw_proof oneof variant populated (covers RXT/RXM proof
// shape).
func TestShareRoundTrip(t *testing.T) {
	want := &Share{
		Algo:           Algo_ALGO_RXT,
		Network:        Network_NETWORK_TESTNET,
		Shares:         int64(1),
		PaymentAddress: "tari1qexampleaddress",
		FoundBlock:     true,
		PaymentId:      proto.String("optional-payment-id"),
		PoolType:       PoolType_POOL_TYPE_PPLNS,
		PoolId:         7,
		BlockDiff:      123456789,
		BlockHeight:    9223372036,
		Timestamp:      1700000000,
		Identifier:     "worker-01",
		RawProof: &Share_RandomxProof{
			RandomxProof: &RandomXProof{
				Blob:      []byte{0x01, 0x02, 0x03},
				SeedHash:  []byte{0xAA, 0xBB},
				ResultHex: "deadbeef",
			},
		},
		TrustedShare: true,
	}

	data, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got := &Share{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(want, got) {
		t.Fatalf("round-trip mismatch:\nwant=%v\ngot=%v", want, got)
	}

	rx := got.GetRandomxProof()
	if rx == nil {
		t.Fatal("expected RandomxProof oneof variant to survive round-trip")
	}
	if rx.GetResultHex() != "deadbeef" {
		t.Fatalf("ResultHex = %q, want %q", rx.GetResultHex(), "deadbeef")
	}
	if got.GetBlockHeight() != 9223372036 {
		t.Fatalf("BlockHeight = %d, want a value that would overflow int32", got.GetBlockHeight())
	}
	if !got.GetTrustedShare() {
		t.Fatal("expected TrustedShare to survive round-trip as true")
	}
}

// TestBlockRoundTrip verifies marshal/unmarshal for Block, including the
// optional value field.
func TestBlockRoundTrip(t *testing.T) {
	want := &Block{
		Algo:       Algo_ALGO_SHA3X,
		Network:    Network_NETWORK_MAINNET,
		Hash:       "0xabc123",
		Difficulty: 1_000_000,
		Shares:     42,
		Timestamp:  1700000001,
		PoolType:   PoolType_POOL_TYPE_SOLO,
		Unlocked:   false,
		Valid:      true,
		Value:      proto.Int64(5_000_000_000),
		Height:     3_000_000_001,
	}

	data, err := proto.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	got := &Block{}
	if err := proto.Unmarshal(data, got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(want, got) {
		t.Fatalf("round-trip mismatch:\nwant=%v\ngot=%v", want, got)
	}
	if got.GetValue() != 5_000_000_000 {
		t.Fatalf("Value = %d, want 5000000000", got.GetValue())
	}
}

// TestShareRawProofVariants checks each oneof variant can be set and
// retrieved independently (C29 and SHA3X, in addition to RandomX above).
func TestShareRawProofVariants(t *testing.T) {
	c29 := &Share{
		Algo:    Algo_ALGO_C29,
		Network: Network_NETWORK_MAINNET,
		RawProof: &Share_C29Proof{
			C29Proof: &C29Proof{
				EdgeBits: 29,
				Cycle:    []uint64{1, 2, 3, 4, 5},
			},
		},
		TrustedShare: false,
	}
	data, err := proto.Marshal(c29)
	if err != nil {
		t.Fatalf("Marshal C29: %v", err)
	}
	gotC29 := &Share{}
	if err := proto.Unmarshal(data, gotC29); err != nil {
		t.Fatalf("Unmarshal C29: %v", err)
	}
	if gotC29.GetC29Proof() == nil || len(gotC29.GetC29Proof().GetCycle()) != 5 {
		t.Fatalf("C29 proof did not round-trip: %v", gotC29.GetC29Proof())
	}
	if gotC29.GetTrustedShare() {
		t.Fatal("expected TrustedShare to round-trip as false for C29 variant")
	}

	sha3x := &Share{
		Algo:    Algo_ALGO_SHA3X,
		Network: Network_NETWORK_TESTNET,
		RawProof: &Share_Sha3XProof{
			Sha3XProof: &SHA3XProof{
				Header: []byte{0x01},
				Nonce:  99,
			},
		},
		TrustedShare: true,
	}
	data, err = proto.Marshal(sha3x)
	if err != nil {
		t.Fatalf("Marshal SHA3X: %v", err)
	}
	gotSHA3X := &Share{}
	if err := proto.Unmarshal(data, gotSHA3X); err != nil {
		t.Fatalf("Unmarshal SHA3X: %v", err)
	}
	if gotSHA3X.GetSha3XProof() == nil || gotSHA3X.GetSha3XProof().GetNonce() != 99 {
		t.Fatalf("SHA3X proof did not round-trip: %v", gotSHA3X.GetSha3XProof())
	}
	if !gotSHA3X.GetTrustedShare() {
		t.Fatal("expected TrustedShare to round-trip as true for SHA3X variant")
	}
}
