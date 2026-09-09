// Copyright and license: see repository LICENSE (MIT).
package legacypb

import (
	"testing"

	"google.golang.org/protobuf/proto"
)

// TestShareRoundTrip_AllFieldsSet proves the hand-written proto2 Share
// schema (modeled byte-for-byte on the real nodejs-pool data.proto --
// see legacy.proto's header doc comment) round-trips correctly with
// every field populated, including the optional paymentID.
func TestShareRoundTrip_AllFieldsSet(t *testing.T) {
	original := &Share{
		Shares:         proto.Int32(42),
		PaymentAddress: proto.String("addr-1"),
		FoundBlock:     proto.Bool(true),
		PaymentID:      proto.String("pid-1"),
		TrustedShare:   proto.Bool(true),
		PoolType:       POOLTYPE_PPLNS.Enum(),
		PoolID:         proto.Int32(7),
		BlockDiff:      proto.Int64(123456789),
		Bitcoin:        proto.Bool(false),
		BlockHeight:    proto.Int32(999999),
		Timestamp:      proto.Int64(1700000000),
		Identifier:     proto.String("worker-1"),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &Share{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}

	// Spot-check every field value individually too, not just proto.Equal,
	// per the brief's "value-for-value" requirement.
	if decoded.GetShares() != 42 {
		t.Errorf("Shares = %d, want 42", decoded.GetShares())
	}
	if decoded.GetPaymentAddress() != "addr-1" {
		t.Errorf("PaymentAddress = %q, want %q", decoded.GetPaymentAddress(), "addr-1")
	}
	if !decoded.GetFoundBlock() {
		t.Errorf("FoundBlock = false, want true")
	}
	if decoded.GetPaymentID() != "pid-1" {
		t.Errorf("PaymentID = %q, want %q", decoded.GetPaymentID(), "pid-1")
	}
	if !decoded.GetTrustedShare() {
		t.Errorf("TrustedShare = false, want true")
	}
	if decoded.GetPoolType() != POOLTYPE_PPLNS {
		t.Errorf("PoolType = %v, want PPLNS", decoded.GetPoolType())
	}
	if decoded.GetPoolID() != 7 {
		t.Errorf("PoolID = %d, want 7", decoded.GetPoolID())
	}
	if decoded.GetBlockDiff() != 123456789 {
		t.Errorf("BlockDiff = %d, want 123456789", decoded.GetBlockDiff())
	}
	if decoded.GetBitcoin() != false {
		t.Errorf("Bitcoin = %v, want false", decoded.GetBitcoin())
	}
	if decoded.GetBlockHeight() != 999999 {
		t.Errorf("BlockHeight = %d, want 999999", decoded.GetBlockHeight())
	}
	if decoded.GetTimestamp() != 1700000000 {
		t.Errorf("Timestamp = %d, want 1700000000", decoded.GetTimestamp())
	}
	if decoded.GetIdentifier() != "worker-1" {
		t.Errorf("Identifier = %q, want %q", decoded.GetIdentifier(), "worker-1")
	}
}

// TestShareRoundTrip_OptionalPaymentIDUnset proves the optional
// paymentID field round-trips correctly when left unset (proto2
// distinguishes "unset" from "empty string" via HasPaymentID/pointer
// nil-ness).
func TestShareRoundTrip_OptionalPaymentIDUnset(t *testing.T) {
	original := &Share{
		Shares:         proto.Int32(1),
		PaymentAddress: proto.String("addr-2"),
		FoundBlock:     proto.Bool(false),
		TrustedShare:   proto.Bool(false),
		PoolType:       POOLTYPE_SOLO.Enum(),
		PoolID:         proto.Int32(1),
		BlockDiff:      proto.Int64(1),
		Bitcoin:        proto.Bool(false),
		BlockHeight:    proto.Int32(1),
		Timestamp:      proto.Int64(1),
		Identifier:     proto.String("worker-2"),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &Share{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}
	if decoded.PaymentID != nil {
		t.Errorf("PaymentID = %v, want nil (unset)", decoded.PaymentID)
	}
}

// TestBlockRoundTrip_AllFieldsSet covers Block with the optional
// value field set.
func TestBlockRoundTrip_AllFieldsSet(t *testing.T) {
	original := &Block{
		Hash:       proto.String("0xdeadbeef"),
		Difficulty: proto.Int64(5000000),
		Shares:     proto.Int64(12345),
		Timestamp:  proto.Int64(1700000001),
		PoolType:   POOLTYPE_PPS.Enum(),
		Unlocked:   proto.Bool(true),
		Valid:      proto.Bool(true),
		Value:      proto.Int64(987654321),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &Block{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}
	if decoded.GetValue() != 987654321 {
		t.Errorf("Value = %d, want 987654321", decoded.GetValue())
	}
}

// TestBlockRoundTrip_OptionalValueUnset covers Block with the optional
// value field left unset.
func TestBlockRoundTrip_OptionalValueUnset(t *testing.T) {
	original := &Block{
		Hash:       proto.String("0xcafef00d"),
		Difficulty: proto.Int64(1),
		Shares:     proto.Int64(1),
		Timestamp:  proto.Int64(1),
		PoolType:   POOLTYPE_PROP.Enum(),
		Unlocked:   proto.Bool(false),
		Valid:      proto.Bool(false),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &Block{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}
	if decoded.Value != nil {
		t.Errorf("Value = %v, want nil (unset)", decoded.Value)
	}
}

// TestWSDataRoundTrip_ShareEnvelope proves WSData round-trips
// correctly wrapping a marshaled Share, for msgType=SHARE.
func TestWSDataRoundTrip_ShareEnvelope(t *testing.T) {
	innerShare := &Share{
		Shares:         proto.Int32(10),
		PaymentAddress: proto.String("addr-3"),
		FoundBlock:     proto.Bool(true),
		TrustedShare:   proto.Bool(true),
		PoolType:       POOLTYPE_PPLNS.Enum(),
		PoolID:         proto.Int32(2),
		BlockDiff:      proto.Int64(2),
		Bitcoin:        proto.Bool(false),
		BlockHeight:    proto.Int32(2),
		Timestamp:      proto.Int64(2),
		Identifier:     proto.String("worker-3"),
	}
	innerData, err := proto.Marshal(innerShare)
	if err != nil {
		t.Fatalf("Marshal inner Share: %v", err)
	}

	original := &WSData{
		MsgType: MESSAGETYPE_SHARE.Enum(),
		Key:     proto.String("secret-key"),
		Msg:     innerData,
		ExInt:   proto.Int32(0),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal WSData: %v", err)
	}

	decoded := &WSData{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal WSData: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}
	if decoded.GetMsgType() != MESSAGETYPE_SHARE {
		t.Errorf("MsgType = %v, want SHARE", decoded.GetMsgType())
	}
	if decoded.GetKey() != "secret-key" {
		t.Errorf("Key = %q, want %q", decoded.GetKey(), "secret-key")
	}

	decodedInner := &Share{}
	if err := proto.Unmarshal(decoded.GetMsg(), decodedInner); err != nil {
		t.Fatalf("Unmarshal inner Share from decoded WSData.Msg: %v", err)
	}
	if !proto.Equal(innerShare, decodedInner) {
		t.Fatalf("inner Share mismatch after WSData round-trip:\nwant: %v\ngot:  %v", innerShare, decodedInner)
	}
}

// TestWSDataRoundTrip_BlockEnvelope proves WSData round-trips
// correctly wrapping a marshaled Block, for msgType=BLOCK, with a
// non-zero exInt (the real block height, per remoteShare.js forwarding
// msgData.exInt into storeBlock).
func TestWSDataRoundTrip_BlockEnvelope(t *testing.T) {
	innerBlock := &Block{
		Hash:       proto.String("0xblockhash"),
		Difficulty: proto.Int64(3),
		Shares:     proto.Int64(3),
		Timestamp:  proto.Int64(3),
		PoolType:   POOLTYPE_SOLO.Enum(),
		Unlocked:   proto.Bool(false),
		Valid:      proto.Bool(true),
	}
	innerData, err := proto.Marshal(innerBlock)
	if err != nil {
		t.Fatalf("Marshal inner Block: %v", err)
	}

	original := &WSData{
		MsgType: MESSAGETYPE_BLOCK.Enum(),
		Key:     proto.String("secret-key-2"),
		Msg:     innerData,
		ExInt:   proto.Int32(123456),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal WSData: %v", err)
	}

	decoded := &WSData{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal WSData: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}
	if decoded.GetExInt() != 123456 {
		t.Errorf("ExInt = %d, want 123456", decoded.GetExInt())
	}
}

// TestInvalidShareRoundTrip_AllFieldsSet covers InvalidShare with the
// optional paymentID set.
func TestInvalidShareRoundTrip_AllFieldsSet(t *testing.T) {
	original := &InvalidShare{
		PaymentAddress: proto.String("addr-4"),
		PaymentID:      proto.String("pid-4"),
		Identifier:     proto.String("worker-4"),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &InvalidShare{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}
}

// TestInvalidShareRoundTrip_OptionalPaymentIDUnset covers InvalidShare
// with the optional paymentID left unset.
func TestInvalidShareRoundTrip_OptionalPaymentIDUnset(t *testing.T) {
	original := &InvalidShare{
		PaymentAddress: proto.String("addr-5"),
		Identifier:     proto.String("worker-5"),
	}

	data, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	decoded := &InvalidShare{}
	if err := proto.Unmarshal(data, decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if !proto.Equal(original, decoded) {
		t.Fatalf("round-trip mismatch:\noriginal: %v\ndecoded:  %v", original, decoded)
	}
	if decoded.PaymentID != nil {
		t.Errorf("PaymentID = %v, want nil (unset)", decoded.PaymentID)
	}
}

// TestShareMarshal_MissingRequiredField_ReturnsError proves the real
// proto2 required-field constraint is enforced at marshal time (a
// genuine runtime error), not silently tolerated the way proto3 would
// tolerate an unset/zero-value field. Per the brief: this is the core
// "required fields are a real wire-encoding constraint" proof.
//
// We leave PaymentAddress (a required string field, generated as a
// *string pointer in proto2 mode) genuinely nil/unset, while every
// other required field is populated -- so if proto.Marshal succeeded
// despite this, that would indicate protobuf-go is NOT enforcing
// proto2 required-ness in this version, which would be a real,
// reportable finding contradicting our assumption. As of
// google.golang.org/protobuf v1.36.x (see legacy.pb.go's own generated
// header for the exact protoc-gen-go version this was generated
// with), it IS enforced: proto.Marshal returns a non-nil error here.
func TestShareMarshal_MissingRequiredField_ReturnsError(t *testing.T) {
	incomplete := &Share{
		Shares: proto.Int32(1),
		// PaymentAddress intentionally left nil -- required field unset.
		FoundBlock:   proto.Bool(false),
		TrustedShare: proto.Bool(false),
		PoolType:     POOLTYPE_PPLNS.Enum(),
		PoolID:       proto.Int32(1),
		BlockDiff:    proto.Int64(1),
		Bitcoin:      proto.Bool(false),
		BlockHeight:  proto.Int32(1),
		Timestamp:    proto.Int64(1),
		Identifier:   proto.String("worker-x"),
	}

	_, err := proto.Marshal(incomplete)
	if err == nil {
		t.Fatal("expected a real error marshaling a Share with a nil required PaymentAddress field, got nil -- proto2 required-field enforcement may not be active in this protobuf-go version (see this test's doc comment)")
	}
	t.Logf("confirmed real proto2 required-field enforcement at marshal time: %v", err)
}

// TestShareMarshal_AllRequiredFieldsNilExceptOne_ReturnsError is a
// second, more extreme required-field-omission case: every required
// scalar field left completely unset (a bare &Share{}), which should
// fail even harder/more obviously than the single-field-omission case
// above.
func TestShareMarshal_AllRequiredFieldsNilExceptOne_ReturnsError(t *testing.T) {
	bare := &Share{}

	_, err := proto.Marshal(bare)
	if err == nil {
		t.Fatal("expected a real error marshaling a completely bare &Share{} (all required fields nil), got nil")
	}
	t.Logf("confirmed: %v", err)
}

// TestBlockMarshal_MissingRequiredField_ReturnsError mirrors the Share
// required-field test above, for Block's required Hash field.
func TestBlockMarshal_MissingRequiredField_ReturnsError(t *testing.T) {
	incomplete := &Block{
		// Hash intentionally left nil -- required field unset.
		Difficulty: proto.Int64(1),
		Shares:     proto.Int64(1),
		Timestamp:  proto.Int64(1),
		PoolType:   POOLTYPE_PPLNS.Enum(),
		Unlocked:   proto.Bool(false),
		Valid:      proto.Bool(false),
	}

	_, err := proto.Marshal(incomplete)
	if err == nil {
		t.Fatal("expected a real error marshaling a Block with a nil required Hash field, got nil")
	}
	t.Logf("confirmed: %v", err)
}

// TestWSDataMarshal_MissingRequiredField_ReturnsError mirrors the
// above for WSData's required Key field.
func TestWSDataMarshal_MissingRequiredField_ReturnsError(t *testing.T) {
	incomplete := &WSData{
		MsgType: MESSAGETYPE_SHARE.Enum(),
		// Key intentionally left nil -- required field unset.
		Msg:   []byte{0x01},
		ExInt: proto.Int32(0),
	}

	_, err := proto.Marshal(incomplete)
	if err == nil {
		t.Fatal("expected a real error marshaling a WSData with a nil required Key field, got nil")
	}
	t.Logf("confirmed: %v", err)
}
