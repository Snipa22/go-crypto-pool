// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bytes"
	"context"
	"testing"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestMoneroNodeClient_RelayTemplateRoundTrip is the primary
// regression test for this fix: a real *Job produced by
// GetBlockTemplate (against a mocked monerod, via
// mockGetBlockTemplateServer -- the same real fixture blob every
// other GetBlockTemplate test in this file uses) is serialized via
// TemplateBytesForRelay and reconstructed via JobFromTemplateBytes on
// a DIFFERENT MoneroNodeClient instance (simulating a genuinely
// separate leaf-direct-Monero process receiving a sibling's relayed
// template over NATS), with no local get_block_template round-trip on
// the receiving side at all.
//
// Both clients are pinned to the SAME instanceID (via SetInstanceID)
// here specifically so that this test's own field-by-field
// byte-equality assertions below stay meaningful for every field
// OTHER than the instance-ID stamp itself -- the instance-ID stamp's
// own "two different instances diverge" behavior is this fix's
// entire point, and is covered by its own dedicated test,
// TestMoneroNodeClient_JobFromTemplateBytes_StampsDistinctInstanceIDs,
// below.
func TestMoneroNodeClient_RelayTemplateRoundTrip(t *testing.T) {
	const reservedOffset = 10 // 10+12=22 <= 76 (the fixture's real length) -- reservation usable.
	srv := mockGetBlockTemplateServer(t, reservedOffset)
	defer srv.Close()

	sameInstanceID := [4]byte{0x99, 0x88, 0x77, 0x66}

	sendingClient := NewMoneroNodeClient(srv.URL)
	sendingClient.SetInstanceID(sameInstanceID)
	originalJob, err := sendingClient.GetBlockTemplate(context.Background(), syntheticTestnetAddress, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("GetBlockTemplate (sending side): %v", err)
	}

	relayBytes, err := sendingClient.TemplateBytesForRelay(originalJob)
	if err != nil {
		t.Fatalf("TemplateBytesForRelay: %v", err)
	}
	if len(relayBytes) == 0 {
		t.Fatal("TemplateBytesForRelay returned empty bytes for a real, populated job")
	}

	// A genuinely different MoneroNodeClient instance -- no shared
	// state, no baseURL even configured -- simulating a sibling
	// leaf-direct-Monero process. JobFromTemplateBytes must not need
	// any local RPC connection at all to reconstruct the job. Pinned
	// to the SAME instanceID as sendingClient (see doc comment above)
	// so this test's byte-equality assertions below aren't
	// conflated with the (separately tested) instance-ID divergence
	// behavior.
	receivingClient := &MoneroNodeClient{}
	receivingClient.SetInstanceID(sameInstanceID)
	reconstructedJob, err := receivingClient.JobFromTemplateBytes(relayBytes, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("JobFromTemplateBytes: %v", err)
	}
	if reconstructedJob == nil {
		t.Fatal("JobFromTemplateBytes returned a nil job with a nil error")
	}

	if reconstructedJob.Height != originalJob.Height {
		t.Errorf("reconstructed Height = %d, want %d", reconstructedJob.Height, originalJob.Height)
	}
	if !bytes.Equal(reconstructedJob.Header, originalJob.Header) {
		t.Errorf("reconstructed Header = %x, want %x", reconstructedJob.Header, originalJob.Header)
	}
	if !bytes.Equal(reconstructedJob.BlockHash, originalJob.BlockHash) {
		t.Errorf("reconstructed BlockHash = %x, want %x", reconstructedJob.BlockHash, originalJob.BlockHash)
	}
	if reconstructedJob.NetworkTargetDifficulty != originalJob.NetworkTargetDifficulty {
		t.Errorf("reconstructed NetworkTargetDifficulty = %d, want %d", reconstructedJob.NetworkTargetDifficulty, originalJob.NetworkTargetDifficulty)
	}
	if !bytes.Equal(reconstructedJob.VmKey, originalJob.VmKey) {
		t.Errorf("reconstructed VmKey = %x, want %x", reconstructedJob.VmKey, originalJob.VmKey)
	}
	if reconstructedJob.ReservedOffset != originalJob.ReservedOffset {
		t.Errorf("reconstructed ReservedOffset = %d, want %d", reconstructedJob.ReservedOffset, originalJob.ReservedOffset)
	}
	if reconstructedJob.ReservedOffsetUsable != originalJob.ReservedOffsetUsable {
		t.Errorf("reconstructed ReservedOffsetUsable = %v, want %v", reconstructedJob.ReservedOffsetUsable, originalJob.ReservedOffsetUsable)
	}
	if !bytes.Equal(reconstructedJob.RawTemplateBlob, originalJob.RawTemplateBlob) {
		t.Errorf("reconstructed RawTemplateBlob = %x, want %x", reconstructedJob.RawTemplateBlob, originalJob.RawTemplateBlob)
	}
	if reconstructedJob.Algo != poolpb.Algo_ALGO_RXM {
		t.Errorf("reconstructed Algo = %v, want ALGO_RXM", reconstructedJob.Algo)
	}

	// The specific anti-pattern the "never derive ID from content"
	// rule exists to catch: a relay-adopted job's ID must be freshly
	// random, NEVER equal to the sending job's own ID (even though
	// every other field above legitimately matches).
	if reconstructedJob.ID == originalJob.ID {
		t.Fatalf("reconstructed job.ID (%q) == original job.ID -- job IDs must never be propagated/derived across the relay boundary, only freshly randomized", reconstructedJob.ID)
	}
	if reconstructedJob.ID == "" {
		t.Fatal("reconstructed job.ID is empty")
	}

	// TemplateData must be a genuinely usable, independent
	// *moneroTemplateData (e.g. for a subsequent BuildCandidateBlock
	// call on the receiving side), not a reused pointer into the
	// sending side's own job.
	reconstructedData, ok := reconstructedJob.TemplateData.(*moneroTemplateData)
	if !ok || reconstructedData == nil {
		t.Fatalf("reconstructed job.TemplateData is not a populated *moneroTemplateData (got %T)", reconstructedJob.TemplateData)
	}
	originalData := originalJob.TemplateData.(*moneroTemplateData)
	if reconstructedData.NonceOffset != originalData.NonceOffset {
		t.Errorf("reconstructed NonceOffset = %d, want %d (re-derived, should still match the same real blob's own nonce offset)", reconstructedData.NonceOffset, originalData.NonceOffset)
	}
}

// TestMoneroNodeClient_JobFromTemplateBytes_MalformedBytes confirms
// that malformed/truncated/garbage relay bytes produce a real error,
// never a corrupted Job -- covering several distinct failure shapes:
// invalid JSON, a well-formed-JSON-but-empty payload, and a
// structurally-truncated blob (nonce offset walks off the end).
func TestMoneroNodeClient_JobFromTemplateBytes_MalformedBytes(t *testing.T) {
	client := &MoneroNodeClient{}

	t.Run("not valid JSON", func(t *testing.T) {
		job, err := client.JobFromTemplateBytes([]byte("this is not json"), poolpb.Algo_ALGO_RXM)
		if err == nil {
			t.Fatal("expected an error for non-JSON relay bytes")
		}
		if job != nil {
			t.Fatalf("expected a nil job alongside an error, got %+v", job)
		}
	})

	t.Run("empty JSON object (missing blobs)", func(t *testing.T) {
		job, err := client.JobFromTemplateBytes([]byte("{}"), poolpb.Algo_ALGO_RXM)
		if err == nil {
			t.Fatal("expected an error for a relay payload missing hashing_blob/template_blob")
		}
		if job != nil {
			t.Fatalf("expected a nil job alongside an error, got %+v", job)
		}
	})

	t.Run("truncated blob (nonce offset walks off the end)", func(t *testing.T) {
		// A valid-JSON, non-empty payload whose "blobs" are far too
		// short for parseMoneroBlockHeaderNonceOffset to walk past
		// major_version/minor_version/timestamp/prev_id.
		short := `{"hashing_blob":"AQID","template_blob":"AQID"}`
		job, err := client.JobFromTemplateBytes([]byte(short), poolpb.Algo_ALGO_RXM)
		if err == nil {
			t.Fatal("expected an error for a structurally truncated relayed blob")
		}
		if job != nil {
			t.Fatalf("expected a nil job alongside an error, got %+v", job)
		}
	})
}

// TestMoneroNodeClient_TemplateBytesForRelay_NeverErrorsOnBenignInputs
// confirms TemplateBytesForRelay's documented "never an error, only
// (nil, nil)" contract for a nil job and for a job whose TemplateData
// isn't a *moneroTemplateData at all (a nil interface, or a
// Tari-shaped TemplateData by mistake).
func TestMoneroNodeClient_TemplateBytesForRelay_NeverErrorsOnBenignInputs(t *testing.T) {
	client := &MoneroNodeClient{}

	t.Run("nil job", func(t *testing.T) {
		data, err := client.TemplateBytesForRelay(nil)
		if err != nil {
			t.Fatalf("expected a nil error for a nil job, got %v", err)
		}
		if data != nil {
			t.Fatalf("expected nil data for a nil job, got %x", data)
		}
	})

	t.Run("nil TemplateData", func(t *testing.T) {
		data, err := client.TemplateBytesForRelay(&Job{Algo: poolpb.Algo_ALGO_RXM})
		if err != nil {
			t.Fatalf("expected a nil error for a job with nil TemplateData, got %v", err)
		}
		if data != nil {
			t.Fatalf("expected nil data for a job with nil TemplateData, got %x", data)
		}
	})

	t.Run("wrong-coin TemplateData (Tari-shaped, by mistake)", func(t *testing.T) {
		// Any non-*moneroTemplateData value is sufficient to exercise
		// the type-assertion failure branch -- a plain string stands
		// in for "some other coin's real TemplateData type" without
		// this test needing to import the Tari-generated package.
		data, err := client.TemplateBytesForRelay(&Job{Algo: poolpb.Algo_ALGO_RXM, TemplateData: "not-a-moneroTemplateData"})
		if err != nil {
			t.Fatalf("expected a nil error for mismatched TemplateData, got %v", err)
		}
		if data != nil {
			t.Fatalf("expected nil data for mismatched TemplateData, got %x", data)
		}
	})
}

// TestMoneroNodeClient_JobFromTemplateBytes_StampsDistinctInstanceIDs
// is the relay-adoption counterpart to
// TestMoneroNodeClient_GetBlockTemplate_StampsDistinctInstanceIDs
// (monero_node_test.go) and the SECOND direct regression test required
// by this fix: one MoneroNodeClient produces TemplateBytesForRelay
// output from a real GetBlockTemplate job, and TWO DIFFERENT
// RECEIVING MoneroNodeClient instances (different instance IDs,
// injected via SetInstanceID) call JobFromTemplateBytes on the
// IDENTICAL wire bytes. Their two resulting jobs' RawTemplateBlobs
// must differ at exactly ReservedOffset+4:ReservedOffset+8 -- proving
// that adopting a sibling's relayed template still yields a
// genuinely distinct coinbase per receiving leaf, and that neither
// receiver's stamp is merely inherited from (or left as) the
// ORIGINATING leaf's own instance ID.
func TestMoneroNodeClient_JobFromTemplateBytes_StampsDistinctInstanceIDs(t *testing.T) {
	const reservedOffset = 10 // 10+12=22 <= 76 (fixture length) -- reservation usable.
	srv := mockGetBlockTemplateServer(t, reservedOffset)
	defer srv.Close()

	sendingClient := NewMoneroNodeClient(srv.URL)
	sendingClient.SetInstanceID([4]byte{0x01, 0x02, 0x03, 0x04})
	originalJob, err := sendingClient.GetBlockTemplate(context.Background(), syntheticTestnetAddress, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("GetBlockTemplate (sending side): %v", err)
	}
	relayBytes, err := sendingClient.TemplateBytesForRelay(originalJob)
	if err != nil {
		t.Fatalf("TemplateBytesForRelay: %v", err)
	}

	receiver1 := &MoneroNodeClient{}
	receiver1.SetInstanceID([4]byte{0x11, 0x22, 0x33, 0x44})
	receiver2 := &MoneroNodeClient{}
	receiver2.SetInstanceID([4]byte{0xAA, 0xBB, 0xCC, 0xDD})

	job1, err := receiver1.JobFromTemplateBytes(relayBytes, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("JobFromTemplateBytes (receiver1): %v", err)
	}
	job2, err := receiver2.JobFromTemplateBytes(relayBytes, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("JobFromTemplateBytes (receiver2): %v", err)
	}

	if !job1.ReservedOffsetUsable || !job2.ReservedOffsetUsable {
		t.Fatalf("test premise violated: reservation must be usable for this offset (job1=%v job2=%v)", job1.ReservedOffsetUsable, job2.ReservedOffsetUsable)
	}

	stampStart := reservedOffset + 4
	stampEnd := reservedOffset + 8

	blob1 := job1.RawTemplateBlob
	blob2 := job2.RawTemplateBlob

	if !bytes.Equal(blob1[stampStart:stampEnd], receiver1.instanceID[:]) {
		t.Fatalf("job1 (receiver1) stamped bytes = %x, want receiver1's own instanceID %x", blob1[stampStart:stampEnd], receiver1.instanceID[:])
	}
	if !bytes.Equal(blob2[stampStart:stampEnd], receiver2.instanceID[:]) {
		t.Fatalf("job2 (receiver2) stamped bytes = %x, want receiver2's own instanceID %x", blob2[stampStart:stampEnd], receiver2.instanceID[:])
	}
	if bytes.Equal(blob1[stampStart:stampEnd], blob2[stampStart:stampEnd]) {
		t.Fatalf("both receivers adopting the IDENTICAL relayed template bytes produced the SAME stamped instance-ID bytes (%x) -- two different leaves adopting the identical relayed template bytes must still end up serving DISTINCT coinbases", blob1[stampStart:stampEnd])
	}
	// The receiver must stamp its OWN instance ID, never merely leave
	// (or inherit) the ORIGINATING leaf's own instance ID.
	if bytes.Equal(blob1[stampStart:stampEnd], sendingClient.instanceID[:]) {
		t.Fatalf("receiver1's stamped bytes still equal the ORIGINATING leaf's instance ID (%x) -- the receiving leaf must stamp its OWN instance ID on top before dispatch, not inherit the sender's", sendingClient.instanceID[:])
	}
	if bytes.Equal(blob2[stampStart:stampEnd], sendingClient.instanceID[:]) {
		t.Fatalf("receiver2's stamped bytes still equal the ORIGINATING leaf's instance ID (%x) -- the receiving leaf must stamp its OWN instance ID on top before dispatch, not inherit the sender's", sendingClient.instanceID[:])
	}

	if !bytes.Equal(blob1[:stampStart], blob2[:stampStart]) {
		t.Fatalf("bytes before the instance-ID stamp differ between the two receivers' jobs:\n job1=%x\n job2=%x", blob1[:stampStart], blob2[:stampStart])
	}
	if !bytes.Equal(blob1[stampEnd:], blob2[stampEnd:]) {
		t.Fatalf("bytes after the instance-ID stamp differ between the two receivers' jobs:\n job1=%x\n job2=%x", blob1[stampEnd:], blob2[stampEnd:])
	}
}

// TestMoneroNodeClient_JobFromTemplateBytes_RejectsNonMoneroFamilyAlgo
// confirms JobFromTemplateBytes mirrors GetBlockTemplate's own algo
// guard: a non-Monero-family algo must be rejected outright, even
// with an otherwise well-formed relay payload.
func TestMoneroNodeClient_JobFromTemplateBytes_RejectsNonMoneroFamilyAlgo(t *testing.T) {
	const reservedOffset = 10
	srv := mockGetBlockTemplateServer(t, reservedOffset)
	defer srv.Close()

	sendingClient := NewMoneroNodeClient(srv.URL)
	job, err := sendingClient.GetBlockTemplate(context.Background(), syntheticTestnetAddress, poolpb.Algo_ALGO_RXM)
	if err != nil {
		t.Fatalf("GetBlockTemplate: %v", err)
	}
	relayBytes, err := sendingClient.TemplateBytesForRelay(job)
	if err != nil {
		t.Fatalf("TemplateBytesForRelay: %v", err)
	}

	receivingClient := &MoneroNodeClient{}
	for _, algo := range []poolpb.Algo{poolpb.Algo_ALGO_RXT, poolpb.Algo_ALGO_SHA3X, poolpb.Algo_ALGO_C29, poolpb.Algo_ALGO_UNSPECIFIED} {
		if IsMoneroFamilyAlgo(algo) {
			t.Fatalf("test premise violated: %v is considered Monero-family", algo)
		}
		if _, err := receivingClient.JobFromTemplateBytes(relayBytes, algo); err == nil {
			t.Fatalf("JobFromTemplateBytes(algo=%v) succeeded, want an error (not a Monero-family algo)", algo)
		}
	}
}
