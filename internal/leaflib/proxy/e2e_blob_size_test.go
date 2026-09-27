// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"encoding/hex"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// TestEndToEnd_DownstreamWireBlobNeverExceedsXMRigMaxBlobSize is
// required test 4 from the brief: table-driven over a couple of
// representative decoded blob lengths in the real 76-200 byte range
// (the RandomX/"rx/0" algo path), proving the final downstream wire
// job.blob hex field's decoded byte length is always < 408 (xmrig's
// kMaxBlobSize, src/base/net/stratum/Job.cpp) end to end from a real
// UpstreamJobPayload, through applyJob, WorkerTemplate,
// JobManager.NextJob/Job, all the way to Session.jobPayload's actual
// wire "blob" hex string.
func TestEndToEnd_DownstreamWireBlobNeverExceedsXMRigMaxBlobSize(t *testing.T) {
	const xmrigMaxBlobSize = 408

	cases := []struct {
		name       string
		blobLenHex int // decoded byte length of the upstream job.Blob field
	}{
		{name: "76-byte-blob-standard-randomx", blobLenHex: 76},
		{name: "152-byte-blob", blobLenHex: 152},
		{name: "186-byte-blob-upper-observed-range", blobLenHex: 186},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc := NewUpstreamClient(UpstreamConfig{Login: "test-address"}, discardLogger())

			blobHex := hexOfLen(tc.blobLenHex)
			seedHex := hexOfLen(32)
			uc.applyJob(UpstreamJobPayload{
				JobID:      "e2e-job",
				Blob:       blobHex,
				SeedHash:   seedHex,
				Height:     42,
				TargetDiff: 1000,
			})

			jm := NewJobManager(uc, discardLogger())
			job, err := jm.NextJob(500)
			if err != nil {
				t.Fatalf("NextJob: %v", err)
			}

			sess := &Session{
				jobs: leaflib.NewJobHistory[*Job](defaultProxySessionJobHistorySize),
			}
			payload := sess.jobPayload(job)

			decoded, err := hex.DecodeString(payload.Blob)
			if err != nil {
				t.Fatalf("decoding final wire blob hex %q: %v", payload.Blob, err)
			}
			if len(decoded) >= xmrigMaxBlobSize {
				t.Fatalf("final downstream wire job.blob decoded length = %d, want < %d (xmrig kMaxBlobSize)", len(decoded), xmrigMaxBlobSize)
			}
			if len(decoded) != tc.blobLenHex {
				t.Fatalf("final downstream wire job.blob decoded length = %d, want exactly %d (worker-nonce write must not change length)", len(decoded), tc.blobLenHex)
			}
			if payload.Algo != "rx/0" {
				t.Fatalf("payload.Algo = %q, want %q", payload.Algo, "rx/0")
			}
		})
	}
}
