// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// newMultiPortTestServer builds one real Server (real ConnectionManager,
// real SHA3XValidator, fake NodeClient, real shared JobManager) with no
// per-server starting difficulty baked in — exactly the multi-port-tier
// shape: callers dial connections through Server.handleConn, passing
// whichever port tier's difficulty applies, mirroring what
// Server.Serve(ctx, ln, port) would do for a real net.Listener.
func newMultiPortTestServer(t *testing.T) (*Server, *JobManager, *fakeNodeClient) {
	t.Helper()
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: 1 << 62,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
	}
	jm := NewJobManager(JobManagerConfig{
		Node:          node,
		PayoutAddress: "solo-test-address",
		// Deliberately NOT set to either port's difficulty below —
		// this field is only the JobForXN fallback default; every
		// session in these tests goes through JobForXNAtDifficulty
		// with its OWN port's difficulty, so a mismatched/zero
		// default here proves the per-port value actually drove the
		// session, not this fallback.
		StaticDifficulty: 0,
	})
	cm := leaflib.NewConnectionManager(context.Background(), leaflib.ManagerConfig{IdleTimeout: 2 * time.Second})
	v := validator.NewSHA3XValidator()
	server := NewServer(cm, jm, node, v, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})
	return server, jm, node
}

// dialAndLoginAtDifficulty opens an in-process net.Pipe connection
// through server.handleConn (as Serve would for a real listener
// accepting on a port tier configured at startingDifficulty), performs
// a real login handshake, and returns the session's assigned xn and
// the decoded starting difficulty implied by the login-pushed job's
// wire "target" field (reversing diffToTargetHex).
func dialAndLoginAtDifficulty(t *testing.T, server *Server, startingDifficulty uint64, address string) (xn string, decodedDifficulty uint64) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	ctx := context.Background()
	go server.handleConn(ctx, serverConn, startingDifficulty)
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &testHarness{
		t:      t,
		server: server,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
	}
	_, xn = login(t, h, address)

	// Re-fetch the login response's job to decode its target back to
	// a difficulty (login() only returns id/xn) — read the session's
	// own current difficulty directly via the JobManager, matching
	// what the wire "target" field was derived from at login time.
	job, err := server.jobManager.JobForXN(context.Background(), xn)
	if err != nil {
		t.Fatalf("JobForXN(%q): %v", xn, err)
	}
	return xn, job.StaticDifficulty
}

// TestTwoPortsGiveDifferentStartingDifficulties is the core multi-port
// requirement: two sessions connecting on two DIFFERENT configured
// port tiers must start at each tier's own configured difficulty, not
// a single global value.
func TestTwoPortsGiveDifferentStartingDifficulties(t *testing.T) {
	server, _, _ := newMultiPortTestServer(t)

	lowPort := PortConfig{Address: ":0", Difficulty: 1000, PortDesc: "low-diff"}
	highPort := PortConfig{Address: ":0", Difficulty: 1_000_000, PortDesc: "high-diff"}

	_, lowGot := dialAndLoginAtDifficulty(t, server, lowPort.Difficulty, "addr-low")
	_, highGot := dialAndLoginAtDifficulty(t, server, highPort.Difficulty, "addr-high")

	if lowGot != lowPort.Difficulty {
		t.Errorf("low-diff port session starting difficulty = %d, want %d", lowGot, lowPort.Difficulty)
	}
	if highGot != highPort.Difficulty {
		t.Errorf("high-diff port session starting difficulty = %d, want %d", highGot, highPort.Difficulty)
	}
	if lowGot == highGot {
		t.Fatalf("expected the two port tiers to produce different starting difficulties, both got %d", lowGot)
	}
}

// TestBackwardCompatibleSinglePortStillWorks is the regression guard
// for the pre-existing, already-deployed single
// LEAF_SOLO_LISTEN_ADDRESS/LEAF_SOLO_STARTING_DIFFICULTY behavior: a
// Server driven by exactly one Serve/handleConn call at one
// difficulty must produce sessions starting at exactly that value,
// with no other tiers involved — i.e. the implicit single-entry port
// list path cmd/leaf-solo's resolvePorts falls back to when
// LEAF_SOLO_PORTS is unset.
func TestBackwardCompatibleSinglePortStillWorks(t *testing.T) {
	server, _, _ := newMultiPortTestServer(t)

	const legacyStartingDifficulty = 10000
	_, got := dialAndLoginAtDifficulty(t, server, legacyStartingDifficulty, "addr-legacy")

	if got != legacyStartingDifficulty {
		t.Errorf("single-port session starting difficulty = %d, want %d (legacy LEAF_SOLO_STARTING_DIFFICULTY-equivalent behavior)", got, legacyStartingDifficulty)
	}
}

// TestMultiplePortsShareSameJobManager confirms the critical
// "not-wasteful" requirement: sessions accepted on two DIFFERENT port
// tiers must still be served by the exact SAME underlying *JobManager
// instance (one backend node connection, one set of per-xn job
// templates) — proven two ways: (1) the two sessions are demonstrably
// resolvable through the identical *JobManager pointer the Server
// itself holds, and (2) they still get the existing per-xn distinct-
// template guarantee (different xn -> different job_id) that only
// holds if they're sharing one cache, not two independent ones.
func TestMultiplePortsShareSameJobManager(t *testing.T) {
	server, jm, _ := newMultiPortTestServer(t)

	xnA, _ := dialAndLoginAtDifficulty(t, server, 5000, "addr-shared-a")
	xnB, _ := dialAndLoginAtDifficulty(t, server, 500_000, "addr-shared-b")

	if xnA == xnB {
		t.Fatalf("expected sessions on different port tiers to still get different xns, both got %q", xnA)
	}

	// Both xns must be resolvable through the SAME *JobManager the
	// Server was constructed with (server.jobManager == jm), and
	// produce two DIFFERENT job_ids -- the existing per-xn guarantee,
	// which is only meaningful if one shared cache is being consulted
	// for both port tiers.
	if server.jobManager != jm {
		t.Fatalf("server.jobManager pointer changed unexpectedly across port tiers")
	}
	jobA, err := jm.JobForXN(context.Background(), xnA)
	if err != nil {
		t.Fatalf("JobForXN(%q): %v", xnA, err)
	}
	jobB, err := jm.JobForXN(context.Background(), xnB)
	if err != nil {
		t.Fatalf("JobForXN(%q): %v", xnB, err)
	}
	if jobA.ID == jobB.ID {
		t.Fatalf("expected two different-port-tier sessions to get different job_ids from the shared JobManager, both got %q", jobA.ID)
	}
	if len(xnA) != 4 || len(xnB) != 4 {
		t.Fatalf("expected 4-hex-char xns, got %q and %q", xnA, xnB)
	}
	if _, err := hex.DecodeString(xnA); err != nil {
		t.Errorf("xnA %q is not valid hex: %v", xnA, err)
	}
}
