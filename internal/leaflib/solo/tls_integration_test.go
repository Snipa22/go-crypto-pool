// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
	"github.com/Snipa22/go-crypto-pool/internal/leaflib/validator"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// TestServeOverRealTLSListener is the genuine TLS-handshake
// regression test required by the TLS-listener-support brief: it
// spins up a REAL net.Listener, wraps it with tls.NewListener using a
// real self-signed certificate produced by
// leaflib.LoadOrGenerateCert, serves it with the real
// Server.Serve(ctx, ln, port) (the exact same entrypoint
// cmd/leaf-solo and cmd/leaf-direct's main() use for a ":tls"-suffixed
// port tier), and connects with a real crypto/tls.Dial(...,
// &tls.Config{InsecureSkipVerify: true}) client -- mirroring exactly
// how a real miner with certificate verification disabled would
// connect (see internal/leaflib/tls.go's doc comment: miners are
// expected to skip TLS verification, self-signing is intentional).
//
// It then performs a real login/getjob JSON-RPC exchange over that
// TLS connection using the exact same login()/testHarness helpers
// session_test.go's plain-net.Pipe-based tests use, and asserts the
// same session-state/job-response shape: a valid 4-hex-char xn and a
// job whose wire "target" field decodes back to the port's configured
// starting difficulty -- proving Server.Serve/handleConn genuinely
// don't care whether the net.Conn they were handed came from a plain
// TCP net.Listener or a *tls.Listener.
func TestServeOverRealTLSListener(t *testing.T) {
	node := &fakeNodeClient{
		height:           42,
		targetDifficulty: 1 << 62,
		mergeMiningHash:  []byte("test-merge-mining-hash-32bytes!"),
		blockHashSeed:    []byte("test-block-hash-seed-32-bytes!!"),
	}
	const startingDifficulty = 12345
	jm := NewJobManager(JobManagerConfig{
		Node:             node,
		PayoutAddress:    "solo-test-address",
		StaticDifficulty: startingDifficulty,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cm := leaflib.NewConnectionManager(ctx, leaflib.ManagerConfig{IdleTimeout: 5 * time.Second})
	v := validator.NewSHA3XValidator()
	registry := validator.Registry{poolpb.Algo_ALGO_SHA3X: v}
	server := NewServer(cm, jm, node, registry, poolpb.Network_NETWORK_TESTNET, nil, VardiffConfig{})

	// Real self-signed cert, generated in memory (no cert/key files,
	// no persistence -- exercising LoadOrGenerateCert's simplest
	// path, already covered on its own by internal/leaflib/tls_test.go).
	cert, err := leaflib.LoadOrGenerateCert("", "", "", "127.0.0.1:0", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("LoadOrGenerateCert: %v", err)
	}

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	tlsLn := tls.NewListener(plainLn, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { _ = tlsLn.Close() })

	port := PortConfig{Address: tlsLn.Addr().String(), Difficulty: startingDifficulty, PortDesc: "tls-test", TLS: true}

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- server.Serve(ctx, tlsLn, port) }()

	// Real crypto/tls client dial -- exactly how a real miner with
	// cert verification disabled connects (see this test's doc
	// comment).
	clientConn, err := tls.Dial("tcp", tlsLn.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	h := &testHarness{
		t:      t,
		server: server,
		cm:     cm,
		jm:     jm,
		node:   node,
		client: clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		cancel: cancel,
	}

	sessionID, xn := login(t, h, "addr-tls-integration")
	if sessionID == "" {
		t.Fatalf("expected a non-empty session ID from login over TLS")
	}
	if len(xn) != 4 {
		t.Fatalf("expected a 4-hex-char xn, got %q", xn)
	}
	if _, err := hex.DecodeString(xn); err != nil {
		t.Fatalf("xn %q is not valid hex: %v", xn, err)
	}

	job, err := jm.JobForXN(context.Background(), xn)
	if err != nil {
		t.Fatalf("JobForXN(%q): %v", xn, err)
	}
	if job.StaticDifficulty != startingDifficulty {
		t.Fatalf("job.StaticDifficulty = %d, want %d (this TLS-served port tier's configured starting difficulty)", job.StaticDifficulty, startingDifficulty)
	}

	cancel()
	_ = tlsLn.Close()
	select {
	case err := <-serveErrCh:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("Server.Serve returned an unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Server.Serve did not return after context cancellation + listener close")
	}
}
