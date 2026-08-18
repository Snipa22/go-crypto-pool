package leaflib

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// TestConcurrentWritesDoNotInterleave regression-guards bug class 4: the
// legacy stratum servers let both the read-loop goroutine and
// periodic/cron-driven goroutines call Write() on the same net.Conn with
// no synchronization, risking byte-interleaved/corrupted protocol
// frames. Here many goroutines concurrently call ManagedConnection.Write
// with distinguishable, delimited payloads; the receiving end must see
// each payload whole and unmangled, never interleaved with another.
func TestConcurrentWritesDoNotInterleave(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	cm := NewConnectionManager(context.Background(), ManagerConfig{})
	defer cm.Shutdown()

	mc, err := cm.Accept(context.Background(), serverConn)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer mc.Close("test done")

	const goroutines = 20
	const perGoroutine = 25

	// Each payload is a self-delimited, distinguishable line:
	// "g<goroutine-id>-m<msg-id>-<padding>\n" with a per-goroutine fixed
	// pattern in the padding so any interleaving/truncation is visible
	// as a decode failure or a checksum mismatch on the receiving side.
	received := make(chan string, goroutines*perGoroutine)
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		r := io.Reader(clientConn)
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 256)
		for {
			n, err := r.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				for {
					idx := bytes.IndexByte(buf, '\n')
					if idx < 0 {
						break
					}
					line := string(buf[:idx])
					buf = buf[idx+1:]
					received <- line
				}
			}
			if err != nil {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for m := 0; m < perGoroutine; m++ {
				line := fmt.Sprintf("g%02d-m%03d-%s\n", g, m, bytes.Repeat([]byte{byte('A' + g)}, 8))
				if err := mc.Write([]byte(line)); err != nil {
					t.Errorf("Write from goroutine %d: %v", g, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	// Give the reader time to drain, then close the writer side so the
	// reader goroutine terminates.
	deadlineCh := time.After(3 * time.Second)
	total := goroutines * perGoroutine
	got := make([]string, 0, total)
collect:
	for len(got) < total {
		select {
		case line := <-received:
			got = append(got, line)
		case <-deadlineCh:
			break collect
		}
	}

	mc.Close("test done")
	<-readDone

	if len(got) != total {
		t.Fatalf("expected %d whole messages, received %d (bug class 4 regression: writes interleaved/lost)", total, len(got))
	}

	seen := make(map[string]bool, total)
	for _, line := range got {
		var g, m int
		var pad string
		if _, err := fmt.Sscanf(line, "g%02d-m%03d-%s", &g, &m, &pad); err != nil {
			t.Fatalf("received corrupted/interleaved line %q: %v", line, err)
		}
		expectedPad := string(bytes.Repeat([]byte{byte('A' + g)}, 8))
		if pad != expectedPad {
			t.Fatalf("line %q has mismatched padding for goroutine %d (interleaving corruption)", line, g)
		}
		key := fmt.Sprintf("g%02d-m%03d", g, m)
		if seen[key] {
			t.Fatalf("duplicate message %q received (corruption)", key)
		}
		seen[key] = true
	}
}
