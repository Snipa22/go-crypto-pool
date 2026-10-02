// Copyright and license: see repository LICENSE (MIT).
package proxy

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/leaflib"
)

// openTestStatsDB opens a fresh StatsDB backed by a file in t's own
// TempDir (never /tmp directly -- t.TempDir() is the standard Go
// testing idiom, auto-cleaned up at test end).
func openTestStatsDB(t *testing.T) *StatsDB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stats.db")
	db, err := OpenStatsDB(path, log.New(nil2Writer{}, "", 0))
	if err != nil {
		t.Fatalf("OpenStatsDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestStatsDB_InsertAndHistory confirms a basic insert round-trips
// through History, sorted oldest-to-newest.
func TestStatsDB_InsertAndHistory(t *testing.T) {
	db := openTestStatsDB(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	samples := []MinerSample{
		{Timestamp: now.Add(-2 * time.Minute), Address: "addr1", Port: "default", Difficulty: 1000, HashrateHz: 100, ShareCount: 1},
		{Timestamp: now.Add(-1 * time.Minute), Address: "addr1", Port: "default", Difficulty: 2000, HashrateHz: 200, ShareCount: 2},
		{Timestamp: now, Address: "addr2", Port: "default", Difficulty: 3000, HashrateHz: 300, ShareCount: 3},
	}
	if err := db.InsertSamples(ctx, samples); err != nil {
		t.Fatalf("InsertSamples: %v", err)
	}

	got, err := db.History(ctx, "addr1")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("History(addr1) returned %d rows, want 2", len(got))
	}
	if !got[0].Timestamp.Before(got[1].Timestamp) {
		t.Errorf("expected oldest-to-newest order, got %v then %v", got[0].Timestamp, got[1].Timestamp)
	}
	if got[0].Difficulty != 1000 || got[1].Difficulty != 2000 {
		t.Errorf("unexpected difficulty values: %+v", got)
	}

	gotOther, err := db.History(ctx, "addr2")
	if err != nil {
		t.Fatalf("History(addr2): %v", err)
	}
	if len(gotOther) != 1 {
		t.Fatalf("History(addr2) returned %d rows, want 1", len(gotOther))
	}

	gotMissing, err := db.History(ctx, "no-such-address")
	if err != nil {
		t.Fatalf("History(missing): %v", err)
	}
	if len(gotMissing) != 0 {
		t.Fatalf("History(missing) returned %d rows, want 0", len(gotMissing))
	}
}

// TestStatsDB_PruneOlderThan_ActuallyRemovesOldRows is the required
// section-5 verification test (DISPATCH_BRIEF.md "Required
// verification before you report done", item 2): "SQLite insert +
// 24h prune actually removes old rows -- don't just test insert".
func TestStatsDB_PruneOlderThan_ActuallyRemovesOldRows(t *testing.T) {
	db := openTestStatsDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	samples := []MinerSample{
		{Timestamp: now.Add(-30 * time.Hour), Address: "stale-addr", Port: "default", Difficulty: 1000, HashrateHz: 100, ShareCount: 1}, // older than 24h
		{Timestamp: now.Add(-25 * time.Hour), Address: "stale-addr", Port: "default", Difficulty: 1000, HashrateHz: 100, ShareCount: 1}, // older than 24h
		{Timestamp: now.Add(-1 * time.Hour), Address: "stale-addr", Port: "default", Difficulty: 2000, HashrateHz: 200, ShareCount: 2},  // within 24h, must survive
	}
	if err := db.InsertSamples(ctx, samples); err != nil {
		t.Fatalf("InsertSamples: %v", err)
	}

	// Sanity: all 3 rows are there before pruning.
	var countBefore int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM miner_samples WHERE address = ?`, "stale-addr").Scan(&countBefore); err != nil {
		t.Fatalf("count before prune: %v", err)
	}
	if countBefore != 3 {
		t.Fatalf("countBefore = %d, want 3", countBefore)
	}

	removed, err := db.PruneOlderThan(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if removed != 2 {
		t.Fatalf("PruneOlderThan removed %d rows, want 2", removed)
	}

	// The real assertion this test exists for: the old rows are
	// ACTUALLY gone from the table, not just reported as removed.
	var countAfter int
	if err := db.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM miner_samples WHERE address = ?`, "stale-addr").Scan(&countAfter); err != nil {
		t.Fatalf("count after prune: %v", err)
	}
	if countAfter != 1 {
		t.Fatalf("countAfter = %d, want 1 (only the within-24h row should survive)", countAfter)
	}

	// And History (which already filters to the last 24h itself)
	// should agree.
	remaining, err := db.History(ctx, "stale-addr")
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(remaining) != 1 {
		t.Fatalf("History returned %d rows after prune, want 1", len(remaining))
	}
	if remaining[0].Difficulty != 2000 {
		t.Errorf("remaining row has difficulty %d, want 2000 (the within-24h sample)", remaining[0].Difficulty)
	}
}

// TestStatsDB_RunSampleLoop_InsertsAndPrunesOnEachTick confirms
// RunSampleLoop both inserts the snapshot AND prunes old rows on
// every tick, not as a separately-forgotten mechanism.
func TestStatsDB_RunSampleLoop_InsertsAndPrunesOnEachTick(t *testing.T) {
	db := openTestStatsDB(t)

	// Seed one row old enough to be pruned on the very first tick.
	ctx := context.Background()
	if err := db.InsertSamples(ctx, []MinerSample{
		{Timestamp: time.Now().Add(-25 * time.Hour), Address: "old-addr", Port: "default", Difficulty: 1, HashrateHz: 1, ShareCount: 1},
	}); err != nil {
		t.Fatalf("seed InsertSamples: %v", err)
	}

	runCtx, cancel := context.WithCancel(context.Background())
	snapshotCalls := 0
	snapshot := func(now time.Time) []MinerSample {
		snapshotCalls++
		return []MinerSample{{Timestamp: now, Address: "fresh-addr", Port: "default", Difficulty: 42, HashrateHz: 1, ShareCount: 1}}
	}

	done := make(chan struct{})
	go func() {
		db.RunSampleLoop(runCtx, 10*time.Millisecond, snapshot)
		close(done)
	}()

	// Give it a few ticks.
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done

	if snapshotCalls == 0 {
		t.Fatal("expected RunSampleLoop to have called snapshot at least once")
	}

	freshHistory, err := db.History(ctx, "fresh-addr")
	if err != nil {
		t.Fatalf("History(fresh-addr): %v", err)
	}
	if len(freshHistory) == 0 {
		t.Fatal("expected at least one inserted sample for fresh-addr")
	}

	oldHistory, err := db.History(ctx, "old-addr")
	if err != nil {
		t.Fatalf("History(old-addr): %v", err)
	}
	if len(oldHistory) != 0 {
		t.Fatalf("expected the 25h-old seeded row for old-addr to have been pruned, got %d rows", len(oldHistory))
	}
}

// TestMinersHistoryHandler_RequiresAddress confirms a missing
// address query parameter is a 400, not "return everything" --
// DISPATCH_BRIEF.md's own explicit scope ("a simple per-address
// query is sufficient scope").
func TestMinersHistoryHandler_RequiresAddress(t *testing.T) {
	db := openTestStatsDB(t)

	srv := httptest.NewServer(MinersHistoryHandler(db))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when address is omitted", resp.StatusCode)
	}
}

// TestMinersHistoryHandler_ReturnsSortedSamples confirms the HTTP
// handler returns the address's samples, oldest-to-newest, as a JSON
// array.
func TestMinersHistoryHandler_ReturnsSortedSamples(t *testing.T) {
	db := openTestStatsDB(t)
	ctx := context.Background()

	now := time.Now().UTC()
	if err := db.InsertSamples(ctx, []MinerSample{
		{Timestamp: now.Add(-2 * time.Minute), Address: "history-addr", Port: "p1", Difficulty: 10, HashrateHz: 1, ShareCount: 1},
		{Timestamp: now.Add(-1 * time.Minute), Address: "history-addr", Port: "p1", Difficulty: 20, HashrateHz: 2, ShareCount: 2},
	}); err != nil {
		t.Fatalf("InsertSamples: %v", err)
	}

	srv := httptest.NewServer(MinersHistoryHandler(db))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "?address=history-addr")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var entries []minerHistoryEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if entries[0].Difficulty != 10 || entries[1].Difficulty != 20 {
		t.Errorf("unexpected ordering/values: %+v", entries)
	}
}

// TestSampleForStatsDB_SkipsEmptyAddressSessions confirms
// Server.SampleForStatsDB only emits a sample for sessions that have
// actually logged in (non-empty address) -- an un-logged-in
// connection has nothing meaningful to track per-address.
func TestSampleForStatsDB_SkipsEmptyAddressSessions(t *testing.T) {
	h := newHarness(t, leaflib.VardiffConfig{RetargetInterval: time.Hour}, 0)
	c, _ := h.connect()
	_ = c // connected but never logs in

	samples := h.server.SampleForStatsDB(time.Now())
	if len(samples) != 0 {
		t.Fatalf("expected 0 samples for a never-logged-in session, got %d: %+v", len(samples), samples)
	}
}
