package db_test

// Integration tests for db.Repository.SetAddressMap's idempotent
// same-value-resubmit and concurrency-safety semantics (see
// FIX_BRIEF_IDEMPOTENT.md). Like the rest of this package's
// integration tests (see integration_test.go's doc comment), these
// are gated on GCPOOL_TEST_DSN and are skipped, not failed, when no
// real Postgres instance is available.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

// TestIntegrationSetAddressMap_IdempotentSameValue calls
// SetAddressMap twice sequentially for the same xmr_address with the
// SAME tari_address -- both calls must return nil, and the row's
// tari_address must equal that value. It then calls SetAddressMap a
// third time with a DIFFERENT tari_address, which must return
// ErrAddressAlreadyMapped while leaving the row's stored tari_address
// at its ORIGINAL value, unchanged.
func TestIntegrationSetAddressMap_IdempotentSameValue(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const xmrAddr = "idempotent-same-value-xmr-addr"
	const tariAddr = "idempotent-same-value-tari-addr"

	if err := repo.SetAddressMap(ctx, xmrAddr, tariAddr); err != nil {
		t.Fatalf("first SetAddressMap: %v", err)
	}
	if err := repo.SetAddressMap(ctx, xmrAddr, tariAddr); err != nil {
		t.Fatalf("second SetAddressMap (identical resubmit): got %v, want nil (idempotent no-op)", err)
	}

	m, err := repo.GetAddressMap(ctx, xmrAddr)
	if err != nil {
		t.Fatalf("GetAddressMap: %v", err)
	}
	if m.TariAddress != tariAddr {
		t.Fatalf("got tari_address = %q, want %q", m.TariAddress, tariAddr)
	}
}

// TestIntegrationSetAddressMap_RejectsDifferentValue is
// TestIntegrationSetAddressMap_IdempotentSameValue's sibling: a THIRD
// call for the same xmr_address with a DIFFERENT tari_address must
// return ErrAddressAlreadyMapped, and the row's stored tari_address
// must remain the ORIGINAL value.
func TestIntegrationSetAddressMap_RejectsDifferentValue(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const xmrAddr = "rejects-different-value-xmr-addr"
	const originalTari = "rejects-different-value-original-tari-addr"
	const differentTari = "rejects-different-value-different-tari-addr"

	if err := repo.SetAddressMap(ctx, xmrAddr, originalTari); err != nil {
		t.Fatalf("first SetAddressMap: %v", err)
	}
	if err := repo.SetAddressMap(ctx, xmrAddr, originalTari); err != nil {
		t.Fatalf("second SetAddressMap (identical resubmit): got %v, want nil", err)
	}
	err := repo.SetAddressMap(ctx, xmrAddr, differentTari)
	if !errors.Is(err, db.ErrAddressAlreadyMapped) {
		t.Fatalf("third SetAddressMap (different tari_address): got %v, want ErrAddressAlreadyMapped", err)
	}

	m, err := repo.GetAddressMap(ctx, xmrAddr)
	if err != nil {
		t.Fatalf("GetAddressMap: %v", err)
	}
	if m.TariAddress != originalTari {
		t.Fatalf("got tari_address = %q, want original %q (must be unchanged)", m.TariAddress, originalTari)
	}
}

// TestIntegrationSetAddressMap_ConcurrentSameValueAllSucceed spins up
// N goroutines all calling SetAddressMap concurrently for the SAME
// brand-new xmr_address with the SAME tari_address (first-set race,
// identical value). ALL N calls must return nil (no error), and
// after they all complete, querying the row must show exactly one
// row with that tari_address -- no duplicate-row crash, no
// corruption.
func TestIntegrationSetAddressMap_ConcurrentSameValueAllSucceed(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const n = 20
	const xmrAddr = "concurrent-same-value-xmr-addr"
	const tariAddr = "concurrent-same-value-tari-addr"

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = repo.SetAddressMap(ctx, xmrAddr, tariAddr)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: SetAddressMap returned %v, want nil (all identical-value calls must succeed)", i, err)
		}
	}

	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM address_map WHERE xmr_address = $1", xmrAddr).Scan(&count); err != nil {
		t.Fatalf("counting address_map rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("got %d rows for %s, want exactly 1 (no duplicate/corrupted rows)", count, xmrAddr)
	}

	m, err := repo.GetAddressMap(ctx, xmrAddr)
	if err != nil {
		t.Fatalf("GetAddressMap: %v", err)
	}
	if m.TariAddress != tariAddr {
		t.Fatalf("got tari_address = %q, want %q", m.TariAddress, tariAddr)
	}
}

// TestIntegrationSetAddressMap_ConcurrentDifferentValuesExactlyOneWins
// spins up N goroutines concurrently calling SetAddressMap for the
// SAME brand-new xmr_address but with DIFFERENT tari_addresses (each
// goroutine gets a distinct value). Exactly ONE call must return nil
// and ALL the rest must return ErrAddressAlreadyMapped, and the final
// row's tari_address must match whichever single value won.
func TestIntegrationSetAddressMap_ConcurrentDifferentValuesExactlyOneWins(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	const n = 20
	const xmrAddr = "concurrent-different-values-xmr-addr"

	tariAddrs := make([]string, n)
	for i := 0; i < n; i++ {
		tariAddrs[i] = fmt.Sprintf("concurrent-different-values-tari-addr-%d", i)
	}

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = repo.SetAddressMap(ctx, xmrAddr, tariAddrs[i])
		}(i)
	}
	wg.Wait()

	var winners int
	var winnerIdx = -1
	for i, err := range errs {
		if err == nil {
			winners++
			winnerIdx = i
			continue
		}
		if !errors.Is(err, db.ErrAddressAlreadyMapped) {
			t.Errorf("goroutine %d: got err = %v, want nil or ErrAddressAlreadyMapped", i, err)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d goroutines returning nil, want exactly 1 (all others must return ErrAddressAlreadyMapped)", winners)
	}

	m, err := repo.GetAddressMap(ctx, xmrAddr)
	if err != nil {
		t.Fatalf("GetAddressMap: %v", err)
	}
	if m.TariAddress != tariAddrs[winnerIdx] {
		t.Fatalf("got tari_address = %q, want the single winner's value %q", m.TariAddress, tariAddrs[winnerIdx])
	}

	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM address_map WHERE xmr_address = $1", xmrAddr).Scan(&count); err != nil {
		t.Fatalf("counting address_map rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("got %d rows for %s, want exactly 1", count, xmrAddr)
	}
}
