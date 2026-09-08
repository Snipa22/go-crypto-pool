package db_test

// Integration tests for internal/backend/db/users.go, motd.go, and
// forcepayout.go's real-Postgres persistence -- the SXMR-legacy
// authentication/account-settings/force-payout tables added by
// migrations/0007_users_motd.up.sql and
// migrations/0008_balance_force_payout.up.sql. Same GCPOOL_TEST_DSN
// opt-in convention as integration_test.go -- see that file's
// package doc comment.

import (
	"context"
	"errors"
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
)

func TestIntegrationUsersCRUD(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}

	repo := db.NewRepository(pool)

	// UpsertUserThreshold creates a fresh row with the legacy
	// placeholder email when none exists yet.
	if err := repo.UpsertUserThreshold(ctx, "addr-1", 1000); err != nil {
		t.Fatalf("UpsertUserThreshold (create): %v", err)
	}
	u, err := repo.GetUserByUsername(ctx, "addr-1")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if u.Email != "null@null.null" || u.PayoutThreshold != 1000 || u.Pass != nil || u.Admin || u.EnableEmail {
		t.Fatalf("unexpected freshly-created user: %+v", u)
	}

	// Re-upserting the same username updates the threshold in place,
	// not a second row (uq_users_username).
	if err := repo.UpsertUserThreshold(ctx, "addr-1", 2000); err != nil {
		t.Fatalf("UpsertUserThreshold (update): %v", err)
	}
	u2, err := repo.GetUserByUsername(ctx, "addr-1")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if u2.ID != u.ID || u2.PayoutThreshold != 2000 {
		t.Fatalf("expected same row with updated threshold, got %+v (was %+v)", u2, u)
	}

	// GetUserByID mirrors GetUserByUsername for the same row.
	byID, err := repo.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if byID.Username != "addr-1" {
		t.Fatalf("GetUserByID returned wrong row: %+v", byID)
	}

	// UpdateUserPassword.
	hash := "deadbeef"
	if err := repo.UpdateUserPassword(ctx, u.ID, hash); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	byID, _ = repo.GetUserByID(ctx, u.ID)
	if byID.Pass == nil || *byID.Pass != hash {
		t.Fatalf("password not persisted: %+v", byID)
	}

	// ToggleUserEnableEmail (JWT-gated path, keyed by id).
	if err := repo.ToggleUserEnableEmail(ctx, u.ID); err != nil {
		t.Fatalf("ToggleUserEnableEmail: %v", err)
	}
	byID, _ = repo.GetUserByID(ctx, u.ID)
	if !byID.EnableEmail {
		t.Fatalf("expected enable_email = true after toggle, got %+v", byID)
	}

	// ToggleUserEnableEmailByUsername (public path, keyed by
	// username) toggles the same underlying column.
	if err := repo.ToggleUserEnableEmailByUsername(ctx, "addr-1"); err != nil {
		t.Fatalf("ToggleUserEnableEmailByUsername: %v", err)
	}
	byID, _ = repo.GetUserByID(ctx, u.ID)
	if byID.EnableEmail {
		t.Fatalf("expected enable_email = false after second toggle, got %+v", byID)
	}
	// No-op (still no error) for a username that doesn't exist.
	if err := repo.ToggleUserEnableEmailByUsername(ctx, "no-such-user"); err != nil {
		t.Fatalf("ToggleUserEnableEmailByUsername(missing): expected no-op, got %v", err)
	}

	// UpdateUserPayoutThreshold (JWT-gated path, keyed by id).
	if err := repo.UpdateUserPayoutThreshold(ctx, u.ID, 3000); err != nil {
		t.Fatalf("UpdateUserPayoutThreshold: %v", err)
	}
	byID, _ = repo.GetUserByID(ctx, u.ID)
	if byID.PayoutThreshold != 3000 {
		t.Fatalf("expected payout_threshold = 3000, got %+v", byID)
	}

	// Not-found cases.
	if _, err := repo.GetUserByUsername(ctx, "ghost"); !errors.Is(err, db.ErrUserNotFound) {
		t.Fatalf("GetUserByUsername(ghost): expected ErrUserNotFound, got %v", err)
	}
	if _, err := repo.GetUserByID(ctx, 999999); !errors.Is(err, db.ErrUserNotFound) {
		t.Fatalf("GetUserByID(999999): expected ErrUserNotFound, got %v", err)
	}
	if err := repo.UpdateUserPassword(ctx, 999999, "x"); !errors.Is(err, db.ErrUserNotFound) {
		t.Fatalf("UpdateUserPassword(999999): expected ErrUserNotFound, got %v", err)
	}
	if err := repo.ToggleUserEnableEmail(ctx, 999999); !errors.Is(err, db.ErrUserNotFound) {
		t.Fatalf("ToggleUserEnableEmail(999999): expected ErrUserNotFound, got %v", err)
	}
	if err := repo.UpdateUserPayoutThreshold(ctx, 999999, 1); !errors.Is(err, db.ErrUserNotFound) {
		t.Fatalf("UpdateUserPayoutThreshold(999999): expected ErrUserNotFound, got %v", err)
	}
}

func TestIntegrationMotd(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// Empty table: ErrMotdNotFound, not a generic error.
	if _, err := repo.LatestMotd(ctx); !errors.Is(err, db.ErrMotdNotFound) {
		t.Fatalf("LatestMotd(empty): expected ErrMotdNotFound, got %v", err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO motd (subject, body, type, active) VALUES ('first', 'first body', 'info', TRUE)`); err != nil {
		t.Fatalf("inserting first motd row: %v", err)
	}
	m1, err := repo.LatestMotd(ctx)
	if err != nil {
		t.Fatalf("LatestMotd: %v", err)
	}
	if m1.Subject != "first" || !m1.Active {
		t.Fatalf("unexpected motd row: %+v", m1)
	}

	// A second, newer row (higher id) wins over the first.
	if _, err := pool.Exec(ctx, `INSERT INTO motd (subject, body, type, active) VALUES ('second', 'second body', 'warn', FALSE)`); err != nil {
		t.Fatalf("inserting second motd row: %v", err)
	}
	m2, err := repo.LatestMotd(ctx)
	if err != nil {
		t.Fatalf("LatestMotd: %v", err)
	}
	if m2.Subject != "second" || m2.Active {
		t.Fatalf("expected the newest (second) row to win, got %+v", m2)
	}
}

func TestIntegrationSetForcePayout(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	resetSchema(t, pool)
	if err := db.ApplyMigrations(ctx, pool); err != nil {
		t.Fatalf("ApplyMigrations: %v", err)
	}
	repo := db.NewRepository(pool)

	// No matching balance row at all.
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "addr-none", nil); !errors.Is(err, db.ErrBalanceNotFound) {
		t.Fatalf("SetForcePayout(no row): expected ErrBalanceNotFound, got %v", err)
	}

	// A balance row exists but pending_balance is zero -- still
	// rejected (this backend's stated equivalent of legacy's
	// too-low-balance check, see forcepayout.go's doc comment).
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "addr-zero", nil, 0); err != nil {
		t.Fatalf("CreditBalance(0): %v", err)
	}
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "addr-zero", nil); !errors.Is(err, db.ErrBalanceNotFound) {
		t.Fatalf("SetForcePayout(zero balance): expected ErrBalanceNotFound, got %v", err)
	}

	// A real, positive-balance row gets flagged.
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "addr-ok", nil, 500); err != nil {
		t.Fatalf("CreditBalance: %v", err)
	}
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "addr-ok", nil); err != nil {
		t.Fatalf("SetForcePayout: %v", err)
	}
	var forced bool
	if err := pool.QueryRow(ctx, `SELECT force_payout FROM balance WHERE algo = 'RXM' AND network = 'TESTNET' AND payment_address = 'addr-ok'`).Scan(&forced); err != nil {
		t.Fatalf("querying force_payout: %v", err)
	}
	if !forced {
		t.Fatal("expected force_payout = TRUE after SetForcePayout")
	}

	// payment_id-scoped rows are distinguished correctly.
	pid := "pid-1"
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "addr-multi", nil, 100); err != nil {
		t.Fatalf("CreditBalance(no pid): %v", err)
	}
	if err := repo.CreditBalance(ctx, "RXM", "TESTNET", "addr-multi", &pid, 200); err != nil {
		t.Fatalf("CreditBalance(pid): %v", err)
	}
	if err := repo.SetForcePayout(ctx, "RXM", "TESTNET", "addr-multi", &pid); err != nil {
		t.Fatalf("SetForcePayout(pid): %v", err)
	}
	var noPidForced, pidForced bool
	if err := pool.QueryRow(ctx, `SELECT force_payout FROM balance WHERE algo='RXM' AND network='TESTNET' AND payment_address='addr-multi' AND payment_id IS NULL`).Scan(&noPidForced); err != nil {
		t.Fatalf("querying no-pid row: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT force_payout FROM balance WHERE algo='RXM' AND network='TESTNET' AND payment_address='addr-multi' AND payment_id = 'pid-1'`).Scan(&pidForced); err != nil {
		t.Fatalf("querying pid row: %v", err)
	}
	if noPidForced {
		t.Fatal("expected the no-payment_id row to remain untouched")
	}
	if !pidForced {
		t.Fatal("expected the pid-1 row to be flagged")
	}
}
