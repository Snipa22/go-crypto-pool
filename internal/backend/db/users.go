// users.go implements the backend's persistence for `users` (see
// migrations/0007_users_motd.up.sql): the SXMR-legacy
// authentication/account-settings system's account table. Kept as
// its own file for the same reason addressmap.go/network.go are
// separate from repository.go -- this is a genuinely distinct read/
// write surface (miner account credentials/settings, consumed by
// internal/backend/authapi) from the core share/block ingestion
// methods.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// User is one `users` row. Username is the miner's payment address
// (see that migration's doc comment -- there is no separate
// registration flow). Pass is nullable: a NULL pass means this user
// can never successfully authenticate via POST /authenticate (see
// internal/backend/authapi's package doc comment for the deliberate
// deviation from legacy's NULL/email-fallback quirk here).
type User struct {
	ID              int64
	Username        string
	Email           string
	Pass            *string
	Admin           bool
	EnableEmail     bool
	PayoutThreshold int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// ErrUserNotFound is returned by GetUserByUsername/GetUserByID when
// no matching row exists, and by the Update* methods below when their
// WHERE clause matches zero rows (i.e. the id/username no longer
// exists).
var ErrUserNotFound = errors.New("db: users: no such user")

const userColumns = `id, username, email, pass, admin, enable_email, payout_threshold, created_at, updated_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Pass, &u.Admin, &u.EnableEmail, &u.PayoutThreshold, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// GetUserByUsername returns the `users` row for username, or
// ErrUserNotFound if none exists.
func (r *Repository) GetUserByUsername(ctx context.Context, username string) (User, error) {
	stmt := `SELECT ` + userColumns + ` FROM users WHERE username = $1`
	u, err := scanUser(r.pool.QueryRow(ctx, stmt, username))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("db: querying user %q: %w", username, err)
	}
	return u, nil
}

// GetUserByID returns the `users` row for id, or ErrUserNotFound if
// none exists. Used by internal/backend/authapi to resolve a
// validated JWT's `id` claim back to the real account row (GET
// /authed/).
func (r *Repository) GetUserByID(ctx context.Context, id int64) (User, error) {
	stmt := `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	u, err := scanUser(r.pool.QueryRow(ctx, stmt, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}
		return User{}, fmt.Errorf("db: querying user id %d: %w", id, err)
	}
	return u, nil
}

// UpdateUserPassword sets the `pass` column (an already-hashed
// credential -- see authapi.Handler's hashPassword; this repository
// layer never hashes anything itself) for the user identified by id.
// Returns ErrUserNotFound if id does not match any row.
func (r *Repository) UpdateUserPassword(ctx context.Context, id int64, passHash string) error {
	const stmt = `UPDATE users SET pass = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, stmt, id, passHash)
	if err != nil {
		return fmt.Errorf("db: updating password for user %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ToggleUserEnableEmail flips `enable_email` for the user identified
// by id (the JWT-gated POST /authed/toggleEmail path). Returns
// ErrUserNotFound if id does not match any row.
func (r *Repository) ToggleUserEnableEmail(ctx context.Context, id int64) error {
	const stmt = `UPDATE users SET enable_email = NOT enable_email, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, stmt, id)
	if err != nil {
		return fmt.Errorf("db: toggling enable_email for user %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// ToggleUserEnableEmailByUsername flips `enable_email` for the user
// identified by username (the public POST /user/toggleEmail path).
// Deliberately does NOT return ErrUserNotFound when username matches
// no row -- per legacy behavior (see brief-auth.md), this is a no-op
// that still reports success, not an error.
func (r *Repository) ToggleUserEnableEmailByUsername(ctx context.Context, username string) error {
	const stmt = `UPDATE users SET enable_email = NOT enable_email, updated_at = now() WHERE username = $1`
	if _, err := r.pool.Exec(ctx, stmt, username); err != nil {
		return fmt.Errorf("db: toggling enable_email for %q: %w", username, err)
	}
	return nil
}

// UpdateUserPayoutThreshold sets `payout_threshold` for the user
// identified by id (the JWT-gated POST /authed/changePayoutThreshold
// path). Returns ErrUserNotFound if id does not match any row.
func (r *Repository) UpdateUserPayoutThreshold(ctx context.Context, id int64, threshold int64) error {
	const stmt = `UPDATE users SET payout_threshold = $2, updated_at = now() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, stmt, id, threshold)
	if err != nil {
		return fmt.Errorf("db: updating payout_threshold for user %d: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}

// UpsertUserThreshold implements the public POST /user/updateThreshold
// path's exact legacy semantics: insert a new `users` row for
// username (with the legacy placeholder email 'null@null.null') if
// none exists yet, or simply update payout_threshold on the existing
// one -- relying on uq_users_username for the ON CONFLICT target.
func (r *Repository) UpsertUserThreshold(ctx context.Context, username string, threshold int64) error {
	const stmt = `
		INSERT INTO users (username, email, payout_threshold)
		VALUES ($1, 'null@null.null', $2)
		ON CONFLICT (username)
		DO UPDATE SET payout_threshold = EXCLUDED.payout_threshold, updated_at = now()`
	if _, err := r.pool.Exec(ctx, stmt, username, threshold); err != nil {
		return fmt.Errorf("db: upserting threshold for %q: %w", username, err)
	}
	return nil
}
