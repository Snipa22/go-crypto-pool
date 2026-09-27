// Package db: address_flags plumbing -- the persistence layer for two
// REAL, manual/operator-flag-driven miner-address controls: a hard
// ban (reject every further share from this address) and a forced
// minimum share difficulty (reject shares below an operator-set
// floor). See migrations/0004_address_flags.up.sql's doc comment for
// the full design rationale, and cmd/backend/addresscli.go for the
// only intended way an operator sets either of these (there is no
// HTTP endpoint for either -- these are deliberately CLI-only, human-
// in-the-loop actions, mirroring blockcli.go/retentioncli.go's own
// -yes-gated, ops-triggered convention).
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrAddressBanned is returned by InsertShare when the submitting
// share's payment_address has an address_flags row with banned =
// TRUE. Repository.InsertShare returns this BEFORE performing any
// insert -- a banned address's shares never reach the `shares` table,
// so they can never accrue balance, count toward a block find, or
// otherwise affect payout/accounting.
var ErrAddressBanned = errors.New("db: payment address is banned")

// ErrShareDifficultyTooLow is returned by InsertShare when the
// submitting share's payment_address has an address_flags row with a
// non-NULL forced_min_difficulty and the share's block_diff is below
// it. Like ErrAddressBanned, this is checked BEFORE any insert -- an
// under-floor share from a difficulty-flagged address never reaches
// `shares` either.
var ErrShareDifficultyTooLow = errors.New("db: share difficulty below operator-forced minimum for this payment address")

// AddressFlag is one address_flags row -- the manual ban/forced-
// difficulty state for a single payment_address. A zero-value
// AddressFlag (Banned=false, ForcedMinDifficulty=nil) is what
// GetAddressFlag returns for an address with no row at all, which is
// the overwhelmingly common case (this table only ever holds
// addresses an operator has explicitly acted on) -- see
// GetAddressFlag's doc comment.
type AddressFlag struct {
	PaymentAddress string

	Banned    bool
	BanReason *string
	BannedAt  *time.Time
	BannedBy  *string

	// ForcedMinDifficulty is nil when no operator-forced floor is
	// set for this address. When non-nil it is guaranteed > 0 (see
	// the schema's chk_address_flags_forced_min_difficulty_positive
	// CHECK constraint and SetForcedMinDifficulty's own validation).
	ForcedMinDifficulty *int64
	DifficultyReason    *string
	DifficultySetAt     *time.Time
	DifficultySetBy     *string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// GetAddressFlag returns the address_flags row for paymentAddress, or
// a zero-value AddressFlag (Banned=false, ForcedMinDifficulty=nil) if
// no row exists. Mirrors SoloShare/GetAddressMap's "not found is a
// normal, non-error outcome" convention: the overwhelming majority of
// real payment addresses will never have a row here at all, and that
// is not a caller error -- it is simply "this address is not, and has
// never been, operator-flagged".
func (r *Repository) GetAddressFlag(ctx context.Context, paymentAddress string) (AddressFlag, error) {
	if paymentAddress == "" {
		return AddressFlag{}, errors.New("db: GetAddressFlag: payment_address is required")
	}

	const stmt = `
		SELECT payment_address, banned, ban_reason, banned_at, banned_by,
		       forced_min_difficulty, difficulty_reason, difficulty_set_at, difficulty_set_by,
		       created_at, updated_at
		FROM address_flags
		WHERE payment_address = $1`
	var f AddressFlag
	err := r.pool.QueryRow(ctx, stmt, paymentAddress).Scan(
		&f.PaymentAddress, &f.Banned, &f.BanReason, &f.BannedAt, &f.BannedBy,
		&f.ForcedMinDifficulty, &f.DifficultyReason, &f.DifficultySetAt, &f.DifficultySetBy,
		&f.CreatedAt, &f.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AddressFlag{PaymentAddress: paymentAddress}, nil
		}
		return AddressFlag{}, fmt.Errorf("db: getting address flag for %s: %w", paymentAddress, err)
	}
	return f, nil
}

// SetAddressBan upserts paymentAddress's ban state. banned=true sets
// ban_reason/banned_at/banned_by to reason/now()/by; banned=false
// clears banned back to FALSE but deliberately leaves ban_reason/
// banned_at/banned_by in place as a historical record of the most
// recent ban action (an unban is not "this address was never banned",
// it's "this address's ban was lifted" -- an operator reviewing this
// row later should still be able to see why/when/by whom it was last
// banned). The difficulty-flag columns are untouched either way; ban
// and forced-difficulty are independent flags on the same row.
//
// reason/by may be empty strings (stored as NULL) -- neither is
// required by this method itself, though cmd/backend's CLI requires
// -reason for `address ban` (see addresscli.go) since an operator
// action with no recorded justification is exactly the kind of gap
// this table's audit columns exist to close.
func (r *Repository) SetAddressBan(ctx context.Context, paymentAddress string, banned bool, reason, by string) error {
	if paymentAddress == "" {
		return errors.New("db: SetAddressBan: payment_address is required")
	}

	var reasonPtr, byPtr *string
	var bannedAt *time.Time
	if banned {
		if reason != "" {
			reasonPtr = &reason
		}
		if by != "" {
			byPtr = &by
		}
		now := time.Now().UTC()
		bannedAt = &now
	}

	const stmt = `
		INSERT INTO address_flags (payment_address, banned, ban_reason, banned_at, banned_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (payment_address) DO UPDATE SET
			banned     = EXCLUDED.banned,
			ban_reason = CASE WHEN $2 THEN EXCLUDED.ban_reason ELSE address_flags.ban_reason END,
			banned_at  = CASE WHEN $2 THEN EXCLUDED.banned_at ELSE address_flags.banned_at END,
			banned_by  = CASE WHEN $2 THEN EXCLUDED.banned_by ELSE address_flags.banned_by END,
			updated_at = now()`
	if _, err := r.pool.Exec(ctx, stmt, paymentAddress, banned, reasonPtr, bannedAt, byPtr); err != nil {
		return fmt.Errorf("db: setting ban state for %s: %w", paymentAddress, err)
	}
	return nil
}

// SetForcedMinDifficulty upserts paymentAddress's forced-minimum-
// share-difficulty floor. minDifficulty > 0 sets the floor (plus
// difficulty_reason/difficulty_set_at/difficulty_set_by); minDifficulty
// <= 0 CLEARS it (sets forced_min_difficulty back to NULL) -- there is
// no such thing as a real "floor of zero", so this is the one
// deliberate exception to this method's own positive-value
// requirement, and it is the only way to remove a floor once set (see
// cmd/backend/addresscli.go's `address clear-difficulty` subcommand,
// which calls this with minDifficulty=0). Like SetAddressBan, the
// audit columns (difficulty_reason/set_at/set_by) are only overwritten
// when actually setting a floor, so clearing one preserves the record
// of the most recent floor that was in effect.
func (r *Repository) SetForcedMinDifficulty(ctx context.Context, paymentAddress string, minDifficulty int64, reason, by string) error {
	if paymentAddress == "" {
		return errors.New("db: SetForcedMinDifficulty: payment_address is required")
	}

	clearing := minDifficulty <= 0
	var floorPtr *int64
	var reasonPtr, byPtr *string
	var setAt *time.Time
	if !clearing {
		floorPtr = &minDifficulty
		if reason != "" {
			reasonPtr = &reason
		}
		if by != "" {
			byPtr = &by
		}
		now := time.Now().UTC()
		setAt = &now
	}

	const stmt = `
		INSERT INTO address_flags (payment_address, forced_min_difficulty, difficulty_reason, difficulty_set_at, difficulty_set_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (payment_address) DO UPDATE SET
			forced_min_difficulty = $2,
			difficulty_reason     = CASE WHEN $2 IS NOT NULL THEN EXCLUDED.difficulty_reason ELSE address_flags.difficulty_reason END,
			difficulty_set_at     = CASE WHEN $2 IS NOT NULL THEN EXCLUDED.difficulty_set_at ELSE address_flags.difficulty_set_at END,
			difficulty_set_by     = CASE WHEN $2 IS NOT NULL THEN EXCLUDED.difficulty_set_by ELSE address_flags.difficulty_set_by END,
			updated_at            = now()`
	if _, err := r.pool.Exec(ctx, stmt, paymentAddress, floorPtr, reasonPtr, setAt, byPtr); err != nil {
		return fmt.Errorf("db: setting forced minimum difficulty for %s: %w", paymentAddress, err)
	}
	return nil
}

// ListAddressFlags returns every address_flags row that currently has
// an active flag (banned = TRUE OR forced_min_difficulty IS NOT
// NULL), payment_address ascending. Rows that were once flagged but
// have since been fully cleared (banned=false AND
// forced_min_difficulty IS NULL) are intentionally excluded -- this
// is an ops-facing "who is flagged right now" view (the `backend
// address list` CLI subcommand), not a full audit-log dump of every
// row that ever existed.
func (r *Repository) ListAddressFlags(ctx context.Context) ([]AddressFlag, error) {
	const stmt = `
		SELECT payment_address, banned, ban_reason, banned_at, banned_by,
		       forced_min_difficulty, difficulty_reason, difficulty_set_at, difficulty_set_by,
		       created_at, updated_at
		FROM address_flags
		WHERE banned = TRUE OR forced_min_difficulty IS NOT NULL
		ORDER BY payment_address ASC`
	rows, err := r.pool.Query(ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("db: listing address flags: %w", err)
	}
	defer rows.Close()

	var out []AddressFlag
	for rows.Next() {
		var f AddressFlag
		if err := rows.Scan(
			&f.PaymentAddress, &f.Banned, &f.BanReason, &f.BannedAt, &f.BannedBy,
			&f.ForcedMinDifficulty, &f.DifficultyReason, &f.DifficultySetAt, &f.DifficultySetBy,
			&f.CreatedAt, &f.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("db: scanning address flag row: %w", err)
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterating address flag rows: %w", err)
	}
	return out, nil
}

// checkAddressFlags is InsertShare's real enforcement point for both
// manual controls: it looks up s's payment_address in address_flags
// and returns ErrAddressBanned or ErrShareDifficultyTooLow if either
// condition applies. Called BEFORE InsertShare does any partitioning/
// insert work, so a rejected share never touches `shares` at all --
// see this file's package doc comment and migrations/
// 0004_address_flags.up.sql for why that matters (banned/under-floor
// shares must never accrue balance or count toward a block find).
//
// A lookup error here (e.g. the DB is briefly unreachable) is
// propagated as a real error, not silently treated as "not flagged"
// -- failing open on a ban/difficulty-floor check would defeat the
// entire point of the control being enforced at all.
func (r *Repository) checkAddressFlags(ctx context.Context, paymentAddress string, blockDiff int64) error {
	flag, err := r.GetAddressFlag(ctx, paymentAddress)
	if err != nil {
		return fmt.Errorf("db: checking address flags for %s: %w", paymentAddress, err)
	}
	if flag.Banned {
		return fmt.Errorf("%w: %s", ErrAddressBanned, paymentAddress)
	}
	if flag.ForcedMinDifficulty != nil && blockDiff < *flag.ForcedMinDifficulty {
		return fmt.Errorf("%w: %s submitted diff %d, floor is %d", ErrShareDifficultyTooLow, paymentAddress, blockDiff, *flag.ForcedMinDifficulty)
	}
	return nil
}
