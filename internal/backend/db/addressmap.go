// addressmap.go implements the backend's persistence for `address_map`
// (see migrations/0003_address_map.up.sql): the SXMR merge-mining
// system's XMR-to-Tari address mapping. Kept as its own file for the
// same reason stats.go is separate from repository.go -- this is a
// genuinely distinct read/write surface (miner-submitted address
// mapping, consulted by the Tari-side payout path) from the core
// share/block ingestion methods.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AddressMap is one `address_map` row: a miner's chosen Tari payout
// destination for a given Monero (XMR) payment address.
type AddressMap struct {
	XMRAddress  string
	TariAddress string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ErrAddressMapNotFound is returned by GetAddressMap when xmrAddress
// has no mapping row.
var ErrAddressMapNotFound = errors.New("db: address_map: no mapping for xmr_address")

// ErrAddressAlreadyMapped is returned by SetAddressMap when
// xmrAddress already has a mapping row -- see that function's doc
// comment: this closes the payout-redirection vector where a caller
// who merely knows an xmr_address could otherwise hijack an
// already-set tari_address destination.
var ErrAddressAlreadyMapped = errors.New("db: address_map: xmr_address is already mapped")

// SetAddressMap inserts a new xmrAddress -> tariAddress mapping if
// (and only if) xmrAddress has no existing row. It is deliberately
// set-once/no-overwrite -- per explicit product direction (see
// FIX_BRIEF.md), once an xmr_address has a tari_address mapped, a
// later call for the same xmr_address must NOT change it. Returns
// ErrAddressAlreadyMapped (leaving the existing row completely
// untouched -- not even updated_at is stamped) if xmrAddress already
// has a mapping; this function was previously named UpsertAddressMap
// and did overwrite on conflict -- renamed because it is no longer an
// upsert. Both addresses are required; this function does not itself
// validate that they are well-formed Monero/Tari addresses (that is
// the HTTP handler's job -- see internal/backend/addressmap -- so
// this repository layer stays a thin, reusable persistence
// primitive).
func (r *Repository) SetAddressMap(ctx context.Context, xmrAddress, tariAddress string) error {
	if xmrAddress == "" {
		return fmt.Errorf("db: SetAddressMap: xmr_address is required")
	}
	if tariAddress == "" {
		return fmt.Errorf("db: SetAddressMap: tari_address is required")
	}

	const stmt = `
		INSERT INTO address_map (xmr_address, tari_address)
		VALUES ($1, $2)
		ON CONFLICT (xmr_address)
		DO NOTHING`
	tag, err := r.pool.Exec(ctx, stmt, xmrAddress, tariAddress)
	if err != nil {
		return fmt.Errorf("db: inserting address_map for %s: %w", xmrAddress, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAddressAlreadyMapped
	}
	return nil
}

// GetAddressMap returns the mapping row for xmrAddress, or
// ErrAddressMapNotFound if none exists.
func (r *Repository) GetAddressMap(ctx context.Context, xmrAddress string) (AddressMap, error) {
	if xmrAddress == "" {
		return AddressMap{}, fmt.Errorf("db: GetAddressMap: xmr_address is required")
	}

	const stmt = `
		SELECT xmr_address, tari_address, created_at, updated_at
		FROM address_map
		WHERE xmr_address = $1`
	var m AddressMap
	err := r.pool.QueryRow(ctx, stmt, xmrAddress).Scan(&m.XMRAddress, &m.TariAddress, &m.CreatedAt, &m.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AddressMap{}, ErrAddressMapNotFound
		}
		return AddressMap{}, fmt.Errorf("db: querying address_map for %s: %w", xmrAddress, err)
	}
	return m, nil
}
