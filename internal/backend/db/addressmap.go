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

// UpsertAddressMap inserts a new xmrAddress -> tariAddress mapping, or
// updates the existing one (stamping updated_at) if xmrAddress
// already has a row -- see uq_address_map_xmr_address, which is what
// makes ON CONFLICT well-defined here. Both addresses are required;
// this function does not itself validate that they are well-formed
// Monero/Tari addresses (that is the HTTP handler's job -- see
// internal/backend/addressmap -- so this repository layer stays a
// thin, reusable persistence primitive).
func (r *Repository) UpsertAddressMap(ctx context.Context, xmrAddress, tariAddress string) error {
	if xmrAddress == "" {
		return fmt.Errorf("db: UpsertAddressMap: xmr_address is required")
	}
	if tariAddress == "" {
		return fmt.Errorf("db: UpsertAddressMap: tari_address is required")
	}

	const stmt = `
		INSERT INTO address_map (xmr_address, tari_address)
		VALUES ($1, $2)
		ON CONFLICT (xmr_address)
		DO UPDATE SET tari_address = EXCLUDED.tari_address, updated_at = now()`
	if _, err := r.pool.Exec(ctx, stmt, xmrAddress, tariAddress); err != nil {
		return fmt.Errorf("db: upserting address_map for %s: %w", xmrAddress, err)
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
