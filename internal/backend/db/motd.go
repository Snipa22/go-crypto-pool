// motd.go implements the backend's persistence for `motd` (see
// migrations/0007_users_motd.up.sql): the SXMR-legacy message-of-the-
// day system's single-newest-row-wins table, consumed by
// internal/backend/legacyconfig's GET /pool/motd.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Motd is one `motd` row.
type Motd struct {
	ID      int64
	Created time.Time
	Subject string
	Body    string
	Type    string
	Active  bool
}

// ErrMotdNotFound is returned by LatestMotd when the `motd` table has
// no rows at all.
var ErrMotdNotFound = errors.New("db: motd: no rows")

// LatestMotd returns the newest (highest id) `motd` row, mirroring
// legacy's exact query shape (`select created, subject, body, type,
// active from motd order by id desc limit 1`). Returns ErrMotdNotFound
// if the table is empty -- not itself an error condition for the
// caller (see legacyconfig.Handler.handleMotd, which renders that as
// `200 {}`, same as an explicitly inactive row).
func (r *Repository) LatestMotd(ctx context.Context) (Motd, error) {
	const stmt = `SELECT id, created, subject, body, type, active FROM motd ORDER BY id DESC LIMIT 1`
	var m Motd
	err := r.pool.QueryRow(ctx, stmt).Scan(&m.ID, &m.Created, &m.Subject, &m.Body, &m.Type, &m.Active)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Motd{}, ErrMotdNotFound
		}
		return Motd{}, fmt.Errorf("db: querying motd: %w", err)
	}
	return m, nil
}
