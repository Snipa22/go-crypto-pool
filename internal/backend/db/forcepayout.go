// forcepayout.go implements the backend's persistence for `balance`'s
// `force_payout` column (see
// migrations/0008_balance_force_payout.up.sql): the real-schema
// replacement for legacy's POST /user/forcePayment Redis
// `earlyPayout` queue push. See that migration's doc comment for the
// full rationale and this change's explicit scope (setting the flag
// only -- internal/backend/disburse does not yet consume it as a
// priority signal).
package db

import (
	"context"
	"errors"
	"fmt"
)

// ErrBalanceNotFound is returned by SetForcePayout when no `balance`
// row matches (algo, network, paymentAddress, paymentID) with a
// positive pending_balance -- i.e. either no such balance row exists
// at all, or it exists but has nothing pending to pay out. Legacy's
// own forcePayment path conflates these two cases into a single
// failure response (see brief-auth.md's transcription: "rejects if
// balance too low" and "No matching balance: 400" are both surfaced
// identically by internal/backend/authapi's handler), so this
// repository layer does not itself distinguish them either.
var ErrBalanceNotFound = errors.New("db: balance: no payable row for that identity")

// SetForcePayout flags the `balance` row identified by (algo, network,
// paymentAddress, paymentID) with force_payout = TRUE, but only if
// that row exists AND its pending_balance > 0 (this backend's stated,
// explicit equivalent of legacy's raw atomic-unit payout-threshold
// constant -- see that migration's doc comment). Returns
// ErrBalanceNotFound if no row satisfies both conditions.
func (r *Repository) SetForcePayout(ctx context.Context, algo, network, paymentAddress string, paymentID *string) error {
	if err := ValidateAlgo(algo); err != nil {
		return err
	}
	if err := ValidateNetwork(network); err != nil {
		return err
	}
	if paymentAddress == "" {
		return fmt.Errorf("db: SetForcePayout: payment_address is required")
	}

	const stmt = `
		UPDATE balance
		SET force_payout = TRUE, updated_at = now()
		WHERE algo = $1 AND network = $2 AND payment_address = $3
		  AND COALESCE(payment_id, '') = COALESCE($4, '')
		  AND pending_balance > 0`
	tag, err := r.pool.Exec(ctx, stmt, algo, network, paymentAddress, paymentID)
	if err != nil {
		return fmt.Errorf("db: setting force_payout for %q: %w", paymentAddress, err)
	}
	if tag.RowsAffected() == 0 {
		return ErrBalanceNotFound
	}
	return nil
}
