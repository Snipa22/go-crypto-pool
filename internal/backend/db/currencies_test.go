package db_test

// Unit tests (no Postgres required) for db.ValidCurrencies/
// db.ValidateCurrency's widened set — see fix #2 in payoutbrief.md:
// these must accept every internal/coinprofile.Registry ticker (in
// addition to the two pre-existing legacy values XMR/XTM), with no
// duplicate entries even though "XMR" legitimately appears in both
// the legacy set and Registry (see db.buildValidCurrencies' own doc
// comment for why that overlap is intentional).

import (
	"testing"

	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	"github.com/Snipa22/go-crypto-pool/internal/coinprofile"
)

func TestValidCurrenciesIncludesEveryCoinProfileTicker(t *testing.T) {
	set := make(map[string]bool, len(db.ValidCurrencies))
	for _, c := range db.ValidCurrencies {
		if set[c] {
			t.Errorf("db.ValidCurrencies contains a duplicate entry %q: %v", c, db.ValidCurrencies)
		}
		set[c] = true
	}

	// The two fixed legacy values must still be present.
	for _, want := range []string{"XMR", "XTM"} {
		if !set[want] {
			t.Errorf("db.ValidCurrencies is missing the legacy value %q: %v", want, db.ValidCurrencies)
		}
	}

	// Every internal/coinprofile.Registry entry's own Ticker must be
	// present -- this is the actual fix: before it, ARQ/XEQ/GRFT/
	// SFX/ZEPH/SAL (and, redundantly but harmlessly, XMR) were absent
	// and any CreditBalance call using one of those currencies would
	// have failed the CHECK constraint (once migration 0017 is
	// applied) or been silently invalid (before ValidateCurrency knew
	// about them at all).
	for _, profile := range coinprofile.Registry {
		if !set[profile.Ticker] {
			t.Errorf("db.ValidCurrencies is missing coinprofile.Registry ticker %q: %v", profile.Ticker, db.ValidCurrencies)
		}
	}

	// Sanity: exactly 2 fixed + 7 registry tickers, minus the 1
	// intentional XMR overlap = 8 distinct values total.
	if len(set) != 2+len(coinprofile.Registry)-1 {
		t.Errorf("db.ValidCurrencies has %d distinct entries, want %d (2 legacy + %d registry tickers - 1 intentional XMR overlap): %v",
			len(set), 2+len(coinprofile.Registry)-1, len(coinprofile.Registry), db.ValidCurrencies)
	}
}

func TestValidateCurrencyAcceptsEveryCoinProfileTicker(t *testing.T) {
	for _, profile := range coinprofile.Registry {
		if err := db.ValidateCurrency(profile.Ticker); err != nil {
			t.Errorf("ValidateCurrency(%q): %v, want accepted", profile.Ticker, err)
		}
	}
	if err := db.ValidateCurrency("XMR"); err != nil {
		t.Errorf("ValidateCurrency(%q): %v, want accepted", "XMR", err)
	}
	if err := db.ValidateCurrency("XTM"); err != nil {
		t.Errorf("ValidateCurrency(%q): %v, want accepted", "XTM", err)
	}
	if err := db.ValidateCurrency("BTC"); err == nil {
		t.Error("ValidateCurrency(\"BTC\") succeeded, want rejected (not a real currency this schema tracks)")
	}
}
