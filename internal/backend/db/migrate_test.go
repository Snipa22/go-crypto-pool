package db

// Unit tests for isAlreadyExistsError (see migrate.go) that don't
// need a real Postgres connection -- unlike migrate_integration_test.go's
// TestIntegrationApplyMigrations* (package db_test, require
// GCPOOL_TEST_DSN), these run unconditionally as part of `go test
// ./...` in package db itself, since isAlreadyExistsError is
// unexported.

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// TestIsAlreadyExistsError_MatchesKnownDuplicateObjectCodes is the
// regression test for PROD_HARDENING_REVIEW.md finding #20: only the
// specific Postgres SQLSTATE codes a migration's own DDL can actually
// produce for "this object already exists" must be treated as the
// backfill signal.
func TestIsAlreadyExistsError_MatchesKnownDuplicateObjectCodes(t *testing.T) {
	cases := []struct {
		name string
		code string
		want bool
	}{
		{"duplicate_table (CREATE TABLE/INDEX)", "42P07", true},
		{"duplicate_column (ALTER TABLE ADD COLUMN)", "42701", true},
		{"duplicate_object (ADD CONSTRAINT)", "42710", true},
		{"unrelated_code (syntax_error)", "42601", false},
		{"unrelated_code (undefined_table)", "42P01", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &pgconn.PgError{Code: tc.code, Message: "some message"}
			if got := isAlreadyExistsError(err); got != tc.want {
				t.Errorf("isAlreadyExistsError(code=%s) = %v, want %v", tc.code, got, tc.want)
			}
		})
	}
}

// TestIsAlreadyExistsError_DoesNotSubstringMatchUnrelatedErrors is
// the real regression case the loose `strings.Contains(err.Error(),
// "already exists")` fallback this replaced could misclassify: a
// genuinely-different Postgres error (e.g. "role ... already
// exists", nothing to do with the migration's own table/column/
// constraint) must NOT be treated as "this migration was already
// applied".
func TestIsAlreadyExistsError_DoesNotSubstringMatchUnrelatedErrors(t *testing.T) {
	// duplicate_object's SQLSTATE class is 42, but a role-already-
	// exists error is reported as SQLSTATE 42710 too in some
	// Postgres versions for CREATE ROLE -- to prove this is a
	// genuine non-substring-based decision (not an accidental
	// string match), use a totally unrelated code with "already
	// exists" in its message text.
	err := &pgconn.PgError{Code: "23505", Message: `duplicate key value violates unique constraint "already exists in a sense"`}
	if isAlreadyExistsError(err) {
		t.Errorf("isAlreadyExistsError must not match an unrelated SQLSTATE (23505) even if its message text contains \"already exists\"")
	}
}

// TestIsAlreadyExistsError_NonPgError confirms a plain, non-Postgres
// error (e.g. a network failure) is never treated as the backfill
// signal.
func TestIsAlreadyExistsError_NonPgError(t *testing.T) {
	if isAlreadyExistsError(errors.New("some other error: already exists")) {
		t.Error("isAlreadyExistsError must not match a plain error that isn't a *pgconn.PgError, even with matching text")
	}
}
