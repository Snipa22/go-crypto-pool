// Copyright and license: see repository LICENSE (MIT).

// Package cfgfile is the shared, binary-agnostic helper library behind
// each of the 4 cmd binaries' (backend, leaf-solo, leaf-direct,
// leaf-proxy) "-config <file.toml>" flag. It is intentionally generic
// and reusable rather than 4x duplicated merge logic: this package
// owns TOML decoding and the flag/env/file precedence rule; each
// binary's own per-field TOML struct (with pointer fields so an
// absent key decodes to nil) lives in that binary's own cmd/<binary>/
// main.go, not here.
//
// Precedence order, highest to lowest:
//
//  1. an explicit CLI flag (the operator actually passed -foo=bar)
//  2. an explicit, non-empty environment variable
//  3. a value present in the config file
//  4. the binary's hardcoded default (whatever the field already
//     held before any of this package's Apply* helpers ran)
//
// The whole point of this package is that a config-file value for a
// field is applied ONLY when NEITHER an explicit CLI flag NOR an
// explicit environment variable were set by the operator for that
// same field -- see ShouldApplyFile and the ApplyXxx family below.
package cfgfile

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Decode parses the TOML file at path into dst (a pointer to a struct
// whose fields are tagged with `toml:"key_name"`). If path == "",
// Decode is a no-op and returns nil (no file configured is not an
// error). If the file does not exist, cannot be read, or fails to
// parse as TOML, Decode returns a wrapped error identifying path.
func Decode(path string, dst any) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("cfgfile: reading %s: %w", path, err)
	}

	if err := toml.Unmarshal(data, dst); err != nil {
		return fmt.Errorf("cfgfile: parsing %s: %w", path, err)
	}

	return nil
}

// VisitedFlags returns the set of flag names that were explicitly
// passed on the command line for fs (call this AFTER fs.Parse(...),
// typically with flag.CommandLine). Uses fs.Visit, which -- per the
// flag package's own docs -- only visits flags that were actually set
// on the command line, not flags merely left at their default/zero
// value.
func VisitedFlags(fs *flag.FlagSet) map[string]bool {
	visited := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	return visited
}

// Source describes, for one config field, whether it was explicitly
// set outside the config file (by an actual CLI flag or a non-empty
// environment variable). Precedence rule (this is the whole point of
// the package): a config-file value for a field is applied ONLY when
// BOTH ExplicitFlag and ExplicitEnv are false -- i.e. explicit CLI
// flag > explicit env var > config file > hardcoded default.
type Source struct {
	ExplicitFlag bool
	ExplicitEnv  bool
}

// ShouldApplyFile reports whether a config-file value should override
// the in-memory default for a field, given src.
func ShouldApplyFile(src Source) bool {
	return !src.ExplicitFlag && !src.ExplicitEnv
}

// FieldSource is a small constructor helper: given the flag name, the
// env var name, and the already-computed `visited` set (from
// VisitedFlags), builds the Source for that field by checking
// visited[flagName] and os.Getenv(envVar) != "".
func FieldSource(visited map[string]bool, flagName, envVar string) Source {
	return Source{
		ExplicitFlag: visited[flagName],
		ExplicitEnv:  os.Getenv(envVar) != "",
	}
}

// ApplyString mutates *dst in place to *fileVal, but ONLY when
// fileVal != nil AND ShouldApplyFile(FieldSource(visited, flagName,
// envVar)) is true. Otherwise it is a no-op.
func ApplyString(dst *string, fileVal *string, visited map[string]bool, flagName, envVar string) {
	if fileVal == nil {
		return
	}
	if !ShouldApplyFile(FieldSource(visited, flagName, envVar)) {
		return
	}
	*dst = *fileVal
}

// ApplyInt mutates *dst in place to *fileVal, but ONLY when fileVal !=
// nil AND ShouldApplyFile(FieldSource(visited, flagName, envVar)) is
// true. Otherwise it is a no-op.
func ApplyInt(dst *int, fileVal *int, visited map[string]bool, flagName, envVar string) {
	if fileVal == nil {
		return
	}
	if !ShouldApplyFile(FieldSource(visited, flagName, envVar)) {
		return
	}
	*dst = *fileVal
}

// ApplyInt64 mutates *dst in place to *fileVal, but ONLY when fileVal
// != nil AND ShouldApplyFile(FieldSource(visited, flagName, envVar))
// is true. Otherwise it is a no-op.
func ApplyInt64(dst *int64, fileVal *int64, visited map[string]bool, flagName, envVar string) {
	if fileVal == nil {
		return
	}
	if !ShouldApplyFile(FieldSource(visited, flagName, envVar)) {
		return
	}
	*dst = *fileVal
}

// ApplyUint64 mutates *dst in place to *fileVal, but ONLY when fileVal
// != nil AND ShouldApplyFile(FieldSource(visited, flagName, envVar))
// is true. Otherwise it is a no-op.
func ApplyUint64(dst *uint64, fileVal *uint64, visited map[string]bool, flagName, envVar string) {
	if fileVal == nil {
		return
	}
	if !ShouldApplyFile(FieldSource(visited, flagName, envVar)) {
		return
	}
	*dst = *fileVal
}

// ApplyBool mutates *dst in place to *fileVal, but ONLY when fileVal
// != nil AND ShouldApplyFile(FieldSource(visited, flagName, envVar))
// is true. Otherwise it is a no-op.
func ApplyBool(dst *bool, fileVal *bool, visited map[string]bool, flagName, envVar string) {
	if fileVal == nil {
		return
	}
	if !ShouldApplyFile(FieldSource(visited, flagName, envVar)) {
		return
	}
	*dst = *fileVal
}

// ApplyDuration mutates *dst in place to *fileVal, but ONLY when
// fileVal != nil AND ShouldApplyFile(FieldSource(visited, flagName,
// envVar)) is true. Otherwise it is a no-op.
func ApplyDuration(dst *time.Duration, fileVal *time.Duration, visited map[string]bool, flagName, envVar string) {
	if fileVal == nil {
		return
	}
	if !ShouldApplyFile(FieldSource(visited, flagName, envVar)) {
		return
	}
	*dst = *fileVal
}

// ApplyFloat64 mutates *dst in place to *fileVal, but ONLY when
// fileVal != nil AND ShouldApplyFile(FieldSource(visited, flagName,
// envVar)) is true. Otherwise it is a no-op.
func ApplyFloat64(dst *float64, fileVal *float64, visited map[string]bool, flagName, envVar string) {
	if fileVal == nil {
		return
	}
	if !ShouldApplyFile(FieldSource(visited, flagName, envVar)) {
		return
	}
	*dst = *fileVal
}
