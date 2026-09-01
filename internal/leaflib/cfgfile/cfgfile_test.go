// Copyright and license: see repository LICENSE (MIT).
package cfgfile

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDecode(t *testing.T) {
	type cfg struct {
		Name    *string `toml:"name"`
		Count   *int    `toml:"count"`
		Enabled *bool   `toml:"enabled"`
	}

	t.Run("happy path", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "cfg.toml")
		writeFile(t, path, "name = \"pool1\"\ncount = 42\nenabled = true\n")

		var dst cfg
		if err := Decode(path, &dst); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dst.Name == nil || *dst.Name != "pool1" {
			t.Errorf("Name = %v, want pool1", dst.Name)
		}
		if dst.Count == nil || *dst.Count != 42 {
			t.Errorf("Count = %v, want 42", dst.Count)
		}
		if dst.Enabled == nil || *dst.Enabled != true {
			t.Errorf("Enabled = %v, want true", dst.Enabled)
		}
	})

	t.Run("empty path is a no-op", func(t *testing.T) {
		dst := cfg{}
		if err := Decode("", &dst); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dst.Name != nil || dst.Count != nil || dst.Enabled != nil {
			t.Errorf("dst should be left untouched, got %+v", dst)
		}
	})

	t.Run("nonexistent file returns an error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "does-not-exist.toml")

		var dst cfg
		err := Decode(path, &dst)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})

	t.Run("malformed TOML returns an error", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bad.toml")
		writeFile(t, path, "this is not = = valid toml [[[")

		var dst cfg
		err := Decode(path, &dst)
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
	})
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("writing test fixture %s: %v", path, err)
	}
}

func TestVisitedFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	foo := fs.String("foo", "default-foo", "")
	bar := fs.Int("bar", 0, "")
	baz := fs.Bool("baz", false, "")
	_ = foo
	_ = bar
	_ = baz

	if err := fs.Parse([]string{"-foo", "explicit-value"}); err != nil {
		t.Fatalf("parse: %v", err)
	}

	visited := VisitedFlags(fs)

	if !visited["foo"] {
		t.Errorf("expected foo to be reported as visited")
	}
	if visited["bar"] {
		t.Errorf("expected bar (left at default) to NOT be reported as visited")
	}
	if visited["baz"] {
		t.Errorf("expected baz (left at default) to NOT be reported as visited")
	}
	if len(visited) != 1 {
		t.Errorf("expected exactly 1 visited flag, got %d: %v", len(visited), visited)
	}
}

func TestShouldApplyFile(t *testing.T) {
	tests := []struct {
		name         string
		explicitFlag bool
		explicitEnv  bool
		want         bool
	}{
		{name: "neither explicit", explicitFlag: false, explicitEnv: false, want: true},
		{name: "flag explicit only", explicitFlag: true, explicitEnv: false, want: false},
		{name: "env explicit only", explicitFlag: false, explicitEnv: true, want: false},
		{name: "both explicit", explicitFlag: true, explicitEnv: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := Source{ExplicitFlag: tt.explicitFlag, ExplicitEnv: tt.explicitEnv}
			got := ShouldApplyFile(src)
			if got != tt.want {
				t.Errorf("ShouldApplyFile(%+v) = %v, want %v", src, got, tt.want)
			}
		})
	}
}

func TestFieldSource(t *testing.T) {
	t.Run("flag visited, env unset", func(t *testing.T) {
		visited := map[string]bool{"foo": true}
		src := FieldSource(visited, "foo", "FOO_ENV_UNSET_ABCXYZ")
		if !src.ExplicitFlag {
			t.Errorf("expected ExplicitFlag = true")
		}
		if src.ExplicitEnv {
			t.Errorf("expected ExplicitEnv = false")
		}
	})

	t.Run("flag not visited, env unset", func(t *testing.T) {
		visited := map[string]bool{}
		src := FieldSource(visited, "foo", "FOO_ENV_UNSET_ABCXYZ")
		if src.ExplicitFlag {
			t.Errorf("expected ExplicitFlag = false")
		}
		if src.ExplicitEnv {
			t.Errorf("expected ExplicitEnv = false")
		}
	})

	t.Run("flag not visited, env set non-empty", func(t *testing.T) {
		t.Setenv("CFGFILE_TEST_ENV", "some-value")
		visited := map[string]bool{}
		src := FieldSource(visited, "foo", "CFGFILE_TEST_ENV")
		if src.ExplicitFlag {
			t.Errorf("expected ExplicitFlag = false")
		}
		if !src.ExplicitEnv {
			t.Errorf("expected ExplicitEnv = true")
		}
	})

	t.Run("flag not visited, env set empty", func(t *testing.T) {
		t.Setenv("CFGFILE_TEST_ENV_EMPTY", "")
		visited := map[string]bool{}
		src := FieldSource(visited, "foo", "CFGFILE_TEST_ENV_EMPTY")
		if src.ExplicitEnv {
			t.Errorf("expected ExplicitEnv = false for empty env var")
		}
	})

	t.Run("both flag visited and env set", func(t *testing.T) {
		t.Setenv("CFGFILE_TEST_ENV_BOTH", "value")
		visited := map[string]bool{"foo": true}
		src := FieldSource(visited, "foo", "CFGFILE_TEST_ENV_BOTH")
		if !src.ExplicitFlag || !src.ExplicitEnv {
			t.Errorf("expected both explicit, got %+v", src)
		}
	})
}

func TestApplyString(t *testing.T) {
	fileVal := "from-file"

	t.Run("fileVal nil is a no-op", func(t *testing.T) {
		dst := "default"
		ApplyString(&dst, nil, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != "default" {
			t.Errorf("dst = %q, want %q", dst, "default")
		}
	})

	t.Run("neither explicit applies file value", func(t *testing.T) {
		dst := "default"
		ApplyString(&dst, &fileVal, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != fileVal {
			t.Errorf("dst = %q, want %q", dst, fileVal)
		}
	})

	t.Run("flag explicit leaves dst untouched", func(t *testing.T) {
		dst := "default"
		visited := map[string]bool{"flag": true}
		ApplyString(&dst, &fileVal, visited, "flag", "ENV_UNSET_ABCXYZ")
		if dst != "default" {
			t.Errorf("dst = %q, want %q (untouched)", dst, "default")
		}
	})

	t.Run("env explicit leaves dst untouched", func(t *testing.T) {
		t.Setenv("APPLY_STRING_ENV", "set")
		dst := "default"
		ApplyString(&dst, &fileVal, map[string]bool{}, "flag", "APPLY_STRING_ENV")
		if dst != "default" {
			t.Errorf("dst = %q, want %q (untouched)", dst, "default")
		}
	})
}

func TestApplyInt(t *testing.T) {
	fileVal := 42

	t.Run("fileVal nil is a no-op", func(t *testing.T) {
		dst := 1
		ApplyInt(&dst, nil, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1 {
			t.Errorf("dst = %d, want %d", dst, 1)
		}
	})

	t.Run("neither explicit applies file value", func(t *testing.T) {
		dst := 1
		ApplyInt(&dst, &fileVal, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != fileVal {
			t.Errorf("dst = %d, want %d", dst, fileVal)
		}
	})

	t.Run("flag explicit leaves dst untouched", func(t *testing.T) {
		dst := 1
		visited := map[string]bool{"flag": true}
		ApplyInt(&dst, &fileVal, visited, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1 {
			t.Errorf("dst = %d, want %d (untouched)", dst, 1)
		}
	})

	t.Run("env explicit leaves dst untouched", func(t *testing.T) {
		t.Setenv("APPLY_INT_ENV", "set")
		dst := 1
		ApplyInt(&dst, &fileVal, map[string]bool{}, "flag", "APPLY_INT_ENV")
		if dst != 1 {
			t.Errorf("dst = %d, want %d (untouched)", dst, 1)
		}
	})
}

func TestApplyInt64(t *testing.T) {
	var fileVal int64 = 9999999999

	t.Run("fileVal nil is a no-op", func(t *testing.T) {
		var dst int64 = 1
		ApplyInt64(&dst, nil, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1 {
			t.Errorf("dst = %d, want %d", dst, 1)
		}
	})

	t.Run("neither explicit applies file value", func(t *testing.T) {
		var dst int64 = 1
		ApplyInt64(&dst, &fileVal, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != fileVal {
			t.Errorf("dst = %d, want %d", dst, fileVal)
		}
	})

	t.Run("flag explicit leaves dst untouched", func(t *testing.T) {
		var dst int64 = 1
		visited := map[string]bool{"flag": true}
		ApplyInt64(&dst, &fileVal, visited, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1 {
			t.Errorf("dst = %d, want %d (untouched)", dst, 1)
		}
	})

	t.Run("env explicit leaves dst untouched", func(t *testing.T) {
		t.Setenv("APPLY_INT64_ENV", "set")
		var dst int64 = 1
		ApplyInt64(&dst, &fileVal, map[string]bool{}, "flag", "APPLY_INT64_ENV")
		if dst != 1 {
			t.Errorf("dst = %d, want %d (untouched)", dst, 1)
		}
	})
}

func TestApplyUint64(t *testing.T) {
	var fileVal uint64 = 123456789

	t.Run("fileVal nil is a no-op", func(t *testing.T) {
		var dst uint64 = 1
		ApplyUint64(&dst, nil, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1 {
			t.Errorf("dst = %d, want %d", dst, 1)
		}
	})

	t.Run("neither explicit applies file value", func(t *testing.T) {
		var dst uint64 = 1
		ApplyUint64(&dst, &fileVal, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != fileVal {
			t.Errorf("dst = %d, want %d", dst, fileVal)
		}
	})

	t.Run("flag explicit leaves dst untouched", func(t *testing.T) {
		var dst uint64 = 1
		visited := map[string]bool{"flag": true}
		ApplyUint64(&dst, &fileVal, visited, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1 {
			t.Errorf("dst = %d, want %d (untouched)", dst, 1)
		}
	})

	t.Run("env explicit leaves dst untouched", func(t *testing.T) {
		t.Setenv("APPLY_UINT64_ENV", "set")
		var dst uint64 = 1
		ApplyUint64(&dst, &fileVal, map[string]bool{}, "flag", "APPLY_UINT64_ENV")
		if dst != 1 {
			t.Errorf("dst = %d, want %d (untouched)", dst, 1)
		}
	})
}

func TestApplyBool(t *testing.T) {
	fileVal := true

	t.Run("fileVal nil is a no-op", func(t *testing.T) {
		dst := false
		ApplyBool(&dst, nil, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != false {
			t.Errorf("dst = %v, want %v", dst, false)
		}
	})

	t.Run("neither explicit applies file value", func(t *testing.T) {
		dst := false
		ApplyBool(&dst, &fileVal, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != fileVal {
			t.Errorf("dst = %v, want %v", dst, fileVal)
		}
	})

	t.Run("flag explicit leaves dst untouched", func(t *testing.T) {
		dst := false
		visited := map[string]bool{"flag": true}
		ApplyBool(&dst, &fileVal, visited, "flag", "ENV_UNSET_ABCXYZ")
		if dst != false {
			t.Errorf("dst = %v, want %v (untouched)", dst, false)
		}
	})

	t.Run("env explicit leaves dst untouched", func(t *testing.T) {
		t.Setenv("APPLY_BOOL_ENV", "set")
		dst := false
		ApplyBool(&dst, &fileVal, map[string]bool{}, "flag", "APPLY_BOOL_ENV")
		if dst != false {
			t.Errorf("dst = %v, want %v (untouched)", dst, false)
		}
	})
}

func TestApplyDuration(t *testing.T) {
	fileVal := 5 * time.Minute

	t.Run("fileVal nil is a no-op", func(t *testing.T) {
		dst := time.Second
		ApplyDuration(&dst, nil, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != time.Second {
			t.Errorf("dst = %v, want %v", dst, time.Second)
		}
	})

	t.Run("neither explicit applies file value", func(t *testing.T) {
		dst := time.Second
		ApplyDuration(&dst, &fileVal, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != fileVal {
			t.Errorf("dst = %v, want %v", dst, fileVal)
		}
	})

	t.Run("flag explicit leaves dst untouched", func(t *testing.T) {
		dst := time.Second
		visited := map[string]bool{"flag": true}
		ApplyDuration(&dst, &fileVal, visited, "flag", "ENV_UNSET_ABCXYZ")
		if dst != time.Second {
			t.Errorf("dst = %v, want %v (untouched)", dst, time.Second)
		}
	})

	t.Run("env explicit leaves dst untouched", func(t *testing.T) {
		t.Setenv("APPLY_DURATION_ENV", "set")
		dst := time.Second
		ApplyDuration(&dst, &fileVal, map[string]bool{}, "flag", "APPLY_DURATION_ENV")
		if dst != time.Second {
			t.Errorf("dst = %v, want %v (untouched)", dst, time.Second)
		}
	})
}

func TestApplyFloat64(t *testing.T) {
	fileVal := 3.14

	t.Run("fileVal nil is a no-op", func(t *testing.T) {
		dst := 1.0
		ApplyFloat64(&dst, nil, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1.0 {
			t.Errorf("dst = %v, want %v", dst, 1.0)
		}
	})

	t.Run("neither explicit applies file value", func(t *testing.T) {
		dst := 1.0
		ApplyFloat64(&dst, &fileVal, map[string]bool{}, "flag", "ENV_UNSET_ABCXYZ")
		if dst != fileVal {
			t.Errorf("dst = %v, want %v", dst, fileVal)
		}
	})

	t.Run("flag explicit leaves dst untouched", func(t *testing.T) {
		dst := 1.0
		visited := map[string]bool{"flag": true}
		ApplyFloat64(&dst, &fileVal, visited, "flag", "ENV_UNSET_ABCXYZ")
		if dst != 1.0 {
			t.Errorf("dst = %v, want %v (untouched)", dst, 1.0)
		}
	})

	t.Run("env explicit leaves dst untouched", func(t *testing.T) {
		t.Setenv("APPLY_FLOAT64_ENV", "set")
		dst := 1.0
		ApplyFloat64(&dst, &fileVal, map[string]bool{}, "flag", "APPLY_FLOAT64_ENV")
		if dst != 1.0 {
			t.Errorf("dst = %v, want %v (untouched)", dst, 1.0)
		}
	})
}
