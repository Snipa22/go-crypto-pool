package api

import "testing"

func TestNewHandler(t *testing.T) {
	if h := NewHandler(); h == nil {
		t.Fatal("NewHandler returned nil")
	}
}
