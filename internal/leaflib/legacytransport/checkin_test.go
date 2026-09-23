// Copyright and license: see repository LICENSE (MIT).
package legacytransport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeTipSource struct{ height uint64 }

func (f fakeTipSource) LatestHeight() uint64 { return f.height }

type fakePortCounter struct{ counts map[int]int }

func (f fakePortCounter) PortMinerCounts() map[int]int { return f.counts }

func TestCheckin_PostOnce_SendsExactJSONShapeAndHeaders(t *testing.T) {
	var (
		gotPath   string
		gotMethod string
		gotAuth   string
		gotCT     string
		gotBody   checkinBody
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotAuth = r.Header.Get("x-pool-auth")
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()

	c, err := NewCheckin(CheckinConfig{
		APIURL:    srv.URL + "/poolApi/",
		AuthToken: "the-real-api-auth-token",
		PoolID:    7,
		Interval:  time.Second,
	})
	if err != nil {
		t.Fatalf("NewCheckin: %v", err)
	}

	before := time.Now().UnixMilli()
	if err := c.postOnce(context.Background(), fakeTipSource{height: 123456}, fakePortCounter{counts: map[int]int{4444: 12, 4443: 3}}); err != nil {
		t.Fatalf("postOnce: %v", err)
	}
	after := time.Now().UnixMilli()

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/poolApi/poolCheckin" {
		t.Errorf("path = %q, want /poolApi/poolCheckin", gotPath)
	}
	if gotAuth != "the-real-api-auth-token" {
		t.Errorf("x-pool-auth header = %q, want %q", gotAuth, "the-real-api-auth-token")
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if gotBody.PoolID != 7 {
		t.Errorf("pool_id = %d, want 7", gotBody.PoolID)
	}
	if gotBody.BlockID != 123456 {
		t.Errorf("block_id = %d, want 123456", gotBody.BlockID)
	}
	if gotBody.Ports[4444] != 12 || gotBody.Ports[4443] != 3 {
		t.Errorf("ports = %v, want map[4444:12 4443:3]", gotBody.Ports)
	}
	// current_time must be real Unix MILLISECONDS (matching the real
	// legacy sender's JS +new Date()), not seconds.
	if gotBody.CurrentTime < before || gotBody.CurrentTime > after {
		t.Errorf("current_time = %d, want within [%d, %d] (Unix milliseconds)", gotBody.CurrentTime, before, after)
	}
}

func TestCheckin_PostOnce_NonOKStatusIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"bad auth"}`))
	}))
	defer srv.Close()

	c, err := NewCheckin(CheckinConfig{APIURL: srv.URL, AuthToken: "tok", PoolID: 1, Interval: time.Second})
	if err != nil {
		t.Fatalf("NewCheckin: %v", err)
	}

	if err := c.postOnce(context.Background(), fakeTipSource{}, fakePortCounter{}); err == nil {
		t.Fatal("postOnce: expected an error for a non-2xx response, got nil")
	}
}

func TestCheckin_Run_FiresOnEveryTickUntilCancelled(t *testing.T) {
	hits := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewCheckin(CheckinConfig{APIURL: srv.URL, AuthToken: "tok", PoolID: 1, Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewCheckin: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, fakeTipSource{}, fakePortCounter{})
		close(done)
	}()

	// Expect at least two ticks within a generous bound.
	timeout := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-hits:
		case <-timeout:
			t.Fatal("Run did not fire the expected number of checkin ticks in time")
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after ctx cancellation")
	}
}

func TestNewCheckin_RequiresAllFields(t *testing.T) {
	cases := []CheckinConfig{
		{APIURL: "", AuthToken: "tok", PoolID: 1},
		{APIURL: "http://x", AuthToken: "", PoolID: 1},
		{APIURL: "http://x", AuthToken: "tok", PoolID: 0},
		{APIURL: "http://x", AuthToken: "tok", PoolID: -1},
	}
	for i, cfg := range cases {
		if _, err := NewCheckin(cfg); err == nil {
			t.Errorf("case %d: NewCheckin(%+v): expected an error, got nil", i, cfg)
		}
	}
}
