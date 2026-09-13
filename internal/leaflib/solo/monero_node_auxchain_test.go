// Copyright and license: see repository LICENSE (MIT).
package solo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMoneroNodeClient_SubmitBlockAuxChains_NoAuxData covers a
// submit_block response with NO "_aux" key at all -- e.g. a bare
// monerod, or a merge-mining proxy whose secondary chain target was
// not cleared on this submission. auxChains must come back empty,
// with no error (the primary submission itself succeeded).
func TestMoneroNodeClient_SubmitBlockAuxChains_NoAuxData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","untrusted":false}}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), &MoneroCandidate{TemplateBlob: []byte{0x01, 0x02}})
	if err != nil {
		t.Fatalf("SubmitBlockAuxChains: unexpected error: %v", err)
	}
	if len(auxChains) != 0 {
		t.Fatalf("SubmitBlockAuxChains: got %d aux chains, want 0: %+v", len(auxChains), auxChains)
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_WithAuxData covers the
// REAL wire shape confirmed against tari-project/tari's own source
// (applications/minotari_merge_mining_proxy/src/proxy/inner.rs,
// handle_submit_block, and src/proxy/utils.rs,
// append_aux_chain_data/MMPROXY_AUX_KEY_NAME): a successful
// submit_block response gains a "_aux":{"chains":[...]} object whose
// array gains an entry shaped {"id": "xtr", "block_hash": "<hex>"}
// when the merge-mined chain (Tari) also cleared its own real target
// and its base node accepted the resulting block. The array also
// carries a template-request-time entry (difficulty/height/
// mining_hash/miner_reward, no block_hash) for the SAME chain, which
// must NOT be misinterpreted as a second acceptance.
func TestMoneroNodeClient_SubmitBlockAuxChains_WithAuxData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{
			"status":"OK",
			"untrusted":false,
			"_aux":{"chains":[
				{"id":"xtr","difficulty":1000,"height":42,"mining_hash":"deadbeef","miner_reward":123},
				{"id":"xtr","block_hash":"aabbccdd"}
			]}
		}}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), &MoneroCandidate{TemplateBlob: []byte{0x01, 0x02}})
	if err != nil {
		t.Fatalf("SubmitBlockAuxChains: unexpected error: %v", err)
	}
	if len(auxChains) != 1 {
		t.Fatalf("SubmitBlockAuxChains: got %d aux chains, want 1 (the template-request-time entry with no block_hash must be excluded): %+v", len(auxChains), auxChains)
	}
	if auxChains[0].ChainID != "xtr" || auxChains[0].Hash != "aabbccdd" {
		t.Fatalf("SubmitBlockAuxChains: got %+v, want ChainID=xtr Hash=aabbccdd", auxChains[0])
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_EmptyEntrySkipped guards
// against ever surfacing a malformed/empty "_aux.chains" entry (id
// or block_hash empty) as a real AuxChainResult -- see
// moneroSubmitBlockAuxResult's own doc comment on why this decode
// never fabricates a chain result from incomplete data.
func TestMoneroNodeClient_SubmitBlockAuxChains_EmptyEntrySkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{
			"status":"OK",
			"_aux":{"chains":[{"id":"xtr","block_hash":""},{"id":"","block_hash":"deadbeef"}]}
		}}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), &MoneroCandidate{TemplateBlob: []byte{0x01, 0x02}})
	if err != nil {
		t.Fatalf("SubmitBlockAuxChains: unexpected error: %v", err)
	}
	if len(auxChains) != 0 {
		t.Fatalf("SubmitBlockAuxChains: got %d aux chains from incomplete entries, want 0: %+v", len(auxChains), auxChains)
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_Error covers a real
// submit_block-level error (e.g. the Tari base node rejecting the
// submission under submit_to_origin=false, or a genuinely rejected
// Monero block) -- auxChains must always be nil alongside the error,
// never a partial result, since callers cannot attribute this error
// to one specific leg (see SubmitBlockAuxChains' own doc comment).
func TestMoneroNodeClient_SubmitBlockAuxChains_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","error":{"code":-7,"message":"Block not accepted"}}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), &MoneroCandidate{TemplateBlob: []byte{0x01, 0x02}})
	if err == nil {
		t.Fatal("SubmitBlockAuxChains: expected an error for a rejected submit_block, got nil")
	}
	if auxChains != nil {
		t.Fatalf("SubmitBlockAuxChains: expected nil aux chains alongside the error, got %+v", auxChains)
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_BareStringResult covers
// the REAL, live-observed raw-monerod submit_block success shape
// where "result" is a bare JSON STRING ("{}") rather than an object
// (confirmed live against a real testnet daemon this session:
// {"id":-1,"jsonrpc":"2.0","result":"{}","status":"OK",
// "untrusted":false} -- status/untrusted sit at the TOP level,
// siblings of "result"). This must be treated as a plain, non-aux
// success -- NOT a hard decode error (the confirmed production bug
// this fix closes: "json: cannot unmarshal string into Go value of
// type solo.moneroSubmitBlockAuxResult").
func TestMoneroNodeClient_SubmitBlockAuxChains_BareStringResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":-1,"jsonrpc":"2.0","result":"{}","status":"OK","untrusted":false}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), &MoneroCandidate{TemplateBlob: []byte{0x01, 0x02}})
	if err != nil {
		t.Fatalf("SubmitBlockAuxChains: unexpected error for the known bare-string \"{}\" result shape: %v", err)
	}
	if auxChains != nil {
		t.Fatalf("SubmitBlockAuxChains: got %+v, want nil aux chains for a bare-string result", auxChains)
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_NonEmptyBareStringIsStillAnError
// guards the OTHER side of the tolerance added above: a bare-string
// result that is NOT the known empty/"{}" shape must still be a hard
// decode error, not silently swallowed.
func TestMoneroNodeClient_SubmitBlockAuxChains_NonEmptyBareStringIsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":-1,"jsonrpc":"2.0","result":"something unexpected","status":"OK","untrusted":false}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), &MoneroCandidate{TemplateBlob: []byte{0x01, 0x02}})
	if err == nil {
		t.Fatalf("SubmitBlockAuxChains: expected an error for a non-empty, non-\"{}\" bare-string result, got auxChains=%+v", auxChains)
	}
	if auxChains != nil {
		t.Fatalf("SubmitBlockAuxChains: expected nil aux chains alongside the error, got %+v", auxChains)
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_RejectsWrongCandidateType
// confirms SubmitBlockAuxChains refuses a candidate that isn't a
// *MoneroCandidate (e.g. the pre-fix bare []byte shape).
func TestMoneroNodeClient_SubmitBlockAuxChains_RejectsWrongCandidateType(t *testing.T) {
	c := NewMoneroNodeClient("http://127.0.0.1:1")
	_, err := c.SubmitBlockAuxChains(context.Background(), []byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected an error for a non-*MoneroCandidate candidate")
	}
}

// Compile-time confirmation that MoneroNodeClient's AuxChainSubmitter
// implementation is reachable via type assertion the same way
// session.go's handleSubmit uses it.
var _ = func() {
	var nc interface {
		SubmitBlock(ctx context.Context, candidate any) error
	} = NewMoneroNodeClient("http://unused.invalid")
	if _, ok := nc.(AuxChainSubmitter); !ok {
		panic("MoneroNodeClient must implement AuxChainSubmitter")
	}
}
