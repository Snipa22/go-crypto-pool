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
// submit_block response with NO aux_chain_data at all -- e.g. a bare
// monerod, or a merge-mining proxy whose secondary chain target was
// not cleared on this submission. auxChains must come back empty,
// with no error (the primary submission itself succeeded).
func TestMoneroNodeClient_SubmitBlockAuxChains_NoAuxData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{"status":"OK","untrusted":false}}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("SubmitBlockAuxChains: unexpected error: %v", err)
	}
	if len(auxChains) != 0 {
		t.Fatalf("SubmitBlockAuxChains: got %d aux chains, want 0: %+v", len(auxChains), auxChains)
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_WithAuxData covers the
// REAL live-confirmed wire shape (CT132's tari-mmproxy.service,
// mirrored against tari-project/tari's own
// applications/minotari_merge_mining_proxy/src/proxy/inner.rs
// handle_submit_block/append_aux_chain_data): a successful
// submit_block response gains an aux_chain_data array with entries
// shaped {"id": "xtr", "block_hash": "<hex>"} when the merge-mined
// chain (Tari) also cleared its own real target and its base node
// accepted the resulting block.
func TestMoneroNodeClient_SubmitBlockAuxChains_WithAuxData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{
			"status":"OK",
			"untrusted":false,
			"aux_chain_data":[{"id":"xtr","block_hash":"aabbccdd"}]
		}}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("SubmitBlockAuxChains: unexpected error: %v", err)
	}
	if len(auxChains) != 1 {
		t.Fatalf("SubmitBlockAuxChains: got %d aux chains, want 1: %+v", len(auxChains), auxChains)
	}
	if auxChains[0].ChainID != "xtr" || auxChains[0].Hash != "aabbccdd" {
		t.Fatalf("SubmitBlockAuxChains: got %+v, want ChainID=xtr Hash=aabbccdd", auxChains[0])
	}
}

// TestMoneroNodeClient_SubmitBlockAuxChains_EmptyEntrySkipped guards
// against ever surfacing a malformed/empty aux_chain_data entry (id
// or block_hash empty) as a real AuxChainResult -- see
// moneroSubmitBlockAuxResult's own doc comment on why this decode
// never fabricates a chain result from incomplete data.
func TestMoneroNodeClient_SubmitBlockAuxChains_EmptyEntrySkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"0","jsonrpc":"2.0","result":{
			"status":"OK",
			"aux_chain_data":[{"id":"xtr","block_hash":""},{"id":"","block_hash":"deadbeef"}]
		}}`)
	}))
	defer srv.Close()

	c := NewMoneroNodeClient(srv.URL)
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), []byte{0x01, 0x02})
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
	auxChains, err := c.SubmitBlockAuxChains(context.Background(), []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("SubmitBlockAuxChains: expected an error for a rejected submit_block, got nil")
	}
	if auxChains != nil {
		t.Fatalf("SubmitBlockAuxChains: expected nil aux chains alongside the error, got %+v", auxChains)
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
