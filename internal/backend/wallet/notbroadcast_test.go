// Copyright and license: see repository LICENSE (MIT).
package wallet

// notbroadcast_test.go pins down the ErrNotBroadcast classification
// for both real WalletClient implementations. This is the mechanism
// internal/backend/disburse uses to decide between recording a payout
// FAILED (balance stays payable, retried next cycle) and AMBIGUOUS
// (balance frozen, disbursement halted, human required).
//
// Getting a case wrong in one direction is a nuisance: a hard
// rejection needlessly halts payouts. Getting it wrong in the OTHER
// direction re-sends real coin. So every case below asserts the
// marking explicitly, and the tests are written so that a future
// refactor which accidentally marks everything NotBroadcast fails
// loudly rather than passing quietly.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
)

func requireNotBroadcast(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got nil error, want one", what)
	}
	if !errors.Is(err, ErrNotBroadcast) {
		t.Errorf("%s: errors.Is(err, ErrNotBroadcast) = false, want true (this error is provably pre-broadcast, so the payout should be retried, not halted): %v", what, err)
	}
}

func requireAmbiguous(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: got nil error, want one", what)
	}
	if errors.Is(err, ErrNotBroadcast) {
		t.Errorf("%s: errors.Is(err, ErrNotBroadcast) = true, want false — this error does NOT prove the transfer never broadcast, so marking it would make the engine re-send possibly-already-spent coin: %v", what, err)
	}
}

// --- Monero -------------------------------------------------------

// TestMoneroTransferLocalValidationIsNotBroadcast: the pre-flight
// refusals never leave this process, so they are provably safe to
// retry.
func TestMoneroTransferLocalValidationIsNotBroadcast(t *testing.T) {
	w := NewMoneroWalletRPC("http://127.0.0.1:1")
	ctx := context.Background()

	_, err := w.Transfer(ctx, TransferRequest{})
	requireNotBroadcast(t, err, "no destinations")

	_, err = w.Transfer(ctx, TransferRequest{Destinations: []Destination{{Address: "addr", Amount: 0}}})
	requireNotBroadcast(t, err, "non-positive amount")

	_, err = w.Transfer(ctx, TransferRequest{Destinations: []Destination{{Address: "", Amount: 5}}})
	requireNotBroadcast(t, err, "empty address")
}

// TestMoneroTransferRPCErrorEnvelopeIsNotBroadcast: an HTTP 200 with
// a JSON-RPC error envelope is monero-wallet-rpc itself answering "I
// did not create a transaction" — the hard-rejection case, safe to
// retry. This is also the common operational case ("not enough
// unlocked money"), which must NOT halt the pool.
func TestMoneroTransferRPCErrorEnvelopeIsNotBroadcast(t *testing.T) {
	srv := walletTestServer(t, func(method string, _ map[string]any) (any, *walletRPCError) {
		return nil, &walletRPCError{Code: -37, Message: "not enough unlocked money"}
	})
	defer srv.Close()

	w := NewMoneroWalletRPC(srv.URL)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireNotBroadcast(t, err, "JSON-RPC error envelope")
}

// TestMoneroTransferAuthFailureIsNotBroadcast: a 401/403 is rejected
// at the authentication gate, before the JSON-RPC method is ever
// dispatched.
func TestMoneroTransferAuthFailureIsNotBroadcast(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		}))
		w := NewMoneroWalletRPC(srv.URL)
		_, err := w.Transfer(context.Background(), TransferRequest{
			Destinations: []Destination{{Address: "addr", Amount: 100}},
		})
		requireNotBroadcast(t, err, http.StatusText(status))
		srv.Close()
	}
}

// TestMoneroTransferTimeoutIsAmbiguous is the single most important
// case in this file: FIX_BRIEF finding #2 case (1). A transfer that
// exceeds the client timeout may have been broadcast for real, so the
// error must NOT be marked, so the engine halts instead of re-paying.
func TestMoneroTransferTimeoutIsAmbiguous(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a wallet that takes far longer than the client
		// is willing to wait — while (in reality) still going on to
		// broadcast the transaction.
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	w := NewMoneroWalletRPC(srv.URL, WithTimeout(50*time.Millisecond))
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "client-side transfer timeout")
}

// TestMoneroTransferTransportFailureIsAmbiguous: a connection-level
// failure says nothing about whether the wallet already acted.
func TestMoneroTransferTransportFailureIsAmbiguous(t *testing.T) {
	// Port 1 on loopback: nothing listening, connection refused.
	w := NewMoneroWalletRPC("http://127.0.0.1:1")
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "connection refused")
}

// TestMoneroTransferServerErrorAndGarbageBodyAreAmbiguous: a 500 (or
// an unparseable body) could equally well be a wallet that broadcast
// and then fell over, so neither may be marked.
func TestMoneroTransferServerErrorAndGarbageBodyAreAmbiguous(t *testing.T) {
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv500.Close()
	w := NewMoneroWalletRPC(srv500.URL)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "HTTP 500")

	srvGarbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not json at all"))
	}))
	defer srvGarbage.Close()
	w = NewMoneroWalletRPC(srvGarbage.URL)
	_, err = w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "unparseable response body")
}

// TestMoneroTransferSuccessWithNoTxHashIsAmbiguous: the RPC reported
// success, so a transaction may well exist — we just did not learn
// its hash. Treating that as "nothing happened" is the double-payment
// assumption.
func TestMoneroTransferSuccessWithNoTxHashIsAmbiguous(t *testing.T) {
	srv := walletTestServer(t, func(method string, _ map[string]any) (any, *walletRPCError) {
		return map[string]any{"amount": 100, "fee": 5, "tx_hash": ""}, nil
	})
	defer srv.Close()

	w := NewMoneroWalletRPC(srv.URL)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "success response with an empty tx_hash")
}

// TestMoneroDefaultTimeoutIsTheDocumentedValue pins the default that
// used to be a hardcoded, unoverridable 30s. A silent regression here
// directly increases how often a real payout is misread as a failure.
func TestMoneroDefaultTimeoutIsTheDocumentedValue(t *testing.T) {
	if DefaultTimeout != 60*time.Second {
		t.Errorf("DefaultTimeout = %v, want 60s", DefaultTimeout)
	}
	w := NewMoneroWalletRPC("http://127.0.0.1:1")
	if w.client.Timeout != DefaultTimeout {
		t.Errorf("client timeout = %v, want DefaultTimeout %v", w.client.Timeout, DefaultTimeout)
	}
	w = NewMoneroWalletRPC("http://127.0.0.1:1", WithTimeout(90*time.Second))
	if w.client.Timeout != 90*time.Second {
		t.Errorf("client timeout = %v, want the 90s override", w.client.Timeout)
	}
	// A non-positive override must be ignored rather than yielding
	// an unbounded client for a fund-moving connection.
	w = NewMoneroWalletRPC("http://127.0.0.1:1", WithTimeout(0))
	if w.client.Timeout != DefaultTimeout {
		t.Errorf("client timeout = %v with WithTimeout(0), want DefaultTimeout %v (never unbounded)", w.client.Timeout, DefaultTimeout)
	}
	w = NewMoneroWalletRPC("http://127.0.0.1:1", WithTimeout(-time.Second))
	if w.client.Timeout != DefaultTimeout {
		t.Errorf("client timeout = %v with a negative override, want DefaultTimeout %v", w.client.Timeout, DefaultTimeout)
	}
}

// --- Tari ---------------------------------------------------------

// TestTariTransferLocalValidationIsNotBroadcast: same pre-flight
// reasoning as Monero's, plus the >1-destination safety refusal.
func TestTariTransferLocalValidationIsNotBroadcast(t *testing.T) {
	w := newTariWalletGRPCWithRPC(&fakeTariWalletRPC{}, 0)
	ctx := context.Background()

	_, err := w.Transfer(ctx, TransferRequest{})
	requireNotBroadcast(t, err, "no destinations")

	_, err = w.Transfer(ctx, TransferRequest{Destinations: []Destination{
		{Address: "a", Amount: 1}, {Address: "b", Amount: 1},
	}})
	requireNotBroadcast(t, err, "more than one destination")

	_, err = w.Transfer(ctx, TransferRequest{Destinations: []Destination{{Address: "a", Amount: 0}}})
	requireNotBroadcast(t, err, "non-positive amount")

	_, err = w.Transfer(ctx, TransferRequest{Destinations: []Destination{{Address: "", Amount: 1}}})
	requireNotBroadcast(t, err, "empty address")
}

// TestTariTransferAllRecipientsRejectedIsNotBroadcast: the wallet's
// own transaction service explicitly rejected the recipient and
// issued no transaction id — Tari's analog of a hard RPC rejection.
func TestTariTransferAllRecipientsRejectedIsNotBroadcast(t *testing.T) {
	rpc := &fakeTariWalletRPC{transferResp: &tari_generated.TransferResponse{
		Results: []*tari_generated.TransferResult{{
			Address:        "addr",
			IsSuccess:      false,
			FailureMessage: "invalid address",
		}},
	}}
	w := newTariWalletGRPCWithRPC(rpc, 0)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireNotBroadcast(t, err, "recipient explicitly rejected with no tx id")
}

// TestTariTransferGRPCErrorIsAmbiguous: a GRPC-level failure carries
// no information about whether the wallet already broadcast.
func TestTariTransferGRPCErrorIsAmbiguous(t *testing.T) {
	rpc := &fakeTariWalletRPC{transferErr: errors.New("rpc error: code = DeadlineExceeded")}
	w := newTariWalletGRPCWithRPC(rpc, 0)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "GRPC DeadlineExceeded")
}

// TestTariTransferGetTransactionInfoFailureIsAmbiguous is FIX_BRIEF
// finding #2 case (2), verbatim: the recipient transfer SUCCEEDED
// (there is a real transaction id, the coin is gone) and only the
// follow-up fee/amount lookup failed. This path previously flowed
// into FailPayout and got the same coin sent again.
func TestTariTransferGetTransactionInfoFailureIsAmbiguous(t *testing.T) {
	rpc := &fakeTariWalletRPC{
		transferResp: &tari_generated.TransferResponse{
			Results: []*tari_generated.TransferResult{{
				Address:       "addr",
				IsSuccess:     true,
				TransactionId: 4242,
				// No inline TransactionInfo -> forces the fallback
				// lookup, which then fails.
			}},
		},
		txInfoErr: errors.New("transaction not found yet"),
	}
	w := newTariWalletGRPCWithRPC(rpc, 0)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "transfer succeeded but GetTransactionInfo failed")

	// The transaction id must appear in the message: it is what the
	// operator needs to confirm the transfer before resolving the
	// resulting AMBIGUOUS payout row.
	if !contains(err.Error(), "4242") {
		t.Errorf("got err=%v, want the real transaction id 4242 in the message for the resolving operator", err)
	}
	if !contains(err.Error(), "WAS broadcast") {
		t.Errorf("got err=%v, want it to state explicitly that the transfer WAS broadcast", err)
	}
}

// TestTariTransferEmptyResultsIsAmbiguous: the RPC returned without
// error, so the wallet may have acted even though it told us nothing.
func TestTariTransferEmptyResultsIsAmbiguous(t *testing.T) {
	w := newTariWalletGRPCWithRPC(&fakeTariWalletRPC{
		transferResp: &tari_generated.TransferResponse{},
	}, 0)
	_, err := w.Transfer(context.Background(), TransferRequest{
		Destinations: []Destination{{Address: "addr", Amount: 100}},
	})
	requireAmbiguous(t, err, "empty results")
}

// TestTariReadTimeoutBoundsGetBalanceButNotTransfer documents and
// enforces the deliberate asymmetry explained in
// WithTariReadTimeout's doc comment: read-only lookups are bounded
// (abandoning one costs nothing), while the fund-moving Transfer is
// NOT, because go-tari-grpc-lib gives no way to actually cancel it
// and abandoning it would manufacture an ambiguous incident.
func TestTariReadTimeoutBoundsGetBalanceButNotTransfer(t *testing.T) {
	blocked := make(chan struct{})
	defer close(blocked)

	rpc := &blockingTariRPC{block: blocked}
	w := newTariWalletGRPCWithRPC(rpc, 0)
	w.readTimeout = 50 * time.Millisecond

	start := time.Now()
	if _, err := w.GetBalance(context.Background()); err == nil {
		t.Fatal("GetBalance: want a timeout error")
	} else if !contains(err.Error(), "timed out") {
		t.Errorf("GetBalance: got err=%v, want a timeout error", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("GetBalance took %v, want it bounded by the ~50ms read timeout", elapsed)
	}

	// ctx cancellation must be honored on read paths too.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.readTimeout = time.Hour
	if _, err := w.GetBalance(ctx); err == nil {
		t.Error("GetBalance with a cancelled ctx: want an error")
	}
}

// blockingTariRPC blocks GetBalance/GetTransactionInfo until its
// channel is closed, for the read-timeout test above.
type blockingTariRPC struct {
	block chan struct{}
}

func (b *blockingTariRPC) Transfer([]*tari_generated.PaymentRecipient) (*tari_generated.TransferResponse, error) {
	return nil, errors.New("not used")
}

func (b *blockingTariRPC) GetBalance() (*tari_generated.GetBalanceResponse, error) {
	<-b.block
	return &tari_generated.GetBalanceResponse{}, nil
}

func (b *blockingTariRPC) GetTransactionInfo(uint64) (*tari_generated.TransactionInfo, error) {
	<-b.block
	return &tari_generated.TransactionInfo{}, nil
}

// TestTariReadTimeoutZeroIsUnbounded confirms the option's
// non-positive guard: zero/negative leaves the pre-existing
// unbounded behavior rather than accidentally introducing a
// zero-length timeout that would fail every call instantly.
func TestTariReadTimeoutZeroIsUnbounded(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Second} {
		var o tariWalletGRPCOptions
		WithTariReadTimeout(d)(&o)
		if o.readTimeout != 0 {
			t.Errorf("WithTariReadTimeout(%v): got readTimeout=%v, want 0 (ignored)", d, o.readTimeout)
		}
	}
	var o tariWalletGRPCOptions
	WithTariReadTimeout(30 * time.Second)(&o)
	if o.readTimeout != 30*time.Second {
		t.Errorf("WithTariReadTimeout(30s): got %v, want 30s", o.readTimeout)
	}
}
