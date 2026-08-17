// Package transport defines the leaf-library abstraction for submitting
// validated Shares/Blocks from a leaf process to the backend, plus the
// concrete HTTP+Protobuf implementation used today.
//
// Backend trust boundary: leaves own all algo-specific PoW validation
// (RXT/C29/SHA3X/RXM) before anything reaches this package — the backend
// does not re-validate hashes (see AGENTS.md). This package only owns
// getting an already-validated Share/Block message to the backend.
//
// Transport is designed to be implementation-agnostic: HTTPProtobufTransport
// is the only implementation today, but a future NATS JetStream
// implementation should be able to satisfy the same interface without any
// call-site changes. Accordingly the interface signature avoids leaking
// HTTP-specific types (no *http.Response, no http.Header, etc.).
package transport

import (
	"context"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

// ShareTransport abstracts how a leaf hands a validated Share or Block
// to the backend. Implementations must be safe for concurrent use.
//
// Implementations must respect ctx cancellation/deadlines — do not block
// indefinitely. This directly guards against the "no timeouts anywhere"
// bug class found in the legacy stratum servers.
type ShareTransport interface {
	// SubmitShare sends a validated share to the backend. It returns a
	// non-nil error if the share could not be delivered (including
	// context deadline/cancellation).
	SubmitShare(ctx context.Context, share *poolpb.Share) error

	// SubmitBlock reports a found block to the backend. It returns a
	// non-nil error if the block could not be delivered (including
	// context deadline/cancellation).
	SubmitBlock(ctx context.Context, block *poolpb.Block) error

	// Close releases any resources (connections, background goroutines,
	// JetStream subscriptions, etc.) held by the implementation. It must
	// be safe to call exactly once during clean shutdown.
	Close() error
}
