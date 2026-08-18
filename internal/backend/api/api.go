// Package api implements the backend's HTTP + Protobuf share-ingestion
// endpoints. The backend is a trust boundary, not a validator: it accepts
// leaf-validated shares and does not perform hashing/PoW verification
// itself.
//
// Endpoints and wire contract here MUST match
// internal/leaflib/transport.HTTPProtobufTransport exactly, since that is
// the (only) client this package is written against:
//
//   - POST /api/v1/share  — body is a protobuf-marshaled poolpb.Share
//   - POST /api/v1/block  — body is a protobuf-marshaled poolpb.Block
//   - Content-Type: application/x-protobuf on both.
//   - Optional shared-secret auth header: if the server is configured
//     with an auth header name+value, requests missing that header (or
//     presenting the wrong value) are rejected with 401 before any
//     decode/DB work happens. If no auth is configured (both name and
//     value empty), no auth check is performed at all — this mirrors the
//     transport's "both empty means no auth header sent" v1 story
//     symmetrically on the server side.
package api

import (
	"context"
	"errors"
	"io"
	"net/http"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
	"google.golang.org/protobuf/proto"
)

// maxBodyBytes bounds how much of a request body we will read. Shares
// and blocks are small protobuf messages; there is no legitimate reason
// for either to approach this size, and capping it protects the handler
// from unbounded-body-based resource exhaustion.
const maxBodyBytes = 1 << 20 // 1 MiB

// ShareBlockRepository is the narrow persistence surface the handlers
// depend on. It is intentionally an interface (rather than the concrete
// *db.Repository type) so tests can inject a fake/mock without needing a
// real Postgres instance. *db.Repository satisfies this interface as-is.
type ShareBlockRepository interface {
	InsertShare(ctx context.Context, s ShareRecord, bucketSize int64) error
	InsertBlock(ctx context.Context, b BlockRecord) error
}

// ShareRecord/BlockRecord mirror db.Share/db.Block field-for-field. They
// exist so this package does not need to import internal/backend/db
// directly for its interface definition (keeping the dependency
// direction: db has no knowledge of api, api depends on db only through
// this interface's structural shape). cmd/backend wires a *db.Repository
// in via a small adapter (see NewRepositoryAdapter) since db.Share/
// db.Block already have the identical shape.
type ShareRecord struct {
	Algo           string
	Network        string
	PoolType       string
	PoolID         int32
	BlockHeight    int64
	Shares         int64
	PaymentAddress string
	PaymentID      *string
	FoundBlock     bool
	BlockDiff      int64
	Timestamp      int64
	Identifier     string
	TrustedShare   bool
}

// BlockRecord mirrors db.Block.
type BlockRecord struct {
	Algo       string
	Network    string
	PoolType   string
	Hash       string
	Height     int64
	Difficulty int64
	Shares     int64
	Timestamp  int64
	Unlocked   bool
	Valid      bool
	Value      *int64
}

// HeightPartitionBucketSize is passed to InsertShare's bucketSize
// parameter. It mirrors db.HeightPartitionBucketSize's value; kept as an
// independent constant here (rather than importing internal/backend/db
// for it) to preserve this package's DB-independence at the interface
// level. cmd/backend's adapter is the only place both packages meet.
const HeightPartitionBucketSize int64 = 100000

// Config configures a Handler.
type Config struct {
	// AuthHeaderName/AuthHeaderValue configure a simple shared-secret
	// header check, symmetric with
	// transport.HTTPProtobufTransportConfig's AuthHeaderName/
	// AuthHeaderValue. Both empty means no auth check is performed.
	AuthHeaderName  string
	AuthHeaderValue string
}

// Handler implements the backend's share/block ingestion HTTP endpoints.
type Handler struct {
	repo ShareBlockRepository
	cfg  Config
}

// NewHandler constructs a Handler backed by repo, using cfg for optional
// auth-header configuration.
func NewHandler(repo ShareBlockRepository, cfg Config) *Handler {
	return &Handler{repo: repo, cfg: cfg}
}

// Mux builds an *http.ServeMux with this Handler's routes registered.
// Kept simple deliberately — this repo has exactly two endpoints and
// does not need a web framework for that.
func (h *Handler) Mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/share", h.handleShare)
	mux.HandleFunc("POST /api/v1/block", h.handleBlock)
	return mux
}

// authConfigured reports whether an auth header check should be
// performed at all.
func (h *Handler) authConfigured() bool {
	return h.cfg.AuthHeaderName != "" || h.cfg.AuthHeaderValue != ""
}

// checkAuth returns true if the request passes the configured auth
// check (or if no auth is configured at all).
func (h *Handler) checkAuth(r *http.Request) bool {
	if !h.authConfigured() {
		return true
	}
	got := r.Header.Get(h.cfg.AuthHeaderName)
	if got == "" {
		return false
	}
	return got == h.cfg.AuthHeaderValue
}

func (h *Handler) handleShare(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}

	share := &poolpb.Share{}
	if err := proto.Unmarshal(body, share); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed protobuf Share")
		return
	}

	if err := validateShare(share); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	record := shareToRecord(share)
	if err := h.repo.InsertShare(r.Context(), record, HeightPartitionBucketSize); err != nil {
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) handleBlock(w http.ResponseWriter, r *http.Request) {
	if !h.checkAuth(r) {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "request body too large or unreadable")
		return
	}

	block := &poolpb.Block{}
	if err := proto.Unmarshal(body, block); err != nil {
		writeErr(w, http.StatusBadRequest, "malformed protobuf Block")
		return
	}

	if err := validateBlock(block); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	record := blockToRecord(block)
	if err := h.repo.InsertBlock(r.Context(), record); err != nil {
		writeErr(w, http.StatusInternalServerError, "insert failed")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func readBody(r *http.Request) ([]byte, error) {
	limited := io.LimitReader(r.Body, maxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxBodyBytes {
		return nil, errors.New("body too large")
	}
	return data, nil
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg))
}

// validateShare checks the fields that genuinely matter for a share to
// be actionable: an explicit (non-unspecified) algo, a non-empty
// payment address, and a non-negative block height. Deliberately not
// exhaustive — this is not a full schema validator, just enough to
// reject obviously-broken submissions before they hit the DB.
func validateShare(s *poolpb.Share) error {
	if s.GetAlgo() == poolpb.Algo_ALGO_UNSPECIFIED {
		return errors.New("share: algo is required")
	}
	if s.GetNetwork() == poolpb.Network_NETWORK_UNSPECIFIED {
		return errors.New("share: network is required")
	}
	if s.GetPoolType() == poolpb.PoolType_POOL_TYPE_UNSPECIFIED {
		return errors.New("share: pool_type is required")
	}
	if s.GetPaymentAddress() == "" {
		return errors.New("share: payment_address is required")
	}
	if s.GetBlockHeight() < 0 {
		return errors.New("share: block_height must be non-negative")
	}
	return nil
}

// validateBlock mirrors validateShare's genuinely-required-fields
// judgment call for Block.
func validateBlock(b *poolpb.Block) error {
	if b.GetAlgo() == poolpb.Algo_ALGO_UNSPECIFIED {
		return errors.New("block: algo is required")
	}
	if b.GetNetwork() == poolpb.Network_NETWORK_UNSPECIFIED {
		return errors.New("block: network is required")
	}
	if b.GetPoolType() == poolpb.PoolType_POOL_TYPE_UNSPECIFIED {
		return errors.New("block: pool_type is required")
	}
	if b.GetHash() == "" {
		return errors.New("block: hash is required")
	}
	if b.GetHeight() < 0 {
		return errors.New("block: height must be non-negative")
	}
	return nil
}

// algoString/networkString/poolTypeString map the proto enums to the
// short string codes used as Postgres partition keys (see
// internal/backend/db.ValidAlgos/ValidPoolTypes). These must stay in
// sync with that package's fixed value sets.
func algoString(a poolpb.Algo) string {
	switch a {
	case poolpb.Algo_ALGO_RXT:
		return "RXT"
	case poolpb.Algo_ALGO_C29:
		return "C29"
	case poolpb.Algo_ALGO_SHA3X:
		return "SHA3X"
	case poolpb.Algo_ALGO_RXM:
		return "RXM"
	default:
		return ""
	}
}

func networkString(n poolpb.Network) string {
	switch n {
	case poolpb.Network_NETWORK_MAINNET:
		return "MAINNET"
	case poolpb.Network_NETWORK_TESTNET:
		return "TESTNET"
	default:
		return ""
	}
}

func poolTypeString(p poolpb.PoolType) string {
	switch p {
	case poolpb.PoolType_POOL_TYPE_PPLNS:
		return "PPLNS"
	case poolpb.PoolType_POOL_TYPE_PPS:
		return "PPS"
	case poolpb.PoolType_POOL_TYPE_PROP:
		return "PROP"
	case poolpb.PoolType_POOL_TYPE_SOLO:
		return "SOLO"
	default:
		return ""
	}
}

func shareToRecord(s *poolpb.Share) ShareRecord {
	var paymentID *string
	if s.PaymentId != nil {
		paymentID = s.PaymentId
	}
	return ShareRecord{
		Algo:           algoString(s.GetAlgo()),
		Network:        networkString(s.GetNetwork()),
		PoolType:       poolTypeString(s.GetPoolType()),
		PoolID:         s.GetPoolId(),
		BlockHeight:    s.GetBlockHeight(),
		Shares:         s.GetShares(),
		PaymentAddress: s.GetPaymentAddress(),
		PaymentID:      paymentID,
		FoundBlock:     s.GetFoundBlock(),
		BlockDiff:      s.GetBlockDiff(),
		Timestamp:      s.GetTimestamp(),
		Identifier:     s.GetIdentifier(),
		TrustedShare:   s.GetTrustedShare(),
	}
}

func blockToRecord(b *poolpb.Block) BlockRecord {
	var value *int64
	if b.Value != nil {
		value = b.Value
	}
	return BlockRecord{
		Algo:       algoString(b.GetAlgo()),
		Network:    networkString(b.GetNetwork()),
		PoolType:   poolTypeString(b.GetPoolType()),
		Hash:       b.GetHash(),
		Height:     b.GetHeight(),
		Difficulty: b.GetDifficulty(),
		Shares:     b.GetShares(),
		Timestamp:  b.GetTimestamp(),
		Unlocked:   b.GetUnlocked(),
		Valid:      b.GetValid(),
		Value:      value,
	}
}
