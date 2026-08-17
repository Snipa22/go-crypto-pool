package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
	"google.golang.org/protobuf/proto"
)

// Default REST-ish paths for the HTTP+Protobuf edge transport. These are
// new for go-crypto-pool — not inherited from the legacy nodejs-pool
// `/leafApi` endpoint naming.
const (
	DefaultShareTimeout = 5 * time.Second
	DefaultBlockTimeout = 5 * time.Second

	defaultSharePath = "/api/v1/share"
	defaultBlockPath = "/api/v1/block"

	protobufContentType = "application/x-protobuf"
)

// HTTPProtobufTransportConfig configures HTTPProtobufTransport.
type HTTPProtobufTransportConfig struct {
	// BaseURL is the backend base URL, e.g. "https://backend.example.com".
	// SharePath/BlockPath are appended to it (with no assumptions about
	// trailing slashes — they're normalized in NewHTTPProtobufTransport).
	BaseURL string

	// SharePath/BlockPath override the default REST-ish paths. Leave
	// empty to use the defaults ("/api/v1/share", "/api/v1/block").
	SharePath string
	BlockPath string

	// AuthHeaderName/AuthHeaderValue configure a simple shared-secret /
	// bearer-token header sent with every request, e.g.
	// AuthHeaderName="Authorization", AuthHeaderValue="Bearer <token>".
	// Both empty means no auth header is sent. This is a deliberately
	// simple v1 auth story — improve later if/when needed.
	AuthHeaderName  string
	AuthHeaderValue string

	// ShareTimeout/BlockTimeout bound each individual HTTP call via
	// context.WithTimeout, in addition to whatever deadline the caller's
	// ctx already carries (the shorter of the two wins). Zero/negative
	// values fall back to the package defaults — this transport never
	// makes an HTTP call with no deadline at all, by design (see the
	// "no timeouts anywhere" bug class called out in AGENTS.md-adjacent
	// review notes).
	ShareTimeout time.Duration
	BlockTimeout time.Duration

	// HTTPClient allows injecting a custom *http.Client (e.g. for
	// connection pooling tuning or test doubles). If nil, a client with
	// a conservative default Timeout is constructed.
	HTTPClient *http.Client
}

// HTTPProtobufTransport is the v1 ShareTransport implementation: it
// POSTs protobuf-marshaled Share/Block messages to configurable backend
// HTTP endpoints. It is the primary edge-to-backend transport per
// AGENTS.md (no GRPC/MQ for this hop without explicit maintainer
// sign-off; NATS is a tracked-separately future option this interface is
// designed to accommodate later without call-site changes).
type HTTPProtobufTransport struct {
	baseURL         string
	sharePath       string
	blockPath       string
	authHeaderName  string
	authHeaderValue string
	shareTimeout    time.Duration
	blockTimeout    time.Duration
	client          *http.Client
}

// NewHTTPProtobufTransport constructs an HTTPProtobufTransport from cfg.
// It returns an error if cfg.BaseURL is empty.
func NewHTTPProtobufTransport(cfg HTTPProtobufTransportConfig) (*HTTPProtobufTransport, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("transport: BaseURL must not be empty")
	}

	sharePath := cfg.SharePath
	if sharePath == "" {
		sharePath = defaultSharePath
	}
	blockPath := cfg.BlockPath
	if blockPath == "" {
		blockPath = defaultBlockPath
	}

	shareTimeout := cfg.ShareTimeout
	if shareTimeout <= 0 {
		shareTimeout = DefaultShareTimeout
	}
	blockTimeout := cfg.BlockTimeout
	if blockTimeout <= 0 {
		blockTimeout = DefaultBlockTimeout
	}

	client := cfg.HTTPClient
	if client == nil {
		// Belt-and-suspenders: even though every call also gets a
		// context.WithTimeout below, the underlying client should never
		// be configured to hang forever either.
		maxTimeout := shareTimeout
		if blockTimeout > maxTimeout {
			maxTimeout = blockTimeout
		}
		client = &http.Client{Timeout: maxTimeout + 5*time.Second}
	}

	baseURL := trimTrailingSlash(cfg.BaseURL)

	return &HTTPProtobufTransport{
		baseURL:         baseURL,
		sharePath:       ensureLeadingSlash(sharePath),
		blockPath:       ensureLeadingSlash(blockPath),
		authHeaderName:  cfg.AuthHeaderName,
		authHeaderValue: cfg.AuthHeaderValue,
		shareTimeout:    shareTimeout,
		blockTimeout:    blockTimeout,
		client:          client,
	}, nil
}

// SubmitShare implements ShareTransport.
func (t *HTTPProtobufTransport) SubmitShare(ctx context.Context, share *poolpb.Share) error {
	return t.post(ctx, t.baseURL+t.sharePath, share, t.shareTimeout, "share")
}

// SubmitBlock implements ShareTransport.
func (t *HTTPProtobufTransport) SubmitBlock(ctx context.Context, block *poolpb.Block) error {
	return t.post(ctx, t.baseURL+t.blockPath, block, t.blockTimeout, "block")
}

// Close implements ShareTransport. HTTPProtobufTransport holds no
// long-lived resources beyond the *http.Client's connection pool, which
// net/http manages itself, so Close is a no-op today — it exists to
// satisfy the interface and give future implementations (e.g. NATS) a
// real teardown hook without changing call sites.
func (t *HTTPProtobufTransport) Close() error {
	return nil
}

func (t *HTTPProtobufTransport) post(ctx context.Context, url string, msg proto.Message, timeout time.Duration, kind string) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("transport: marshal %s: %w", kind, err)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("transport: build %s request: %w", kind, err)
	}
	req.Header.Set("Content-Type", protobufContentType)
	if t.authHeaderName != "" {
		req.Header.Set(t.authHeaderName, t.authHeaderValue)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("transport: submit %s: %w", kind, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("transport: submit %s: backend returned status %d: %s", kind, resp.StatusCode, string(body))
	}

	return nil
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func ensureLeadingSlash(s string) string {
	if len(s) == 0 || s[0] != '/' {
		return "/" + s
	}
	return s
}

// Compile-time assertion that HTTPProtobufTransport satisfies
// ShareTransport.
var _ ShareTransport = (*HTTPProtobufTransport)(nil)
