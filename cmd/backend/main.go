// Command backend is the entrypoint for the unified go-crypto-pool
// backend service. It opens a Postgres connection pool, wires it into
// the HTTP+Protobuf share/block ingestion API (internal/backend/api),
// and serves it.
//
// Configuration is via environment variables (no flags/config file yet
// — this is the first runnable pass, not the final ops story):
//
//	GCPOOL_DB_DSN            (required) Postgres DSN, e.g.
//	                         "postgres://user:pass@host:5432/db?sslmode=disable"
//	GCPOOL_LISTEN_ADDR       (optional) HTTP listen address, default ":8080"
//	GCPOOL_AUTH_HEADER_NAME  (optional) shared-secret auth header name to
//	                         require on /api/v1/share and /api/v1/block,
//	                         e.g. "Authorization". Must be set together
//	                         with GCPOOL_AUTH_HEADER_VALUE, or not at all
//	                         — see internal/backend/api.Config: both
//	                         empty means no auth check is performed
//	                         (matches the leaf transport's opt-in v1 auth
//	                         story).
//	GCPOOL_AUTH_HEADER_VALUE (optional) expected value for the header
//	                         above.
//	GCPOOL_NETWORK           (required) the network this backend is
//	                         configured for. Accepts "mainnet" or
//	                         "testnet" (case-insensitive). There is no
//	                         default — startup fails fast if this is
//	                         missing or does not parse to a valid
//	                         network, since silently defaulting to
//	                         either network here is exactly the kind of
//	                         cross-network contamination this backend
//	                         must prevent. Every submitted Share/Block
//	                         must carry this exact network or it is
//	                         rejected with 400.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Snipa22/go-crypto-pool/internal/backend/api"
	"github.com/Snipa22/go-crypto-pool/internal/backend/db"
	poolpb "github.com/Snipa22/go-crypto-pool/internal/proto"
)

const defaultListenAddr = ":8080"

// parseNetwork parses the GCPOOL_NETWORK environment variable value
// into a poolpb.Network. Only "mainnet" and "testnet" (case-insensitive)
// are accepted; anything else (including empty string) is an error —
// there is deliberately no default value here.
func parseNetwork(raw string) (poolpb.Network, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "mainnet":
		return poolpb.Network_NETWORK_MAINNET, nil
	case "testnet":
		return poolpb.Network_NETWORK_TESTNET, nil
	default:
		return poolpb.Network_NETWORK_UNSPECIFIED, fmt.Errorf("GCPOOL_NETWORK: unrecognized value %q, want \"mainnet\" or \"testnet\"", raw)
	}
}

// repositoryAdapter adapts *db.Repository (whose InsertShare/InsertBlock
// operate on db.Share/db.Block) to api.ShareBlockRepository (which
// operates on api.ShareRecord/api.BlockRecord). This keeps
// internal/backend/api free of any dependency on internal/backend/db —
// this command is the only place the two packages need to meet.
type repositoryAdapter struct {
	repo *db.Repository
}

func (a repositoryAdapter) InsertShare(ctx context.Context, s api.ShareRecord, bucketSize int64) error {
	return a.repo.InsertShare(ctx, db.Share{
		Algo:           s.Algo,
		Network:        s.Network,
		PoolType:       s.PoolType,
		PoolID:         s.PoolID,
		BlockHeight:    s.BlockHeight,
		Shares:         s.Shares,
		PaymentAddress: s.PaymentAddress,
		PaymentID:      s.PaymentID,
		FoundBlock:     s.FoundBlock,
		BlockDiff:      s.BlockDiff,
		Timestamp:      s.Timestamp,
		Identifier:     s.Identifier,
		TrustedShare:   s.TrustedShare,
	}, bucketSize)
}

func (a repositoryAdapter) InsertBlock(ctx context.Context, b api.BlockRecord) error {
	return a.repo.InsertBlock(ctx, db.Block{
		Algo:       b.Algo,
		Network:    b.Network,
		PoolType:   b.PoolType,
		Hash:       b.Hash,
		Height:     b.Height,
		Difficulty: b.Difficulty,
		Shares:     b.Shares,
		Timestamp:  b.Timestamp,
		Unlocked:   b.Unlocked,
		Valid:      b.Valid,
		Value:      b.Value,
	})
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("backend: %v", err)
	}
}

func run() error {
	dsn := os.Getenv("GCPOOL_DB_DSN")
	if dsn == "" {
		return errors.New("GCPOOL_DB_DSN environment variable is required")
	}

	listenAddr := os.Getenv("GCPOOL_LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = defaultListenAddr
	}

	authHeaderName := os.Getenv("GCPOOL_AUTH_HEADER_NAME")
	authHeaderValue := os.Getenv("GCPOOL_AUTH_HEADER_VALUE")

	network, err := parseNetwork(os.Getenv("GCPOOL_NETWORK"))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Open(ctx, db.Config{DSN: dsn})
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer pool.Close()

	repo := db.NewRepository(pool)
	handler := api.NewHandler(repositoryAdapter{repo: repo}, api.Config{
		AuthHeaderName:  authHeaderName,
		AuthHeaderValue: authHeaderValue,
		Network:         network,
	})

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler.Mux(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("backend: listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		log.Print("backend: shutdown signal received, draining connections")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutting down http server: %w", err)
		}
		return <-errCh
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server: %w", err)
		}
		return nil
	}
}
