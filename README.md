# go-crypto-pool

A ground-up Go rewrite of the Tari mining-pool stack: a unified backend service (owning its own Postgres database) plus a shared internal leaf library and three leaf-mode binaries.

## Status

**Early scaffold — private development phase.** This repo will be open-sourced after extensive testing, once the omni-pool backend and leaf stack are production-validated. Do not assume public visibility or external-contribution norms apply yet.

## Architecture (brief)

- **Unified backend** — a single Go service that owns its own Postgres database (no legacy nodejs-pool/MySQL dependency). The backend is a trust boundary, not a validator: it accepts leaf-validated shares over HTTP + Protobuf and does not perform hashing/PoW verification itself. Shares land in algo-partitioned tables rather than one commingled table.
- **Shared leaf library** (`internal/leaflib`) — pooling and connection-lifecycle logic, per-algo job/template caching, and vardiff, shared by every leaf binary and algo.
- **Three leaf deployment modes**, modeled on how XMR-Node-Proxy (XNP) worked, each its own binary sharing the internal leaf library:
  1. **direct-to-backend** — the normal ingest path, one miner connection per leaf connection, writing straight to the backend.
  2. **standalone-solo** — no backend at all, solo-mining mode.
  3. **proxy-aggregator** — aggregates many downstream miner connections behind one upstream connection by emulating an advanced mining client (XNP-style), the direct fix for edge connection-scaling problems.
- **Algo scope:** RXT, C29, SHA3X, RXM — four independent share streams, per-block payout single-stream (no cross-algo commingling).

This repo replaces `go-tari-pool-shim`, `go-tari-pool-shim-fee`, `go-tari-p2pool-interface`, `go-tari-c29-solo-stratum`, and `go-tari-sha3x-solo-stratum` as a parallel rewrite — those repos remain as-is for now and are not being modified as part of this effort.

Full architecture context, decision history, and open design items live in the maintainer's private Obsidian vault (`Projects/Tari/OmniPool-Architecture.md`) — not included in this repo.

## Module layout

```
go-crypto-pool/
├── cmd/
│   ├── backend/       # backend service entrypoint
│   ├── leaf-direct/   # leaf binary, mode 1: direct-to-backend
│   ├── leaf-solo/      # leaf binary, mode 2: standalone solo
│   └── leaf-proxy/     # leaf binary, mode 3: proxy-aggregator (XNP-style)
├── internal/
│   ├── backend/
│   │   ├── api/        # HTTP + Protobuf share-ingestion endpoints
│   │   └── db/         # schema/migrations (pending — see architecture doc open items)
│   └── leaflib/        # shared leaf library: pooling, job/template caching, vardiff
├── AGENTS.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Note: this repo is in a private, pre-review development phase — see that doc's "Private development phase" section.

## License

MIT — see [LICENSE](LICENSE).
