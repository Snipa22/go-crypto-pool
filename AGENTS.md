---
description: go-crypto-pool — unified Tari (+ eventually multi-coin) mining-pool backend and multi-algo leaf stack
---

# AGENTS.md

Instructions for AI coding agents (OpenCode, Claude Code, or any `agents.md`-compatible tool) working in this repository. Read this before making changes.

## Project

- **What this repo is:** Ground-up rewrite of the Tari mining-pool stack. A unified Go backend (owns its own Postgres DB, no legacy nodejs-pool dependency) plus a shared internal leaf library and 3 leaf-mode binaries: direct-to-backend, standalone-solo, and proxy-aggregator (XNP-style). Algo scope: RXT, C29, SHA3X, RXM.
- **Module path:** `github.com/Snipa22/go-crypto-pool`
- **Status:** early scaffold, private development phase.
- **Depends on:** likely `go-tari-grpc-lib` and/or `go-tari-lib` for Tari base-node GRPC access (not yet wired in this scaffold pass — added as real integration work begins).

## Commands

- **Build:** `go build ./...`
- **Test:** `go test ./...`
- **Vet:** `go vet ./...`
- **Format:** `gofmt -l .` (should return nothing; `gofmt -w .` to fix)
- **Tidy:** `go mod tidy`

Run build + vet + gofmt + test before considering any change complete.

## Conventions

- **Conventional Commits** required — commit type drives automated SemVer via release-please.
- **Rebase, never merge.** No merge commits in PR branches.
- **No direct commits/pushes to `main`** (except the initial scaffold commit — see CONTRIBUTING.md).
- Backend is a trust boundary, not a validator — it accepts leaf-validated shares, it does NOT do hashing/PoW verification itself. Leaves own all algo-specific validation (RXT/C29/SHA3X/RXM).
- Edge (leaf) → Backend transport is HTTP + Protobuf — this was a deliberate choice (matches the existing legacy stack, keeps a parallel SXMR migration path aligned). Do not introduce GRPC or a message queue for this hop without an explicit maintainer decision — it's been discussed and intentionally not chosen.
- Proxy leaf mode emulates an advanced mining client to its upstream (XNP-style) — no GRPC in the leaf-to-leaf chain.
- 4 algo-partitioned share streams (RXT/C29/SHA3X/RXM) — NOT one commingled table with a discriminator column. Exact schema is still an open design question (query-volume/retention-driven) — do not invent a final schema without checking current project state.
- Per-block payout is single-stream — a block's payout is not split/commingled across algos.

## Don't

- Don't push directly to `main` or force-push shared branches (after this initial scaffold).
- Don't add merge commits — rebase instead.
- Don't design/commit a final share-table schema without explicit direction — this is a known open item, not yet decided.
- Don't add a nodejs/JS leaf or backend component — this is an all-Go stack by deliberate decision.
- Don't silently change the licensing header or LICENSE file — that's a human decision, flag it instead.
- Don't skip tests because "there weren't any before" — add coverage for what you touch, even placeholder tests in this scaffold pass.
