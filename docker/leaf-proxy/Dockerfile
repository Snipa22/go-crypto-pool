# syntax=docker/dockerfile:1
#
# docker/leaf-proxy/Dockerfile
#
# Builds cmd/leaf-proxy, the XNP-style proxy-aggregator leaf mode.
#
# Builder: CGO_ENABLED=1 with the randomx_cgo build tag, so the real
# block-find re-validation path (internal/leaflib/validator's
# CgoRandomXValidator, selected automatically by
# validator.NewProxyRandomXValidator()'s build-tag factory — see
# factory_cgo.go) is compiled in, backed by real cgo bindings to
# tevador/RandomX's reference C++ implementation via
# github.com/mining-pool/go-randomx. golang:1.25-bookworm already
# ships gcc/g++ (verified directly: `docker run --rm
# golang:1.25-bookworm g++ --version` succeeds), so no extra
# toolchain package install is needed here.
#
# Runtime base: gcr.io/distroless/cc-debian12 (NOT ...static-debian12
# — that variant ships no libc at all and will fail to even start a
# dynamically-linked cgo binary like this one). The `cc` variant adds
# glibc + libstdc++ + libgcc on top of distroless/static's baseline,
# which is exactly what a cgo/C++ binary needs to run, while still
# shipping ca-certificates and the same built-in nonroot (65532:65532)
# user leaf-proxy relies on for outbound TLS verification (it talks to
# a Monero-family node over RPC and to the backend over HTTP+Protobuf,
# both potentially TLS) without a shell or package manager.

FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build \
    -tags randomx_cgo \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/leaf-proxy \
    ./cmd/leaf-proxy

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /out/leaf-proxy /usr/local/bin/leaf-proxy

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/leaf-proxy"]
