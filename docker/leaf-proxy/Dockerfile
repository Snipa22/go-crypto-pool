# syntax=docker/dockerfile:1
#
# docker/leaf-proxy/Dockerfile
#
# Builds cmd/leaf-proxy, the XNP-style proxy-aggregator leaf mode.
#
# Runtime base: gcr.io/distroless/static-debian12. leaf-proxy never
# shells out (no os/exec usage in this package tree) — it emulates a
# mining client to its upstream over plain stratum-style TCP, but it
# also talks to a Monero-family node over RPC and to the backend over
# HTTP+Protobuf, both of which may be TLS, so it needs CA
# certificates for outbound TLS verification. distroless/static ships
# ca-certificates and a built-in nonroot (65532:65532) user, covering
# both needs without a shell or package manager.

FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/leaf-proxy \
    ./cmd/leaf-proxy

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/leaf-proxy /usr/local/bin/leaf-proxy

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/leaf-proxy"]
