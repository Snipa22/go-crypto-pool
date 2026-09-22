# syntax=docker/dockerfile:1
#
# docker/relay-node/Dockerfile
#
# Builds cmd/relay-node, the standalone template-push / found-block relay
# daemon. Mirrors every sibling leaf binary's own Dockerfile convention
# exactly (see docker/leaf-solo/Dockerfile).
#
# Runtime base: gcr.io/distroless/static-debian12. relay-node never shells
# out (no os/exec usage) but talks to a Tari GRPC node or a Monero-family
# RPC/ZMQ endpoint and to a NATS relay, all of which may be reached over
# TLS, so it needs CA certificates for outbound TLS verification.
# distroless/static ships ca-certificates and a built-in nonroot
# (65532:65532) user, covering both needs without a shell or package
# manager.

FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/relay-node \
    ./cmd/relay-node

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/relay-node /usr/local/bin/relay-node

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/relay-node"]
