# syntax=docker/dockerfile:1
#
# docker/leaf-direct/Dockerfile
#
# Builds cmd/leaf-direct, the direct-to-backend leaf mining-proxy mode.
#
# Runtime base: gcr.io/distroless/static-debian12. leaf-direct never
# shells out (no os/exec usage in this package tree) but forwards
# shares to the backend over HTTP+Protobuf and may reach out to a
# Monero-family node over RPC/ZMQ, so it needs CA certificates for
# outbound TLS verification. distroless/static ships ca-certificates
# and a built-in nonroot (65532:65532) user, covering both needs
# without a shell or package manager.

FROM golang:1.25-bookworm AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/leaf-direct \
    ./cmd/leaf-direct

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=builder /out/leaf-direct /usr/local/bin/leaf-direct

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/leaf-direct"]
